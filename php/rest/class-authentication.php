<?php

namespace WPElevator\OAuth_Pilot\Rest;

use WP_HTTP_Response;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;
use WPElevator\OAuth_Pilot\Token\Bearer_Validator;

/**
 * Two separate jobs on the same core filters.
 *
 * First, the OAuth protocol routes are isolated from WordPress request
 * authentication: cookies and Application Passwords must not decide anything
 * there. Second, when the site enables it, bearer tokens authenticate ordinary
 * WordPress REST requests.
 */
class Authentication {

	private Bearer_Validator $validator;

	private Protected_Resources $resources;

	private Settings $settings;

	private ?string $challenge = null;

	public function __construct( Bearer_Validator $validator, Protected_Resources $resources, Settings $settings ) {
		$this->validator = $validator;
		$this->resources = $resources;
		$this->settings = $settings;
	}

	public function init(): void {
		// Before core's cookie nonce check at priority 100.
		add_filter( 'rest_authentication_errors', [ $this, 'filter_isolate_protocol_routes' ], 5 );
		add_filter( 'rest_authentication_errors', [ $this, 'filter_authenticate_bearer' ], 20 );
		add_filter( 'wp_is_application_passwords_available', [ $this, 'filter_application_passwords_available' ], 100 );
		add_filter( 'rest_post_dispatch', [ $this, 'filter_add_challenge_header' ], 10, 3 );
	}

	/**
	 * The route currently being dispatched, as registered.
	 */
	public function get_current_route(): string {
		if ( isset( $GLOBALS['wp'] ) && ! empty( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			return (string) $GLOBALS['wp']->query_vars['rest_route'];
		}

		return '';
	}

	public function is_protocol_route( string $route ): bool {
		$pattern = sprintf(
			'#^/?%s/(%s)/?$#',
			preg_quote( Server_Urls::REST_NAMESPACE, '#' ),
			implode( '|', Server_Urls::ENDPOINTS )
		);

		return (bool) preg_match( $pattern, $route );
	}

	/**
	 * Dispatch the OAuth protocol routes anonymously.
	 *
	 * Returning true short-circuits the rest of the filter chain, which is what
	 * keeps rest_cookie_check_errors() from turning an agent client's authorize
	 * request into a nonce failure just because the user happens to be logged
	 * into WordPress in the same browser.
	 *
	 * @param mixed $result The authentication result so far.
	 *
	 * @return mixed
	 */
	public function filter_isolate_protocol_routes( $result ) {
		if ( ! $this->is_protocol_route( $this->get_current_route() ) ) {
			return $result;
		}

		wp_set_current_user( 0 );

		return true;
	}

	/**
	 * Application Passwords also read HTTP Basic credentials, which collide
	 * with client_secret_basic on the token endpoint.
	 *
	 * @param bool $available Whether Application Passwords may authenticate.
	 */
	public function filter_application_passwords_available( $available ) {
		if ( $this->is_protocol_route( $this->get_current_route() ) ) {
			return false;
		}

		return $available;
	}

	/**
	 * Authenticate an ordinary WordPress REST request with a bearer token.
	 *
	 * @param mixed $result The authentication result so far.
	 *
	 * @return mixed
	 */
	public function filter_authenticate_bearer( $result ) {
		if ( ! empty( $result ) ) {
			return $result; // Another mechanism already decided.
		}

		if ( ! $this->settings->is_rest_authentication_enabled() ) {
			return $result;
		}

		if ( get_current_user_id() > 0 ) {
			return $result; // Never override an established WordPress user.
		}

		$route = $this->get_current_route();

		if ( '' === $route || $this->is_protocol_route( $route ) ) {
			return $result;
		}

		$url = rest_url( $route );
		$resource = $this->resources->match_url( $url );
		$wordpress_resource = $this->resources->get( rest_url() );

		if ( ! $resource || ! $wordpress_resource || $resource->get_uri() !== $wordpress_resource->get_uri() ) {
			return $result;
		}

		if ( ! $this->validator->has_bearer_credential() ) {
			$this->challenge = $this->validator->get_challenge( $resource->get_uri() );

			return $result;
		}

		$required = $this->get_required_scopes( $resource );

		if ( empty( $required ) ) {
			return new WP_Error(
				'oauth_pilot_missing_rest_scope_mapping',
				__( 'This REST resource has no OAuth scope mapping.', 'wpelevator-oauth-pilot' ),
				[ 'status' => 403 ]
			);
		}

		$context = $this->validator->validate_request( $resource->get_uri(), $required );

		if ( is_wp_error( $context ) ) {
			$this->challenge = (string) ( $context->get_error_data()['www_authenticate'] ?? '' );

			return $context;
		}

		// Only now, after the token fully validated, does a WordPress user exist.
		wp_set_current_user( $context->get_user_id() );

		return true;
	}

	/**
	 * The scopes a REST request needs, derived from its HTTP method.
	 */
	public function get_required_scopes( Protected_Resource $protected_resource ): array {
		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			: 'GET';

		$required = in_array( $method, [ 'GET', 'HEAD', 'OPTIONS' ], true )
			? [ Plugin::SCOPE_READ ]
			: [ Plugin::SCOPE_WRITE ];

		$required = array_values( array_intersect( $required, $protected_resource->get_scopes() ) );

		/**
		 * Map a WordPress REST request to the scopes it requires.
		 *
		 * @param array              $required The required scopes.
		 * @param Protected_Resource $protected_resource The matched resource.
		 * @param string             $method   The request method.
		 */
		return (array) apply_filters( 'oauth_pilot__rest_required_scopes', $required, $protected_resource, $method );
	}

	/**
	 * Attach the bearer challenge to the response, so a client learns where the
	 * authorization server is.
	 *
	 * @param WP_HTTP_Response $response The response.
	 * @param WP_REST_Server   $server   The server instance.
	 * @param WP_REST_Request  $request  The request.
	 *
	 * @return WP_HTTP_Response
	 */
	public function filter_add_challenge_header( $response, $server, $request ) {
		if ( empty( $this->challenge ) || ! $response instanceof WP_REST_Response ) {
			return $response;
		}

		if ( in_array( $response->get_status(), [ 401, 403 ], true ) ) {
			$response->header( 'WWW-Authenticate', $this->challenge );
			$response->header( 'Access-Control-Expose-Headers', 'WWW-Authenticate' );
		}

		return $response;
	}
}
