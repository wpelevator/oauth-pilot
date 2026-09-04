<?php

namespace WPElevator\OAuth_Pilot\Rest;

use WP_HTTP_Response;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;
use WPElevator\OAuth_Pilot\Token\Bearer_Validator;

/**
 * Two separate jobs on the same core filters.
 *
 * First, the OAuth protocol routes are isolated from WordPress request
 * authentication: cookies and Application Passwords must not decide anything
 * there. Second, when the site enables it, bearer tokens authenticate any
 * non-protocol WordPress REST request without knowing which component
 * registered the route.
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
		// This service can outlive one request under tests, WP-CLI and persistent
		// application servers. A challenge belongs only to the current request.
		$this->challenge = null;

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

		/*
		 * Prefer the most specific audience registered for this route. A plugin
		 * that registers its own resource under wp-json — an MCP server with its
		 * own scopes, say — owns the tokens for its own routes, and answering
		 * for it here would reject every one of them as minted for a different
		 * resource before the route ever ran.
		 */
		$matched = $this->resources->match_url( rest_url( ltrim( $route, '/' ) ) );

		$resource_uri = $matched ? $matched->get_uri() : rest_url();

		/**
		 * Select the OAuth resource used to authenticate one REST route.
		 *
		 * The default is the most specific registered audience covering the
		 * route, falling back to the shared WordPress REST API audience.
		 *
		 * @param string $resource_uri The resource URI to authenticate against.
		 * @param string $route        The current WordPress REST route.
		 */
		$resource_uri = (string) apply_filters( 'oauth_pilot__rest_authentication_resource_uri', $resource_uri, $route );
		$resource = $this->resources->get( $resource_uri );

		if ( ! $resource || ! in_array( Plugin::SCOPE_REST, $resource->get_scopes(), true ) ) {
			return $result;
		}

		if ( ! $this->validator->has_bearer_credential() ) {
			$this->challenge = $this->validator->get_challenge( $resource->get_uri() );

			return $result;
		}

		$context = $this->validator->validate_request( $resource->get_uri(), [ Plugin::SCOPE_REST ] );

		if ( is_wp_error( $context ) ) {
			$this->challenge = (string) ( $context->get_error_data()['www_authenticate'] ?? '' );

			return $context;
		}

		// Only now, after the token fully validated, does a WordPress user exist.
		wp_set_current_user( $context->get_user_id() );

		return true;
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
