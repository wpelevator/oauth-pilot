<?php

namespace WPElevator\OAuth_Pilot\Rest;

use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WPElevator\OAuth_Pilot\Authorization\Service as Authorization_Service;
use WPElevator\OAuth_Pilot\Client\Registration;
use WPElevator\OAuth_Pilot\Http\Form_Body;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Http\Redirect_Error;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;
use WPElevator\OAuth_Pilot\Token\Service as Token_Service;

/**
 * The advertised OAuth protocol endpoints.
 *
 * Every route here is dispatched anonymously: permission callbacks are public
 * and the endpoint performs whatever OAuth client authentication the protocol
 * requires. A WordPress cookie never changes a response.
 */
class Controller {

	private Authorization_Service $authorization_service;

	private Token_Service $token_service;

	private Registration $registration;

	private Server_Urls $urls;

	private Settings $settings;

	public function __construct(
		Authorization_Service $authorization_service,
		Token_Service $token_service,
		Registration $registration,
		Server_Urls $urls,
		Settings $settings
	) {
		$this->authorization_service = $authorization_service;
		$this->token_service = $token_service;
		$this->registration = $registration;
		$this->urls = $urls;
		$this->settings = $settings;
	}

	public function init(): void {
		add_action( 'rest_api_init', [ $this, 'action_register_routes' ] );
	}

	public function action_register_routes(): void {
		register_rest_route(
			Server_Urls::REST_NAMESPACE,
			'authorize',
			[
				'methods' => WP_REST_Server::READABLE,
				'callback' => [ $this, 'route_authorize' ],
				'permission_callback' => '__return_true',
			]
		);

		register_rest_route(
			Server_Urls::REST_NAMESPACE,
			'token',
			[
				'methods' => 'POST',
				'callback' => [ $this, 'route_token' ],
				'permission_callback' => '__return_true',
			]
		);

		register_rest_route(
			Server_Urls::REST_NAMESPACE,
			'register',
			[
				'methods' => 'POST',
				'callback' => [ $this, 'route_register' ],
				'permission_callback' => '__return_true',
			]
		);

		register_rest_route(
			Server_Urls::REST_NAMESPACE,
			'revoke',
			[
				'methods' => 'POST',
				'callback' => [ $this, 'route_revoke' ],
				'permission_callback' => '__return_true',
			]
		);
	}

	/**
	 * The anonymous authorization entry point. It validates the request, stores
	 * it, and hands the browser to the internal consent controller with nothing
	 * but an opaque identifier.
	 */
	public function route_authorize( WP_REST_Request $request ): WP_REST_Response {
		$params = $request->get_query_params();
		$security_parameters = [ 'client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state', 'resource', 'scope' ];

		foreach ( $security_parameters as $key ) {
			if ( isset( $params[ $key ] ) && ! is_scalar( $params[ $key ] ) ) {
				return $this->error_response(
					new OAuth_Error( 'invalid_request', __( 'Repeated request parameters are not accepted.', 'wpelevator-oauth-pilot' ) )
				);
			}
		}

		try {
			$raw_query = isset( $_SERVER['QUERY_STRING'] ) ? (string) wp_unslash( $_SERVER['QUERY_STRING'] ) : '';

			if ( '' !== $raw_query ) {
				Form_Body::parse( $raw_query )->assert_no_duplicates( $security_parameters );
			}

			$validated = $this->authorization_service->validate_request( $params );
			$created = $this->authorization_service->create_pending( $validated );
		} catch ( Redirect_Error $error ) {
			return $this->redirect_response(
				$this->authorization_service->build_redirect(
					$error->get_redirect_uri(),
					array_merge( $error->to_redirect_params(), [ 'state' => $error->get_state() ] )
				)
			);
		} catch ( OAuth_Error $error ) {
			return $this->error_response( $error );
		}

		return $this->redirect_response( $this->urls->get_consent_url( $created['request_id'] ) );
	}

	public function route_token( WP_REST_Request $request ): WP_REST_Response {
		try {
			$body = $this->get_form_body( $request );

			$response = $this->token_service->handle_token_request(
				$body,
				$request->get_header( 'authorization' )
			);
		} catch ( OAuth_Error $error ) {
			return $this->error_response( $error );
		}

		return $this->json_response( 200, $response );
	}

	public function route_register( WP_REST_Request $request ): WP_REST_Response {
		try {
			if ( ! $this->settings->is_dynamic_registration_enabled() ) {
				throw new OAuth_Error(
					'invalid_request',
					__( 'Dynamic client registration is disabled on this site.', 'wpelevator-oauth-pilot' ),
					403
				);
			}

			$limits = $this->settings->get_dynamic_registration_limits();
			$raw = (string) $request->get_body();

			if ( strlen( $raw ) > (int) $limits['max_body_bytes'] ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					__( 'The registration request is too large.', 'wpelevator-oauth-pilot' ),
					413
				);
			}

			if ( ! $request->is_json_content_type() ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					__( 'The registration endpoint accepts application/json.', 'wpelevator-oauth-pilot' ),
					415
				);
			}

			$metadata = $request->get_json_params();

			if ( ! is_array( $metadata ) ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					__( 'The registration request body must be a JSON object.', 'wpelevator-oauth-pilot' ),
					400
				);
			}

			$client = $this->registration->register_dynamic( $metadata );
		} catch ( OAuth_Error $error ) {
			return $this->error_response( $error );
		}

		return $this->json_response( 201, $client->to_registration_response() );
	}

	public function route_revoke( WP_REST_Request $request ): WP_REST_Response {
		try {
			$body = $this->get_form_body( $request );

			$this->token_service->handle_revocation( $body, $request->get_header( 'authorization' ) );
		} catch ( OAuth_Error $error ) {
			return $this->error_response( $error );
		}

		// RFC 7009: an unknown token is still a success.
		return $this->json_response( 200, [] );
	}

	/**
	 * @throws OAuth_Error When the body is not form encoded.
	 */
	private function get_form_body( WP_REST_Request $request ): Form_Body {
		if ( ! $this->has_content_type( $request, 'application/x-www-form-urlencoded' ) ) {
			throw new OAuth_Error(
				'invalid_request',
				__( 'This endpoint accepts application/x-www-form-urlencoded requests.', 'wpelevator-oauth-pilot' ),
				415
			);
		}

		return Form_Body::parse( (string) $request->get_body() );
	}

	private function has_content_type( WP_REST_Request $request, string $expected ): bool {
		$content_type = $request->get_content_type();

		return ! empty( $content_type['value'] ) && strtolower( $content_type['value'] ) === $expected;
	}

	private function redirect_response( string $url ): WP_REST_Response {
		$response = new WP_REST_Response( null, 302 );
		$response->header( 'Location', $url );

		return $this->add_security_headers( $response );
	}

	private function json_response( int $status, array $data ): WP_REST_Response {
		return $this->add_security_headers( new WP_REST_Response( $data, $status ) );
	}

	private function error_response( OAuth_Error $error ): WP_REST_Response {
		$response = new WP_REST_Response( $error->to_array(), $error->get_status() );

		foreach ( $error->get_headers() as $name => $value ) {
			$response->header( $name, $value );
		}

		return $this->add_security_headers( $response );
	}

	private function add_security_headers( WP_REST_Response $response ): WP_REST_Response {
		$headers = [
			'Cache-Control' => 'no-store',
			'Pragma' => 'no-cache',
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy' => 'no-referrer',
			'Access-Control-Expose-Headers' => 'WWW-Authenticate',
		];

		/**
		 * Customize the headers sent by the OAuth protocol endpoints.
		 *
		 * @param array $headers The response headers.
		 */
		$headers = (array) apply_filters( 'oauth_pilot__cors_headers', $headers );

		foreach ( $headers as $name => $value ) {
			$response->header( $name, $value );
		}

		return $response;
	}
}
