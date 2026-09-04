<?php

namespace WPElevator\OAuth_Pilot\Token;

use WP_Error;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Security_Events;

/**
 * Validates RFC 6750 bearer tokens against a registered protected resource.
 *
 * This is the API an MCP server calls in its permission layer.
 */
class Bearer_Validator {

	private Tokens $tokens;

	private Clients $clients;

	private Scopes $scopes;

	private Protected_Resources $resources;

	public function __construct( Tokens $tokens, Clients $clients, Scopes $scopes, Protected_Resources $resources ) {
		$this->tokens = $tokens;
		$this->clients = $clients;
		$this->scopes = $scopes;
		$this->resources = $resources;
	}

	/**
	 * Read the single accepted credential location: the Authorization header.
	 *
	 * Query string and form body bearer tokens are never accepted, whatever
	 * the client sends.
	 */
	public function get_authorization_header(): ?string {
		foreach ( [ 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ] as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				return trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
			}
		}

		if ( function_exists( 'getallheaders' ) ) {
			foreach ( (array) getallheaders() as $name => $value ) {
				if ( 'authorization' === strtolower( (string) $name ) ) {
					return trim( (string) $value );
				}
			}
		}

		return null;
	}

	/**
	 * Extract exactly one bearer credential from an Authorization header.
	 */
	public function parse_bearer_token( ?string $header ): ?string {
		if ( empty( $header ) ) {
			return null;
		}

		if ( ! preg_match( '/^Bearer\s+([A-Za-z0-9\-._~+\/]+=*)$/i', trim( $header ), $matches ) ) {
			return null;
		}

		return $matches[1];
	}

	public function has_bearer_credential(): bool {
		return null !== $this->parse_bearer_token( $this->get_authorization_header() );
	}

	/**
	 * Validate the current request against a resource and required scopes.
	 *
	 * @return Context|WP_Error
	 */
	public function validate_request( string $resource_uri, array $required_scopes = [] ) {
		$token = $this->parse_bearer_token( $this->get_authorization_header() );

		if ( ! isset( $token ) ) {
			return $this->error(
				'oauth_pilot_missing_token',
				__( 'An OAuth bearer token is required.', 'wpelevator-oauth-pilot' ),
				401,
				$resource_uri
			);
		}

		return $this->validate_token( $token, $resource_uri, $required_scopes );
	}

	/**
	 * @return Context|WP_Error
	 */
	public function validate_token( string $value, string $resource_uri, array $required_scopes = [] ) {
		$resource = $this->resources->get( $resource_uri );

		if ( ! $resource ) {
			return new WP_Error(
				'oauth_pilot_unknown_resource',
				__( 'The requested resource is not registered with OAuth Pilot.', 'wpelevator-oauth-pilot' ),
				[ 'status' => 500 ]
			);
		}

		$token = $this->tokens->get_by_value( $value, Token::TYPE_ACCESS );

		if ( ! $token || ! $token->is_active() ) {
			return $this->error(
				'oauth_pilot_invalid_token',
				__( 'The access token is expired, revoked or unknown.', 'wpelevator-oauth-pilot' ),
				401,
				$resource_uri,
				'invalid_token'
			);
		}

		// The audience is bound at issuance and compared exactly.
		if ( ! hash_equals( $token->get_resource(), $resource->get_uri() ) ) {
			Security_Events::record(
				'token_audience_mismatch',
				[
					'client_id' => $token->get_client_id(),
					'requested' => $resource->get_uri(),
				]
			);

			return $this->error(
				'oauth_pilot_invalid_token',
				__( 'The access token was issued for a different resource.', 'wpelevator-oauth-pilot' ),
				401,
				$resource_uri,
				'invalid_token'
			);
		}

		$client = $this->clients->get_by_client_id( $token->get_client_id() );

		if ( ! $client || ! $client->is_active() ) {
			return $this->error(
				'oauth_pilot_invalid_token',
				__( 'The client this token belongs to is no longer active.', 'wpelevator-oauth-pilot' ),
				401,
				$resource_uri,
				'invalid_token'
			);
		}

		$user = get_userdata( $token->get_user_id() );

		if ( ! $user ) {
			return $this->error(
				'oauth_pilot_invalid_token',
				__( 'The user this token represents no longer exists.', 'wpelevator-oauth-pilot' ),
				401,
				$resource_uri,
				'invalid_token'
			);
		}

		if ( ! $this->scopes->satisfies( $token->get_scopes(), $required_scopes ) ) {
			return $this->error(
				'oauth_pilot_insufficient_scope',
				__( 'The access token does not carry the required scope.', 'wpelevator-oauth-pilot' ),
				403,
				$resource_uri,
				'insufficient_scope',
				$required_scopes
			);
		}

		$this->tokens->touch_last_used( $token );

		$context = new Context( $token, $resource, $this->scopes );

		/**
		 * Fires after a request was authenticated with a bearer token.
		 *
		 * @param Context $context The validated context. Never the credential.
		 */
		do_action( 'oauth_pilot__bearer_authenticated', $context );

		return $context;
	}

	/**
	 * Build the RFC 6750 challenge, including the RFC 9728 resource_metadata
	 * pointer that starts an MCP client's discovery.
	 */
	public function get_challenge( string $resource_uri, ?string $error_code = null, string $description = '', array $required_scopes = [] ): string {
		$resource = $this->resources->get( $resource_uri );

		$params = [];

		if ( isset( $error_code ) ) {
			$params['error'] = $error_code;

			if ( '' !== $description ) {
				$params['error_description'] = $description;
			}
		}

		if ( ! empty( $required_scopes ) ) {
			$params['scope'] = implode( ' ', $required_scopes );
		}

		if ( $resource ) {
			$params['resource_metadata'] = $resource->get_metadata_url();
		}

		/**
		 * Add standards compliant parameters to a bearer challenge.
		 *
		 * @param array  $params       The challenge parameters.
		 * @param string $resource_uri The resource being challenged for.
		 */
		$params = (array) apply_filters( 'oauth_pilot__bearer_challenge', $params, $resource_uri );

		$parts = [];

		foreach ( $params as $key => $value ) {
			$parts[] = sprintf( '%s="%s"', $key, str_replace( '"', '', (string) $value ) );
		}

		return empty( $parts ) ? 'Bearer' : 'Bearer ' . implode( ', ', $parts );
	}

	private function error( string $code, string $message, int $status, string $resource_uri, ?string $oauth_error = null, array $required_scopes = [] ): WP_Error {
		return new WP_Error(
			$code,
			$message,
			[
				'status' => $status,
				'www_authenticate' => $this->get_challenge( $resource_uri, $oauth_error, $message, $required_scopes ),
				'resource' => $resource_uri,
				'scope' => $required_scopes,
			]
		);
	}
}
