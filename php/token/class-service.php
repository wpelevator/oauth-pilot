<?php

namespace WPElevator\OAuth_Pilot\Token;

use WPElevator\OAuth_Pilot\Authorization\Authorization;
use WPElevator\OAuth_Pilot\Authorization\Authorizations;
use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Client\Authentication;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Client\Redirect_URI;
use WPElevator\OAuth_Pilot\Http\Form_Body;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Rate_Limiter;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;

/**
 * The token and revocation grant handlers.
 */
class Service {

	private Clients $clients;

	private Authorizations $authorizations;

	private Tokens $tokens;

	private Scopes $scopes;

	private Protected_Resources $resources;

	private Settings $settings;

	private Server_Urls $urls;

	private Authentication $client_authentication;

	private Rate_Limiter $rate_limiter;

	public function __construct(
		Clients $clients,
		Authorizations $authorizations,
		Tokens $tokens,
		Scopes $scopes,
		Protected_Resources $resources,
		Settings $settings,
		Server_Urls $urls,
		Authentication $client_authentication,
		Rate_Limiter $rate_limiter
	) {
		$this->clients = $clients;
		$this->authorizations = $authorizations;
		$this->tokens = $tokens;
		$this->scopes = $scopes;
		$this->resources = $resources;
		$this->settings = $settings;
		$this->urls = $urls;
		$this->client_authentication = $client_authentication;
		$this->rate_limiter = $rate_limiter;
	}

	/**
	 * @throws OAuth_Error
	 */
	public function handle_token_request( Form_Body $body, ?string $authorization_header ): array {
		$body->assert_no_duplicates(
			[ 'grant_type', 'code', 'code_verifier', 'client_id', 'client_secret', 'redirect_uri', 'refresh_token', 'resource', 'scope' ]
		);

		$grant_type = $body->get( 'grant_type' );

		if ( Client::GRANT_AUTHORIZATION_CODE === $grant_type ) {
			return $this->handle_authorization_code( $body, $authorization_header );
		}

		if ( Client::GRANT_REFRESH_TOKEN === $grant_type ) {
			return $this->handle_refresh_token( $body, $authorization_header );
		}

		throw new OAuth_Error(
			'unsupported_grant_type',
			__( 'Only the authorization_code and refresh_token grants are supported.', 'wpelevator-oauth-pilot' )
		);
	}

	/**
	 * @throws OAuth_Error
	 */
	private function handle_authorization_code( Form_Body $body, ?string $authorization_header ): array {
		$client = $this->client_authentication->authenticate( $body, $authorization_header );

		$this->assert_token_rate_limit( $client );

		$code = $body->get( 'code' );

		if ( '' === $code ) {
			throw new OAuth_Error( 'invalid_request', __( 'The code parameter is required.', 'wpelevator-oauth-pilot' ) );
		}

		$authorization = $this->authorizations->get_by_code( $code );

		if ( ! $authorization ) {
			throw $this->invalid_grant( __( 'The authorization code is not valid.', 'wpelevator-oauth-pilot' ) );
		}

		if ( ! hash_equals( $authorization->get_client_id(), $client->get_client_id() ) ) {
			throw $this->invalid_grant( __( 'The authorization code was issued to a different client.', 'wpelevator-oauth-pilot' ) );
		}

		if ( $authorization->is_consumed() ) {
			// A code presented twice means it leaked: burn everything it produced.
			$this->authorizations->handle_code_reuse( $authorization );

			throw $this->invalid_grant( __( 'The authorization code has already been used.', 'wpelevator-oauth-pilot' ) );
		}

		if ( Authorization::STATUS_APPROVED !== $authorization->get_status() || $authorization->is_expired() ) {
			throw $this->invalid_grant( __( 'The authorization code is expired or was never approved.', 'wpelevator-oauth-pilot' ) );
		}

		$redirect_uri = $body->get( 'redirect_uri' );

		if ( '' === $redirect_uri || ! Redirect_URI::equals( $redirect_uri, $authorization->get_redirect_uri() ) ) {
			throw $this->invalid_grant( __( 'The redirect URI does not match the authorization request.', 'wpelevator-oauth-pilot' ) );
		}

		$requested_resource = $body->get( 'resource' );

		if ( '' !== $requested_resource && $this->urls->normalize_url( $requested_resource ) !== $authorization->get_resource() ) {
			throw new OAuth_Error( 'invalid_target', __( 'The resource does not match the authorization request.', 'wpelevator-oauth-pilot' ) );
		}

		$verifier = $body->get( 'code_verifier' );

		if ( ! PKCE::verify( $verifier, $authorization->get_code_challenge() ) ) {
			Security_Events::record(
				'pkce_verification_failed',
				[ 'client_id' => $client->get_client_id() ]
			);

			throw $this->invalid_grant( __( 'The PKCE code verifier is not valid.', 'wpelevator-oauth-pilot' ) );
		}

		// The atomic claim. Whoever loses this race gets invalid_grant, and
		// no second token set is ever issued for the same code.
		if ( ! $this->authorizations->consume( $authorization ) ) {
			throw $this->invalid_grant( __( 'The authorization code has already been used.', 'wpelevator-oauth-pilot' ) );
		}

		$user_id = (int) $authorization->get_user_id();

		if ( $user_id <= 0 ) {
			throw $this->invalid_grant( __( 'The authorization is not bound to a user.', 'wpelevator-oauth-pilot' ) );
		}

		$this->clients->touch_last_used( $client );

		return $this->issue_token_set(
			$client,
			$user_id,
			$authorization->get_scopes(),
			$authorization->get_resource(),
			$this->tokens->new_family_id(),
			[ 'authorization_id' => $authorization->get_id() ]
		);
	}

	/**
	 * @throws OAuth_Error
	 */
	private function handle_refresh_token( Form_Body $body, ?string $authorization_header ): array {
		$client = $this->client_authentication->authenticate( $body, $authorization_header );

		$this->assert_token_rate_limit( $client );

		if ( ! $client->allows_grant( Client::GRANT_REFRESH_TOKEN ) ) {
			throw new OAuth_Error( 'unauthorized_client', __( 'This client may not use the refresh token grant.', 'wpelevator-oauth-pilot' ) );
		}

		$presented = $body->get( 'refresh_token' );

		if ( '' === $presented ) {
			throw new OAuth_Error( 'invalid_request', __( 'The refresh_token parameter is required.', 'wpelevator-oauth-pilot' ) );
		}

		$token = $this->tokens->get_by_value( $presented, Token::TYPE_REFRESH );

		if ( ! $token ) {
			throw $this->invalid_grant( __( 'The refresh token is not valid.', 'wpelevator-oauth-pilot' ) );
		}

		if ( ! hash_equals( $token->get_client_id(), $client->get_client_id() ) ) {
			throw $this->invalid_grant( __( 'The refresh token was issued to a different client.', 'wpelevator-oauth-pilot' ) );
		}

		if ( $token->is_consumed() ) {
			$this->tokens->handle_refresh_reuse( $token );

			throw $this->invalid_grant( __( 'The refresh token has already been used.', 'wpelevator-oauth-pilot' ) );
		}

		if ( $token->is_revoked() || $token->is_expired() ) {
			throw $this->invalid_grant( __( 'The refresh token is expired or revoked.', 'wpelevator-oauth-pilot' ) );
		}

		$requested_resource = $body->get( 'resource' );

		if ( '' !== $requested_resource && $this->urls->normalize_url( $requested_resource ) !== $token->get_resource() ) {
			throw new OAuth_Error( 'invalid_target', __( 'The resource does not match the refresh token.', 'wpelevator-oauth-pilot' ) );
		}

		$scopes = $token->get_scopes();
		$requested_scope = $body->get( 'scope' );

		if ( '' !== $requested_scope ) {
			$requested = $this->scopes->parse( $requested_scope );

			/*
			 * Drop what this server never registered, exactly as the
			 * authorization request does. A client that echoes its original
			 * scope string here is otherwise refused over a scope that was
			 * silently ignored when the grant was made.
			 */
			$requested = array_values(
				array_filter(
					$requested,
					fn ( $name ) => $this->scopes->has( (string) $name )
				)
			);

			// A refresh may narrow the grant, never widen it.
			if ( ! empty( array_diff( $requested, $scopes ) ) ) {
				throw new OAuth_Error( 'invalid_scope', __( 'A refresh request may not add scopes.', 'wpelevator-oauth-pilot' ) );
			}

			// Nothing recognizable was asked for, so the grant carries over whole.
			if ( ! empty( $requested ) ) {
				$scopes = $requested;
			}
		}

		if ( ! $this->tokens->consume_refresh_token( $token ) ) {
			// Someone else claimed it first: treat it as reuse.
			$this->tokens->handle_refresh_reuse( $token );

			throw $this->invalid_grant( __( 'The refresh token has already been used.', 'wpelevator-oauth-pilot' ) );
		}

		$this->clients->touch_last_used( $client );

		return $this->issue_token_set(
			$client,
			$token->get_user_id(),
			$scopes,
			$token->get_resource(),
			$token->get_family_id(),
			[
				'parent_id' => $token->get_id(),
				'authorization_id' => $token->get_authorization_id(),
			]
		);
	}

	/**
	 * Issue an access token and, unless a filter says otherwise, a rotating
	 * refresh token.
	 *
	 * Refresh tokens are not gated on an offline_access scope: agent clients
	 * do not request it, and without a refresh token their connection dies
	 * when the first access token expires.
	 *
	 * @throws OAuth_Error When persistence failed.
	 */
	private function issue_token_set( Client $client, int $user_id, array $scopes, string $resource_uri, string $family_id, array $args = [] ): array {
		/**
		 * Filter the access token lifetime in seconds.
		 *
		 * @param int    $lifetime Configured lifetime.
		 * @param Client $client   The client the token is issued to.
		 * @param int    $user_id  The represented user.
		 * @param string $resource_uri The token audience.
		 * @param array  $scopes   The granted scopes.
		 */
		$access_lifetime = (int) apply_filters(
			'oauth_pilot__access_token_lifetime',
			(int) $this->settings->get( 'access_token_lifetime' ),
			$client,
			$user_id,
			$resource_uri,
			$scopes
		);

		$access = $this->tokens->issue(
			[
				'token_type' => Token::TYPE_ACCESS,
				'client_id' => $client->get_client_id(),
				'user_id' => $user_id,
				'scopes' => $scopes,
				'resource' => $resource_uri,
				'family_id' => $family_id,
				'authorization_id' => $args['authorization_id'] ?? null,
				'lifetime' => $access_lifetime,
			]
		);

		if ( ! $access ) {
			$this->tokens->revoke_family( $family_id );

			throw new OAuth_Error( 'server_error', __( 'The access token could not be stored.', 'wpelevator-oauth-pilot' ), 500 );
		}

		$response = [
			'access_token' => $access['value'],
			'token_type' => 'Bearer',
			'expires_in' => $access['token']->get_expires_in(),
			'scope' => implode( ' ', $scopes ),
			'resource' => $resource_uri,
		];

		/**
		 * Opt out of issuing a refresh token for one grant.
		 *
		 * @param bool   $issue    Whether to issue a refresh token.
		 * @param Client $client   The client.
		 * @param int    $user_id  The represented user.
		 * @param array  $scopes   The granted scopes.
		 */
		$issue_refresh = (bool) apply_filters( 'oauth_pilot__issue_refresh_token', true, $client, $user_id, $scopes );

		if ( ! $issue_refresh || ! $client->allows_grant( Client::GRANT_REFRESH_TOKEN ) ) {
			return $response;
		}

		/**
		 * Filter the refresh token lifetime in seconds.
		 *
		 * @param int    $lifetime Configured lifetime.
		 * @param Client $client   The client.
		 * @param int    $user_id  The represented user.
		 * @param string $resource_uri The token audience.
		 */
		$refresh_lifetime = (int) apply_filters(
			'oauth_pilot__refresh_token_lifetime',
			(int) $this->settings->get( 'refresh_token_lifetime' ),
			$client,
			$user_id,
			$resource_uri
		);

		$refresh = $this->tokens->issue(
			[
				'token_type' => Token::TYPE_REFRESH,
				'client_id' => $client->get_client_id(),
				'user_id' => $user_id,
				'scopes' => $scopes,
				'resource' => $resource_uri,
				'family_id' => $family_id,
				'parent_id' => $args['parent_id'] ?? null,
				'authorization_id' => $args['authorization_id'] ?? null,
				'lifetime' => $refresh_lifetime,
			]
		);

		if ( ! $refresh ) {
			// Never hand out an access token whose refresh chain is broken.
			$this->tokens->revoke_family( $family_id );

			throw new OAuth_Error( 'server_error', __( 'The refresh token could not be stored.', 'wpelevator-oauth-pilot' ), 500 );
		}

		$response['refresh_token'] = $refresh['value'];

		return $response;
	}

	/**
	 * RFC 7009 revocation. Unknown tokens are a success by design.
	 *
	 * @throws OAuth_Error When the client cannot be authenticated.
	 */
	public function handle_revocation( Form_Body $body, ?string $authorization_header ): void {
		$body->assert_no_duplicates( [ 'token', 'token_type_hint', 'client_id', 'client_secret' ] );

		$client = $this->client_authentication->authenticate( $body, $authorization_header );

		$presented = $body->get( 'token' );

		if ( '' === $presented ) {
			throw new OAuth_Error( 'invalid_request', __( 'The token parameter is required.', 'wpelevator-oauth-pilot' ) );
		}

		$token = $this->tokens->get_by_value( $presented );

		if ( ! $token ) {
			return;
		}

		if ( ! hash_equals( $token->get_client_id(), $client->get_client_id() ) ) {
			// Not this client's token: say nothing about it.
			return;
		}

		if ( Token::TYPE_REFRESH === $token->get_type() ) {
			$this->tokens->revoke_family( $token->get_family_id() );
		} else {
			$this->tokens->revoke( $token );
		}

		Security_Events::record(
			'token_revoked',
			[
				'client_id' => $token->get_client_id(),
				'user_id' => $token->get_user_id(),
				'token_type' => $token->get_type(),
			]
		);
	}

	/**
	 * @throws OAuth_Error When the client is issuing too many token requests.
	 */
	private function assert_token_rate_limit( Client $client ): void {
		$key = 'token_' . $client->get_client_id();

		// A public client identifier is not a credential, so an attacker must not
		// be able to lock out every legitimate instance that shares it.
		if ( $client->is_public() ) {
			$ip_hash = Security_Events::get_ip_hash();
			$key .= '_ip_' . ( '' !== $ip_hash ? $ip_hash : 'unknown' );
		}

		if ( $this->rate_limiter->attempt( $key, 300, HOUR_IN_SECONDS ) ) {
			return;
		}

		Security_Events::record( 'token_rate_limited', [ 'client_id' => $client->get_client_id() ] );

		throw new OAuth_Error(
			'invalid_request',
			__( 'Too many token requests. Try again later.', 'wpelevator-oauth-pilot' ),
			429
		);
	}

	private function invalid_grant( string $description ): OAuth_Error {
		return new OAuth_Error( 'invalid_grant', $description );
	}
}
