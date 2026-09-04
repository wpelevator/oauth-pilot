<?php

namespace WPElevator\OAuth_Pilot\Authorization;

use WPElevator\OAuth_Pilot\Client\Cimd;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Client\Redirect_URI;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Http\Redirect_Error;
use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Rate_Limiter;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * Validates authorization requests and turns approved ones into codes.
 *
 * This runs with no WordPress user: the anonymous protocol endpoint validates
 * everything here before any browser redirect happens.
 */
class Service {

	private Clients $clients;

	private Authorizations $authorizations;

	private Scopes $scopes;

	private Protected_Resources $resources;

	private Server_Urls $urls;

	private Tokens $tokens;

	private Cimd $cimd;

	private Settings $settings;

	private Rate_Limiter $rate_limiter;

	public function __construct(
		Clients $clients,
		Authorizations $authorizations,
		Scopes $scopes,
		Protected_Resources $resources,
		Server_Urls $urls,
		Tokens $tokens,
		Cimd $cimd,
		Settings $settings,
		Rate_Limiter $rate_limiter
	) {
		$this->clients = $clients;
		$this->authorizations = $authorizations;
		$this->scopes = $scopes;
		$this->resources = $resources;
		$this->urls = $urls;
		$this->tokens = $tokens;
		$this->cimd = $cimd;
		$this->settings = $settings;
		$this->rate_limiter = $rate_limiter;
	}

	/**
	 * Validate an authorization request.
	 *
	 * Failures before the redirect URI is trusted throw OAuth_Error and must
	 * be rendered locally. Everything after throws Redirect_Error, which may
	 * be sent back to the client.
	 *
	 * @throws OAuth_Error|Redirect_Error
	 *
	 * @return array The validated request context.
	 */
	public function validate_request( array $params ): array {
		$client_id = (string) ( $params['client_id'] ?? '' );

		if ( '' === $client_id ) {
			throw new OAuth_Error( 'invalid_request', __( 'The client_id parameter is required.', 'wpelevator-oauth-pilot' ) );
		}

		$client = $this->resolve_client( $client_id );

		if ( ! $client || ! $client->is_active() ) {
			Security_Events::record( 'authorization_unknown_client', [ 'client_id' => $client_id ] );

			throw new OAuth_Error( 'invalid_client', __( 'Unknown or inactive client.', 'wpelevator-oauth-pilot' ), 401 );
		}

		$redirect_uri = (string) ( $params['redirect_uri'] ?? '' );

		if ( '' === $redirect_uri ) {
			throw new OAuth_Error( 'invalid_request', __( 'The redirect_uri parameter is required.', 'wpelevator-oauth-pilot' ) );
		}

		$registered = Redirect_URI::match( $redirect_uri, $client->get_redirect_uris() );

		if ( ! isset( $registered ) ) {
			Security_Events::record(
				'authorization_redirect_mismatch',
				[ 'client_id' => $client->get_client_id() ]
			);

			throw new OAuth_Error( 'invalid_request', __( 'The redirect URI is not registered for this client.', 'wpelevator-oauth-pilot' ) );
		}

		// From here the redirect URI is trusted, so errors may go back to the client.
		$state = (string) ( $params['state'] ?? '' );

		if ( ! $client->allows_grant( Client::GRANT_AUTHORIZATION_CODE ) ) {
			throw new Redirect_Error( 'unauthorized_client', __( 'This client may not use the authorization code grant.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
		}

		if ( 'code' !== (string) ( $params['response_type'] ?? '' ) ) {
			throw new Redirect_Error( 'unsupported_response_type', __( 'Only the code response type is supported.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
		}

		if ( PKCE::METHOD !== (string) ( $params['code_challenge_method'] ?? '' ) ) {
			throw new Redirect_Error( 'invalid_request', __( 'The code_challenge_method must be S256.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
		}

		$code_challenge = (string) ( $params['code_challenge'] ?? '' );

		if ( ! PKCE::is_valid_challenge( $code_challenge ) ) {
			throw new Redirect_Error( 'invalid_request', __( 'A valid PKCE code challenge is required.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
		}

		$resource = $this->resolve_resource( (string) ( $params['resource'] ?? '' ), $redirect_uri, $state );

		try {
			$requested = $this->scopes->parse( (string) ( $params['scope'] ?? '' ) );
			$granted = $this->scopes->resolve_requested( $requested, $resource, $client );
		} catch ( OAuth_Error $error ) {
			throw new Redirect_Error( $error->get_error_code(), $error->get_description(), $redirect_uri, $state );
		}

		return [
			'client' => $client,
			'redirect_uri' => $registered === $redirect_uri ? $registered : $redirect_uri,
			'resource' => $resource,
			'scopes' => $granted,
			'state' => $state,
			'code_challenge' => $code_challenge,
		];
	}

	/**
	 * Persist the validated request and return the opaque identifier handed to
	 * the browser.
	 *
	 * @throws OAuth_Error When the request could not be stored.
	 */
	public function create_pending( array $validated ): array {
		$this->assert_authorization_limits( $validated['client'] );
		$this->authorizations->delete_expired();

		$limits = $this->settings->get_authorization_limits();

		if ( $this->authorizations->count_pending() >= (int) $limits['max_pending_requests'] ) {
			Security_Events::record( 'authorization_rate_limited', [ 'limit' => 'max_pending_requests' ] );

			throw new OAuth_Error( 'temporarily_unavailable', __( 'Too many authorization requests are pending. Try again later.', 'wpelevator-oauth-pilot' ), 429 );
		}

		$created = $this->authorizations->create(
			[
				'client_id' => $validated['client']->get_client_id(),
				'client_snapshot' => $validated['client']->to_snapshot(),
				'redirect_uri' => $validated['redirect_uri'],
				'scopes' => $validated['scopes'],
				'resource' => $validated['resource']->get_uri(),
				'code_challenge' => $validated['code_challenge'],
				'state' => $validated['state'],
			]
		);

		if ( ! $created ) {
			throw new OAuth_Error( 'server_error', __( 'The authorization request could not be stored.', 'wpelevator-oauth-pilot' ), 500 );
		}

		return $created;
	}

	/**
	 * @throws OAuth_Error When an authorization request quota is exhausted.
	 */
	private function assert_authorization_limits( Client $client ): void {
		$limits = $this->settings->get_authorization_limits();
		$checks = [
			'client' => [ 'authorization_client_' . $client->get_client_id(), (int) $limits['per_client_per_hour'] ],
			'site' => [ 'authorization_site', (int) $limits['per_site_per_hour'] ],
		];
		$ip_hash = Security_Events::get_ip_hash();

		if ( '' !== $ip_hash ) {
			$checks = [ 'ip' => [ 'authorization_ip_' . $ip_hash, (int) $limits['per_ip_per_hour'] ] ] + $checks;
		}

		foreach ( $checks as $name => $check ) {
			if ( $this->rate_limiter->attempt( $check[0], $check[1], HOUR_IN_SECONDS ) ) {
				continue;
			}

			Security_Events::record( 'authorization_rate_limited', [ 'limit' => 'per_' . $name . '_per_hour' ] );

			throw new OAuth_Error( 'temporarily_unavailable', __( 'Too many authorization requests. Try again later.', 'wpelevator-oauth-pilot' ), 429 );
		}
	}

	/**
	 * Approve a bound authorization and build the client redirect.
	 *
	 * @return string|null The redirect URL, or null when the row was no longer
	 *                     claimable.
	 */
	/**
	 * @param string[]|null $scopes The scopes actually granted, when they are
	 *                              narrower than the ones requested. Defaults to
	 *                              the requested set.
	 */
	public function approve( Authorization $authorization, int $user_id, ?array $scopes = null ): ?string {
		$code = $this->authorizations->approve( $authorization, $user_id, $scopes ?? $authorization->get_scopes() );

		if ( ! isset( $code ) ) {
			return null;
		}

		$client = $this->clients->get_by_client_id( $authorization->get_client_id() );

		if ( $client ) {
			$this->clients->touch_last_used( $client );
		}

		/**
		 * Fires after a user approved a validated authorization request.
		 *
		 * @param Authorization $authorization The approved authorization.
		 * @param int           $user_id       The approving user.
		 */
		do_action( 'oauth_pilot__authorization_approved', $authorization, $user_id );

		Security_Events::record(
			'authorization_approved',
			[
				'client_id' => $authorization->get_client_id(),
				'user_id' => $user_id,
				'resource' => $authorization->get_resource(),
			]
		);

		return $this->build_redirect(
			$authorization->get_redirect_uri(),
			[
				'code' => $code,
				'state' => $authorization->get_state(),
			]
		);
	}

	public function deny( Authorization $authorization, int $user_id ): string {
		$this->authorizations->deny( $authorization, $user_id );

		/**
		 * Fires after a user denied a validated authorization request.
		 *
		 * @param Authorization $authorization The denied authorization.
		 * @param int           $user_id       The denying user.
		 */
		do_action( 'oauth_pilot__authorization_denied', $authorization, $user_id );

		Security_Events::record(
			'authorization_denied',
			[
				'client_id' => $authorization->get_client_id(),
				'user_id' => $user_id,
			]
		);

		return $this->build_redirect(
			$authorization->get_redirect_uri(),
			[
				'error' => 'access_denied',
				'state' => $authorization->get_state(),
			]
		);
	}

	/**
	 * Whether this user already granted the same client the same scopes for
	 * the same resource, which is what remembered consent is derived from.
	 */
	/**
	 * @param string[]|null $scopes The scopes that would be granted now, when
	 *                              they are narrower than the ones requested.
	 */
	public function has_remembered_consent( Authorization $authorization, int $user_id, ?array $scopes = null ): bool {
		$remembered = $this->tokens->has_active_grant(
			$user_id,
			$authorization->get_client_id(),
			$authorization->get_resource(),
			$scopes ?? $authorization->get_scopes()
		);

		/**
		 * Force a fresh consent screen.
		 *
		 * @param bool          $required      Whether consent must be shown again.
		 * @param Authorization $authorization The pending authorization.
		 * @param int           $user_id       The authorizing user.
		 */
		$required = (bool) apply_filters( 'oauth_pilot__consent_required', ! $remembered, $authorization, $user_id );

		return ! $required;
	}

	/**
	 * Append the OAuth response parameters, always including the RFC 9207
	 * issuer so a client can tell which server answered.
	 */
	public function build_redirect( string $redirect_uri, array $params ): string {
		$params['iss'] = $this->urls->get_issuer();

		return add_query_arg(
			array_map( 'rawurlencode', array_filter( $params, fn ( $value ) => '' !== $value ) ),
			$redirect_uri
		);
	}

	/**
	 * Resolve an authorization request's client_id against registered clients,
	 * falling back to Client ID Metadata Document resolution for HTTPS URL
	 * client identifiers.
	 *
	 * @throws OAuth_Error When a CIMD client_id cannot be resolved.
	 */
	private function resolve_client( string $client_id ): ?Client {
		if ( $this->cimd->is_cimd_client_id( $client_id ) ) {
			return $this->cimd->resolve_for_authorization( $client_id );
		}

		return $this->clients->get_by_client_id( $client_id );
	}

	/**
	 * @throws Redirect_Error When the requested resource is unknown.
	 */
	private function resolve_resource( string $requested, string $redirect_uri, string $state ): Protected_Resource {
		if ( '' !== $requested ) {
			$resource = $this->resources->get( $requested );

			if ( ! $resource ) {
				throw new Redirect_Error( 'invalid_target', __( 'The requested resource is not registered on this server.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
			}

			return $resource;
		}

		$resource = $this->resources->get_default();

		if ( ! $resource ) {
			throw new Redirect_Error( 'invalid_target', __( 'A resource parameter is required because this server has no default resource.', 'wpelevator-oauth-pilot' ), $redirect_uri, $state );
		}

		return $resource;
	}
}
