<?php

namespace WPElevator\OAuth_Pilot\Client;

use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Rate_Limiter;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Settings;

/**
 * RFC 7591 dynamic client registration, and the shared validation used for
 * administrator created clients.
 *
 * Dynamic registration is unauthenticated because agent clients rely on it for
 * a URL-only setup, so every quota and size limit here is load-bearing.
 */
class Registration {

	private const ALLOWED_GRANT_TYPES = [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ];

	private const STRING_FIELDS = [ 'client_name', 'client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'software_id', 'software_version', 'application_type' ];

	private const URI_FIELDS = [ 'client_uri', 'logo_uri', 'tos_uri', 'policy_uri' ];

	private Clients $clients;

	private Settings $settings;

	private Rate_Limiter $rate_limiter;

	public function __construct( Clients $clients, Settings $settings, Rate_Limiter $rate_limiter ) {
		$this->clients = $clients;
		$this->settings = $settings;
		$this->rate_limiter = $rate_limiter;
	}

	/**
	 * Register a public client from an unauthenticated request.
	 *
	 * @throws OAuth_Error When registration is disabled, throttled or invalid.
	 */
	public function register_dynamic( array $metadata ): Client {
		if ( ! $this->settings->is_dynamic_registration_enabled() ) {
			throw new OAuth_Error(
				'invalid_request',
				__( 'Dynamic client registration is disabled on this site.', 'wpelevator-oauth-pilot' ),
				403
			);
		}

		$limits = $this->settings->get_dynamic_registration_limits();

		$this->assert_within_quotas( $limits );

		$normalized = $this->normalize( $metadata, $limits );

		if ( ! $this->are_redirect_hosts_allowed( $normalized['redirect_uris'] ) ) {
			Security_Events::record(
				'dynamic_registration_redirect_host_denied',
				[ 'redirect_uris' => $normalized['redirect_uris'] ]
			);

			throw new OAuth_Error(
				'invalid_redirect_uri',
				__( 'This site only accepts dynamic registration for redirect URIs on allow-listed hostnames.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		if ( Client::AUTH_NONE !== $normalized['token_endpoint_auth_method'] ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'Dynamic registration only issues public clients, which must use token_endpoint_auth_method=none.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		$client = $this->clients->create(
			[
				'name' => $normalized['client_name'],
				'client_type' => Client::TYPE_PUBLIC,
				'token_endpoint_auth_method' => Client::AUTH_NONE,
				'redirect_uris' => $normalized['redirect_uris'],
				'grant_types' => $normalized['grant_types'],
				'scopes' => [],
				'source' => Client::SOURCE_DYNAMIC,
				'metadata' => $normalized['metadata'],
			]
		);

		if ( ! $client ) {
			throw new OAuth_Error(
				'server_error',
				__( 'The client could not be stored.', 'wpelevator-oauth-pilot' ),
				500
			);
		}

		Security_Events::record(
			'client_registered',
			[
				'client_id' => $client->get_client_id(),
				'source' => Client::SOURCE_DYNAMIC,
			]
		);

		return $client;
	}

	/**
	 * Register a client on behalf of an administrator.
	 *
	 * @throws OAuth_Error When the submitted metadata is invalid.
	 */
	public function register_admin( array $metadata, int $owner_user_id ): Client {
		$limits = $this->settings->get_dynamic_registration_limits();
		$normalized = $this->normalize( $metadata, $limits );

		$is_confidential = Client::TYPE_CONFIDENTIAL === ( $metadata['client_type'] ?? Client::TYPE_PUBLIC );

		$auth_method = $normalized['token_endpoint_auth_method'];

		if ( $is_confidential && Client::AUTH_NONE === $auth_method ) {
			$auth_method = Client::AUTH_BASIC;
		}

		if ( ! $is_confidential && Client::AUTH_NONE !== $auth_method ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'Public clients must use token_endpoint_auth_method=none.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		$client = $this->clients->create(
			[
				'name' => $normalized['client_name'],
				'client_type' => $is_confidential ? Client::TYPE_CONFIDENTIAL : Client::TYPE_PUBLIC,
				'token_endpoint_auth_method' => $auth_method,
				'redirect_uris' => $normalized['redirect_uris'],
				'grant_types' => $normalized['grant_types'],
				'scopes' => array_values( (array) ( $metadata['scopes'] ?? [] ) ),
				'source' => Client::SOURCE_ADMIN,
				'owner_user_id' => $owner_user_id,
				'metadata' => $normalized['metadata'],
			]
		);

		if ( ! $client ) {
			throw new OAuth_Error(
				'server_error',
				__( 'The client could not be stored.', 'wpelevator-oauth-pilot' ),
				500
			);
		}

		Security_Events::record(
			'client_registered',
			[
				'client_id' => $client->get_client_id(),
				'source' => Client::SOURCE_ADMIN,
			]
		);

		return $client;
	}

	/**
	 * Validate and sanitize submitted client metadata.
	 *
	 * @throws OAuth_Error When a required field is missing or invalid.
	 */
	public function normalize( array $metadata, array $limits ): array {
		$redirect_uris = $this->normalize_redirect_uris( $metadata['redirect_uris'] ?? [], $limits );
		$grant_types = $this->normalize_grant_types( $metadata['grant_types'] ?? [] );

		$this->assert_response_types( $metadata['response_types'] ?? [ 'code' ] );

		$auth_method = (string) ( $metadata['token_endpoint_auth_method'] ?? Client::AUTH_NONE );

		if ( ! in_array( $auth_method, [ Client::AUTH_NONE, Client::AUTH_BASIC, Client::AUTH_POST ], true ) ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'Unsupported token endpoint authentication method.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		$sanitized = [];
		$max_length = (int) $limits['max_string_length'];

		foreach ( self::STRING_FIELDS as $field ) {
			if ( ! isset( $metadata[ $field ] ) || ! is_scalar( $metadata[ $field ] ) ) {
				continue;
			}

			$value = sanitize_text_field( (string) $metadata[ $field ] );

			if ( '' === $value ) {
				continue;
			}

			if ( strlen( $value ) > $max_length ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					sprintf(
						/* translators: %s: client metadata field name. */
						__( 'The %s value is too long.', 'wpelevator-oauth-pilot' ),
						$field
					),
					400
				);
			}

			if ( in_array( $field, self::URI_FIELDS, true ) ) {
				$value = sanitize_url( $value );

				if ( ! preg_match( '#^https?://#i', $value ) ) {
					throw new OAuth_Error(
						'invalid_client_metadata',
						sprintf(
							/* translators: %s: client metadata field name. */
							__( 'The %s value must be an absolute HTTP URL.', 'wpelevator-oauth-pilot' ),
							$field
						),
						400
					);
				}
			}

			$sanitized[ $field ] = $value;
		}

		if ( isset( $sanitized['application_type'] ) && ! in_array( $sanitized['application_type'], [ 'web', 'native' ], true ) ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'The application_type must be web or native.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		if ( ! empty( $metadata['contacts'] ) && is_array( $metadata['contacts'] ) ) {
			$contacts = array_slice(
				array_values( array_filter( array_map( 'sanitize_email', $metadata['contacts'] ) ) ),
				0,
				(int) $limits['max_contacts']
			);

			if ( ! empty( $contacts ) ) {
				$sanitized['contacts'] = $contacts;
			}
		}

		$name = $sanitized['client_name'] ?? '';

		if ( '' === $name ) {
			$name = __( 'Unnamed client', 'wpelevator-oauth-pilot' );
		}

		/**
		 * Filter normalized registration metadata before it is persisted.
		 *
		 * Security relevant fields are reapplied afterwards, so this filter
		 * cannot turn a validated value into an invalid one.
		 *
		 * @param array $sanitized The sanitized metadata.
		 * @param array $metadata  The raw submitted metadata.
		 */
		$sanitized = (array) apply_filters( 'oauth_pilot__client_registration_metadata', $sanitized, $metadata );

		return [
			'client_name' => $name,
			'redirect_uris' => $redirect_uris,
			'grant_types' => $grant_types,
			'token_endpoint_auth_method' => $auth_method,
			'metadata' => $sanitized,
		];
	}

	/**
	 * Whether every redirect URI may register dynamically, checked against the
	 * optional host allow-list.
	 *
	 * Loopback callbacks stay allowed: they are how native and CLI agent
	 * clients receive the code, and the allow-list targets web connectors.
	 */
	public function are_redirect_hosts_allowed( array $redirect_uris ): bool {
		$allowed_hosts = $this->settings->get_dynamic_registration_allowed_redirect_hosts();

		if ( empty( $allowed_hosts ) ) {
			return true;
		}

		foreach ( $redirect_uris as $uri ) {
			$parsed_host = wp_parse_url( (string) $uri, PHP_URL_HOST );
			$host = is_string( $parsed_host ) ? strtolower( $parsed_host ) : '';

			if ( '' !== $host && Redirect_URI::is_loopback_host( $host ) ) {
				continue;
			}

			if ( ! in_array( $host, $allowed_hosts, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @throws OAuth_Error When a URI is missing, duplicated or not allowed.
	 */
	private function normalize_redirect_uris( $uris, array $limits ): array {
		if ( ! is_array( $uris ) || empty( $uris ) ) {
			throw new OAuth_Error(
				'invalid_redirect_uri',
				__( 'At least one redirect URI is required.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		if ( count( $uris ) > (int) $limits['max_redirect_uris'] ) {
			throw new OAuth_Error(
				'invalid_redirect_uri',
				__( 'Too many redirect URIs.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		$normalized = [];

		foreach ( $uris as $uri ) {
			if ( ! is_string( $uri ) ) {
				throw new OAuth_Error(
					'invalid_redirect_uri',
					__( 'Redirect URIs must be strings.', 'wpelevator-oauth-pilot' ),
					400
				);
			}

			$error = Redirect_URI::get_validation_error( $uri );

			if ( isset( $error ) ) {
				throw new OAuth_Error( 'invalid_redirect_uri', $error, 400 );
			}

			if ( in_array( $uri, $normalized, true ) ) {
				throw new OAuth_Error(
					'invalid_redirect_uri',
					__( 'Duplicate redirect URIs are not accepted.', 'wpelevator-oauth-pilot' ),
					400
				);
			}

			$normalized[] = $uri;
		}

		return $normalized;
	}

	/**
	 * @throws OAuth_Error When an unsupported grant is requested.
	 */
	private function normalize_grant_types( $grant_types ): array {
		if ( empty( $grant_types ) ) {
			return [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ];
		}

		if ( ! is_array( $grant_types ) ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'The grant_types value must be an array.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		foreach ( $grant_types as $grant_type ) {
			if ( ! in_array( $grant_type, self::ALLOWED_GRANT_TYPES, true ) ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					sprintf(
						/* translators: %s: the requested grant type. */
						__( 'Unsupported grant type: %s', 'wpelevator-oauth-pilot' ),
						is_scalar( $grant_type ) ? (string) $grant_type : ''
					),
					400
				);
			}
		}

		if ( ! in_array( Client::GRANT_AUTHORIZATION_CODE, $grant_types, true ) ) {
			throw new OAuth_Error(
				'invalid_client_metadata',
				__( 'The authorization_code grant is required.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		return array_values( array_unique( $grant_types ) );
	}

	/**
	 * @throws OAuth_Error When a response type other than code is requested.
	 */
	private function assert_response_types( $response_types ): void {
		if ( ! is_array( $response_types ) ) {
			$response_types = [ $response_types ];
		}

		foreach ( $response_types as $response_type ) {
			if ( 'code' !== $response_type ) {
				throw new OAuth_Error(
					'invalid_client_metadata',
					__( 'Only the code response type is supported.', 'wpelevator-oauth-pilot' ),
					400
				);
			}
		}
	}

	/**
	 * @throws OAuth_Error When a quota is exhausted.
	 */
	private function assert_within_quotas( array $limits ): void {
		if ( $this->clients->count_active_dynamic() >= (int) $limits['max_active_clients'] ) {
			Security_Events::record( 'dynamic_registration_quota_exceeded', [ 'limit' => 'max_active_clients' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'This site has reached its dynamic client registration limit.', 'wpelevator-oauth-pilot' ),
				429
			);
		}

		$ip_hash = Security_Events::get_ip_hash();

		if ( '' !== $ip_hash && ! $this->rate_limiter->attempt( 'dcr_ip_' . $ip_hash, (int) $limits['per_ip_per_hour'], HOUR_IN_SECONDS ) ) {
			Security_Events::record( 'dynamic_registration_rate_limited', [ 'limit' => 'per_ip_per_hour' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'Too many registration attempts. Try again later.', 'wpelevator-oauth-pilot' ),
				429
			);
		}

		if ( ! $this->rate_limiter->attempt( 'dcr_site', (int) $limits['per_site_per_hour'], HOUR_IN_SECONDS ) ) {
			Security_Events::record( 'dynamic_registration_rate_limited', [ 'limit' => 'per_site_per_hour' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'Too many registration attempts. Try again later.', 'wpelevator-oauth-pilot' ),
				429
			);
		}
	}
}
