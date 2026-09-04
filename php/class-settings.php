<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Plugin settings.
 *
 * Each setting is its own option rather than one serialized array, so every
 * one of them registers with its own type, default and sanitizer. That is what
 * lets WordPress expose them individually on /wp/v2/settings, validate them
 * against a real schema, and give other code a single named option to filter
 * or preload.
 */
class Settings {

	/**
	 * Every option name is this prefix plus the setting key, matching the
	 * plugin's filter naming and the option naming the sibling plugins use.
	 */
	public const OPTION_PREFIX = 'oauth_pilot__';

	/**
	 * The settings group the admin form posts to.
	 */
	public const GROUP = 'oauth_pilot';

	public const MIN_ACCESS_TOKEN_LIFETIME = 300;

	public const MAX_ACCESS_TOKEN_LIFETIME = DAY_IN_SECONDS;

	public const MIN_REFRESH_TOKEN_LIFETIME = HOUR_IN_SECONDS;

	public const MAX_REFRESH_TOKEN_LIFETIME = 180 * DAY_IN_SECONDS;

	/**
	 * The definition of every setting: what it stores, what it defaults to, and
	 * how it is narrowed back to a safe value. register() turns each entry into
	 * a register_setting() call, and the accessors below read through it.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function get_schema(): array {
		return [
			'dynamic_registration_enabled' => [
				'type' => 'boolean',
				// Dynamic client registration is deprecated in favor of Client
				// ID Metadata Documents, so a new site exposes no
				// unauthenticated endpoint that writes client rows.
				'default' => false,
				'description' => __( 'Whether anonymous clients may register themselves over RFC 7591.', 'wpelevator-oauth-pilot' ),
				'sanitize_callback' => [ $this, 'sanitize_bool' ],
			],
			'cimd_enabled' => [
				'type' => 'boolean',
				'default' => true,
				'description' => __( 'Whether an HTTPS URL client_id resolves to a Client ID Metadata Document.', 'wpelevator-oauth-pilot' ),
				'sanitize_callback' => [ $this, 'sanitize_bool' ],
			],
			'dynamic_registration_allowed_redirect_hosts' => [
				'type' => 'string',
				'default' => '',
				'description' => __( 'Newline separated redirect URI hosts dynamic registration accepts. Empty allows any host.', 'wpelevator-oauth-pilot' ),
				'sanitize_callback' => [ $this, 'sanitize_host_list' ],
			],
			'rest_authentication_enabled' => [
				'type' => 'boolean',
				// Off by default: an MCP scoped token must not reach the whole REST API
				// before cross resource rejection has been proven on a real site.
				'default' => false,
				'description' => __( 'Whether an OAuth bearer token may authenticate ordinary WordPress REST requests.', 'wpelevator-oauth-pilot' ),
				'sanitize_callback' => [ $this, 'sanitize_bool' ],
			],
			'access_token_lifetime' => [
				'type' => 'integer',
				'default' => Token\Tokens::ACCESS_LIFETIME,
				'description' => __( 'How long an access token stays valid, in seconds.', 'wpelevator-oauth-pilot' ),
				'minimum' => self::MIN_ACCESS_TOKEN_LIFETIME,
				'maximum' => self::MAX_ACCESS_TOKEN_LIFETIME,
				'sanitize_callback' => [ $this, 'sanitize_access_token_lifetime' ],
			],
			'refresh_token_lifetime' => [
				'type' => 'integer',
				'default' => Token\Tokens::REFRESH_LIFETIME,
				'description' => __( 'How long a refresh token stays valid, in seconds.', 'wpelevator-oauth-pilot' ),
				'minimum' => self::MIN_REFRESH_TOKEN_LIFETIME,
				'maximum' => self::MAX_REFRESH_TOKEN_LIFETIME,
				'sanitize_callback' => [ $this, 'sanitize_refresh_token_lifetime' ],
			],
		];
	}

	/**
	 * Register every setting so WordPress owns the defaults, the sanitizing and
	 * the REST schema.
	 *
	 * Must run on init rather than admin_init: show_in_rest only reaches
	 * /wp/v2/settings when the setting is registered for REST requests too.
	 */
	public function register(): void {
		foreach ( $this->get_schema() as $key => $definition ) {
			$rest_schema = [
				'type' => $definition['type'],
				'description' => $definition['description'],
			];

			if ( isset( $definition['minimum'] ) ) {
				$rest_schema['minimum'] = $definition['minimum'];
				$rest_schema['maximum'] = $definition['maximum'];
			}

			register_setting(
				self::GROUP,
				$this->get_option_name( $key ),
				[
					'type' => $definition['type'],
					'label' => $definition['description'],
					'description' => $definition['description'],
					'default' => $definition['default'],
					'sanitize_callback' => $definition['sanitize_callback'],
					'show_in_rest' => [
						'name' => $this->get_option_name( $key ),
						'schema' => $rest_schema,
					],
				]
			);
		}
	}

	/**
	 * The option a setting key is stored in.
	 */
	public function get_option_name( string $key ): string {
		return self::OPTION_PREFIX . $key;
	}

	public function get_defaults(): array {
		return wp_list_pluck( $this->get_schema(), 'default' );
	}

	public function all(): array {
		$values = [];

		foreach ( array_keys( $this->get_schema() ) as $key ) {
			$values[ $key ] = $this->get( $key );
		}

		return $values;
	}

	/**
	 * @return mixed
	 */
	public function get( string $key ) {
		$schema = $this->get_schema();

		if ( ! isset( $schema[ $key ] ) ) {
			return null;
		}

		$value = get_option( $this->get_option_name( $key ), $schema[ $key ]['default'] );

		// An option written before this setting existed - or by hand - is
		// narrowed the same way a submitted value would be.
		return call_user_func( $schema[ $key ]['sanitize_callback'], $value );
	}

	/**
	 * Write the given settings, leaving every key that was not supplied alone.
	 *
	 * @param array $values Setting keys mapped to their new values.
	 */
	public function update( array $values ): bool {
		$updated = false;

		foreach ( $this->get_schema() as $key => $definition ) {
			if ( ! array_key_exists( $key, $values ) ) {
				continue;
			}

			$sanitized = call_user_func( $definition['sanitize_callback'], $values[ $key ] );

			if ( update_option( $this->get_option_name( $key ), $sanitized, true ) ) {
				$updated = true;
			}
		}

		return $updated;
	}

	/**
	 * @param mixed $value
	 */
	public function sanitize_bool( $value ): bool {
		return ! empty( $value ) && 'false' !== $value && '0' !== $value;
	}

	/**
	 * @param mixed $value
	 */
	public function sanitize_host_list( $value ): string {
		return implode( "\n", self::parse_host_list( is_scalar( $value ) ? (string) $value : '' ) );
	}

	/**
	 * @param mixed $value
	 */
	public function sanitize_access_token_lifetime( $value ): int {
		return $this->clamp( (int) $value, self::MIN_ACCESS_TOKEN_LIFETIME, self::MAX_ACCESS_TOKEN_LIFETIME );
	}

	/**
	 * @param mixed $value
	 */
	public function sanitize_refresh_token_lifetime( $value ): int {
		return $this->clamp( (int) $value, self::MIN_REFRESH_TOKEN_LIFETIME, self::MAX_REFRESH_TOKEN_LIFETIME );
	}

	public function is_dynamic_registration_enabled(): bool {
		/**
		 * Disable dynamic client registration while keeping administrator
		 * created clients working.
		 *
		 * @param bool $enabled Whether DCR is enabled.
		 */
		return (bool) apply_filters( 'oauth_pilot__dynamic_registration_enabled', (bool) $this->get( 'dynamic_registration_enabled' ) );
	}

	public function is_cimd_enabled(): bool {
		/**
		 * Disable Client ID Metadata Document resolution while keeping DCR and
		 * administrator created clients working.
		 *
		 * @param bool $enabled Whether CIMD is enabled.
		 */
		return (bool) apply_filters( 'oauth_pilot__cimd_enabled', (bool) $this->get( 'cimd_enabled' ) );
	}

	public function is_rest_authentication_enabled(): bool {
		/**
		 * Enable OAuth bearer authentication for the WordPress REST API.
		 *
		 * @param bool $enabled Whether REST bearer authentication is enabled.
		 */
		return (bool) apply_filters( 'oauth_pilot__enable_rest_authentication', (bool) $this->get( 'rest_authentication_enabled' ) );
	}

	/**
	 * The allow-listed redirect URI hosts for dynamic registration, or an empty
	 * array when any host may register.
	 *
	 * @return string[] Lowercase hostnames.
	 */
	public function get_dynamic_registration_allowed_redirect_hosts(): array {
		/**
		 * Filter the redirect URI hosts dynamic registration accepts.
		 *
		 * Return an empty array to allow any host.
		 *
		 * @param string[] $hosts Lowercase hostnames.
		 */
		$hosts = (array) apply_filters( 'oauth_pilot__dynamic_registration_allowed_redirect_hosts', self::parse_host_list( (string) $this->get( 'dynamic_registration_allowed_redirect_hosts' ) ) );

		return array_values( array_unique( array_filter( array_map( 'strtolower', array_map( 'strval', $hosts ) ) ) ) );
	}

	/**
	 * Split a host list on whitespace, strip punctuation pasted around a host
	 * (separators, quotes, ports, paths), reduce pasted URLs to their host, and
	 * drop anything that is not a plain hostname.
	 *
	 * @return string[] Lowercase hostnames, deduplicated.
	 */
	public static function parse_host_list( string $raw ): array {
		$hosts = [];

		foreach ( preg_split( '/\s+/u', $raw ) as $part ) {
			$part = preg_replace( '/^\W+|\W+$/u', '', strtolower( $part ) );

			if ( ! is_string( $part ) || '' === $part ) {
				continue;
			}

			// A bare host parses as a path, so give the authority the // prefix.
			$host_input = false === strpos( $part, '://' ) ? '//' . $part : $part;

			$parsed_host = wp_parse_url( $host_input, PHP_URL_HOST );
			$host = is_string( $parsed_host ) ? strtolower( $parsed_host ) : '';

			if ( '' === $host || ! preg_match( '/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/', $host ) ) {
				continue;
			}

			$hosts[] = $host;
		}

		return array_values( array_unique( $hosts ) );
	}

	public function get_dynamic_registration_limits(): array {
		$limits = [
			'per_ip_per_hour' => 10,
			'per_site_per_hour' => 100,
			'max_active_clients' => 1000,
			'max_redirect_uris' => 10,
			'max_uri_length' => Client\Redirect_URI::MAX_LENGTH,
			'max_body_bytes' => 32 * KB_IN_BYTES,
			'max_string_length' => 512,
			'max_contacts' => 10,
		];

		/**
		 * Adjust dynamic client registration quotas and size limits.
		 *
		 * Disabling these leaves the registration endpoint unbounded.
		 *
		 * @param array $limits The default limits.
		 */
		return (array) apply_filters( 'oauth_pilot__dynamic_registration_limits', $limits );
	}

	public function get_cimd_limits(): array {
		$limits = [
			'per_ip_per_hour' => 30,
			'per_host_per_hour' => 10,
			'per_site_per_hour' => 300,
			'max_active_clients' => 2000,
			// The draft recommends a small bound: a metadata document is a
			// handful of fields, and this cap is what an unauthenticated
			// request can make the site buffer.
			'max_document_bytes' => 5 * KB_IN_BYTES,
			'max_metadata_url_length' => 512,
			'max_redirect_uris' => 10,
			'max_uri_length' => Client\Redirect_URI::MAX_LENGTH,
			'max_string_length' => 512,
			'max_contacts' => 10,
			'fetch_timeout_seconds' => 5,
			'cache_default_seconds' => HOUR_IN_SECONDS,
			'cache_min_seconds' => 5 * MINUTE_IN_SECONDS,
			'cache_max_seconds' => DAY_IN_SECONDS,
		];

		/**
		 * Adjust Client ID Metadata Document resolution limits.
		 *
		 * These bound the server side fetches triggered by unauthenticated
		 * authorization requests. Disabling them leaves CIMD unbounded.
		 *
		 * @param array $limits The default limits.
		 */
		return (array) apply_filters( 'oauth_pilot__cimd_limits', $limits );
	}

	public function get_authorization_limits(): array {
		$limits = [
			'per_ip_per_hour' => 60,
			'per_client_per_hour' => 300,
			'per_site_per_hour' => 1000,
			'max_pending_requests' => 1000,
		];

		/**
		 * Adjust authorization request quotas.
		 *
		 * @param array $limits The default limits.
		 */
		return (array) apply_filters( 'oauth_pilot__authorization_limits', $limits );
	}

	private function clamp( int $value, int $min, int $max ): int {
		return max( $min, min( $max, $value ) );
	}
}
