<?php

namespace WPElevator\OAuth_Pilot\Client;

/**
 * Redirect URI validation and comparison.
 *
 * Registration-time validation is strict. Authorization-time comparison is an
 * exact string match, with the single documented exception RFC 8252 requires
 * for loopback ports.
 *
 * Static by design: pure functions with no state, like Random.
 */
class Redirect_URI {

	public const LOOPBACK_HOSTS = [ '127.0.0.1', '::1', '[::1]', 'localhost' ];

	private const DENIED_SCHEMES = [ 'javascript', 'data', 'file', 'vbscript', 'blob' ];

	public const MAX_LENGTH = 2048;

	/**
	 * Whether a URI may be registered for a client.
	 */
	public static function is_valid( string $uri ): bool {
		return null === self::get_validation_error( $uri );
	}

	/**
	 * @return string|null A human readable reason, or null when the URI is valid.
	 */
	public static function get_validation_error( string $uri ): ?string {
		if ( '' === $uri ) {
			return __( 'The redirect URI is empty.', 'wpelevator-oauth-pilot' );
		}

		if ( strlen( $uri ) > self::MAX_LENGTH ) {
			return __( 'The redirect URI is too long.', 'wpelevator-oauth-pilot' );
		}

		if ( trim( $uri ) !== $uri || preg_match( '/[\x00-\x20\x7F]/', $uri ) ) {
			return __( 'The redirect URI contains whitespace or control characters.', 'wpelevator-oauth-pilot' );
		}

		if ( false !== strpos( $uri, '*' ) ) {
			return __( 'Wildcard redirect URIs are not supported.', 'wpelevator-oauth-pilot' );
		}

		$parts = wp_parse_url( $uri );

		if ( empty( $parts ) || empty( $parts['scheme'] ) ) {
			return __( 'The redirect URI must be absolute and include a scheme.', 'wpelevator-oauth-pilot' );
		}

		if ( isset( $parts['fragment'] ) ) {
			return __( 'The redirect URI must not contain a fragment.', 'wpelevator-oauth-pilot' );
		}

		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return __( 'The redirect URI must not contain userinfo.', 'wpelevator-oauth-pilot' );
		}

		$scheme = strtolower( $parts['scheme'] );

		if ( in_array( $scheme, self::DENIED_SCHEMES, true ) ) {
			return __( 'The redirect URI scheme is not allowed.', 'wpelevator-oauth-pilot' );
		}

		if ( 'https' === $scheme ) {
			if ( empty( $parts['host'] ) ) {
				return __( 'The redirect URI must include a host.', 'wpelevator-oauth-pilot' );
			}

			return null;
		}

		if ( 'http' === $scheme ) {
			if ( empty( $parts['host'] ) ) {
				return __( 'The redirect URI must include a host.', 'wpelevator-oauth-pilot' );
			}

			if ( ! self::is_loopback_host( $parts['host'] ) ) {
				return __( 'Plain HTTP redirect URIs are only allowed for loopback addresses.', 'wpelevator-oauth-pilot' );
			}

			return null;
		}

		/**
		 * Approve or deny a private-use scheme redirect URI, such as the custom
		 * schemes used by native applications.
		 *
		 * Denied by default: this is the only place a non-HTTPS, non-loopback
		 * callback can enter the system.
		 *
		 * @param bool   $allowed Whether the URI may be registered.
		 * @param string $uri     The full redirect URI.
		 * @param array  $parts   The parsed URI components.
		 */
		$allowed = apply_filters( 'oauth_pilot__redirect_uri_allowed', false, $uri, $parts );

		if ( ! $allowed ) {
			return __( 'The redirect URI scheme is not allowed.', 'wpelevator-oauth-pilot' );
		}

		return null;
	}

	public static function is_loopback_host( string $host ): bool {
		return in_array( strtolower( $host ), self::LOOPBACK_HOSTS, true );
	}

	/**
	 * Whether the URI is a loopback callback, which is how native and CLI agent
	 * clients receive their authorization code.
	 */
	public static function is_loopback( string $uri ): bool {
		$parts = wp_parse_url( $uri );

		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return false;
		}

		return 'http' === strtolower( $parts['scheme'] ) && self::is_loopback_host( $parts['host'] );
	}

	/**
	 * Compare a requested redirect URI against one registered value.
	 *
	 * Exact string comparison, except that RFC 8252 requires the port of a
	 * loopback redirect to be ignored because native clients bind an ephemeral
	 * port. Everything else - scheme, host, path, query - still has to match
	 * exactly, so this never degrades into prefix matching.
	 */
	public static function equals( string $requested, string $registered ): bool {
		if ( hash_equals( $registered, $requested ) ) {
			return true;
		}

		if ( ! self::is_loopback( $requested ) || ! self::is_loopback( $registered ) ) {
			return false;
		}

		return hash_equals( self::without_port( $registered ), self::without_port( $requested ) );
	}

	/**
	 * Find the registered URI matching the request, or null.
	 */
	public static function match( string $requested, array $registered ): ?string {
		foreach ( $registered as $candidate ) {
			if ( self::equals( $requested, (string) $candidate ) ) {
				return (string) $candidate;
			}
		}

		return null;
	}

	private static function without_port( string $uri ): string {
		$parts = wp_parse_url( $uri );

		return sprintf(
			'%s://%s%s%s',
			strtolower( $parts['scheme'] ?? '' ),
			strtolower( $parts['host'] ?? '' ),
			$parts['path'] ?? '',
			isset( $parts['query'] ) ? '?' . $parts['query'] : ''
		);
	}

	/**
	 * The host shown to the user on the consent screen.
	 */
	public static function get_display_host( string $uri ): string {
		$parts = wp_parse_url( $uri );

		if ( ! empty( $parts['host'] ) ) {
			return isset( $parts['port'] )
				? sprintf( '%s:%d', $parts['host'], $parts['port'] )
				: (string) $parts['host'];
		}

		return (string) ( $parts['scheme'] ?? $uri );
	}
}
