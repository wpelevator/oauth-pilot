<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Canonical issuer and endpoint URLs.
 *
 * Every URL this server publishes is built here, from configured WordPress
 * URLs or an explicit filter, and never from request headers.
 */
class Server_Urls {

	public const REST_NAMESPACE = 'oauth-pilot/v1';

	public const WELL_KNOWN_AUTHORIZATION_SERVER = '.well-known/oauth-authorization-server';

	public const WELL_KNOWN_PROTECTED_RESOURCE = '.well-known/oauth-protected-resource';

	public const CONSENT_ACTION = 'oauth-pilot-consent';

	public const ENDPOINTS = [ 'authorize', 'token', 'register', 'revoke' ];

	/**
	 * The canonical issuer identifier: an absolute URL with no trailing slash.
	 */
	public function get_issuer(): string {
		/**
		 * Override the canonical issuer.
		 *
		 * Required when WordPress runs behind a reverse proxy that terminates
		 * TLS, or when the authorization server is published on a dedicated
		 * hostname.
		 *
		 * @param string $issuer The issuer derived from the site URL.
		 */
		$issuer = (string) apply_filters( 'oauth_pilot__issuer', home_url() );

		return $this->normalize_url( $issuer );
	}

	/**
	 * The path component of the issuer, without a trailing slash.
	 *
	 * An empty string means WordPress is installed at the root of its host,
	 * so its own rewrite rules can serve the well-known documents without
	 * extra server configuration. RFC 8414 itself supports path-based
	 * issuers; the root install matters because WordPress rewrites only
	 * apply inside the install directory.
	 */
	public function get_issuer_path(): string {
		$path = (string) ( wp_parse_url( $this->get_issuer(), PHP_URL_PATH ) ?? '' );

		return rtrim( $path, '/' );
	}

	public function is_root_issuer(): bool {
		return '' === $this->get_issuer_path();
	}

	/**
	 * The issuer with its path stripped, which is where the well-known
	 * documents have to be served from.
	 */
	public function get_issuer_origin(): string {
		$parts = wp_parse_url( $this->get_issuer() );

		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return $this->get_issuer();
		}

		return sprintf(
			'%s://%s%s',
			$parts['scheme'],
			$parts['host'],
			isset( $parts['port'] ) ? ':' . $parts['port'] : ''
		);
	}

	/**
	 * An advertised OAuth protocol endpoint.
	 */
	public function get_endpoint_url( string $endpoint ): string {
		if ( ! in_array( $endpoint, self::ENDPOINTS, true ) ) {
			return '';
		}

		$url = rest_url( self::REST_NAMESPACE . '/' . $endpoint );

		/**
		 * Override a generated protocol endpoint URL.
		 *
		 * @param string $url      The generated URL.
		 * @param string $endpoint One of authorize, token, register, revoke.
		 */
		return (string) apply_filters( 'oauth_pilot__endpoint_url', $url, $endpoint );
	}

	public function get_authorization_server_metadata_url(): string {
		$url = sprintf( '%s/%s', $this->get_issuer_origin(), self::WELL_KNOWN_AUTHORIZATION_SERVER );

		if ( ! $this->is_root_issuer() ) {
			// RFC 8414 appends the issuer path after the well-known segment.
			$url .= $this->get_issuer_path();
		}

		return $url;
	}

	/**
	 * The RFC 9728 metadata URL for a resource: the well-known segment is
	 * inserted between the host and the resource path.
	 */
	public function get_protected_resource_metadata_url( string $resource_uri ): string {
		$path = $this->get_resource_path( $resource_uri );

		return sprintf(
			'%s/%s%s',
			$this->get_issuer_origin(),
			self::WELL_KNOWN_PROTECTED_RESOURCE,
			'' === $path ? '' : '/' . $path
		);
	}

	/**
	 * The path that identifies a resource, without a leading or trailing slash.
	 *
	 * With plain permalinks a REST route lives in the rest_route query
	 * parameter rather than in the URL path, which would make every resource
	 * on the site collapse onto /index.php. Folding that parameter into the
	 * path keeps resources distinguishable for both metadata routing and
	 * request matching.
	 */
	public function get_resource_path( string $uri ): string {
		$parts = wp_parse_url( $uri );
		$path = trim( (string) ( $parts['path'] ?? '' ), '/' );

		if ( ! empty( $parts['query'] ) ) {
			$query = [];

			parse_str( (string) $parts['query'], $query );

			if ( ! empty( $query['rest_route'] ) ) {
				$route = trim( (string) $query['rest_route'], '/' );

				$path = '' === $route ? $path : trim( $path . '/' . $route, '/' );
			}
		}

		return $path;
	}

	/**
	 * The internal login and consent controller. Never advertised as an OAuth
	 * endpoint, and the only step of the flow that reads a WordPress cookie.
	 */
	public function get_consent_url( string $request_id ): string {
		return add_query_arg(
			[
				'action' => self::CONSENT_ACTION,
				'request_id' => rawurlencode( $request_id ),
			],
			wp_login_url()
		);
	}

	/**
	 * Whether HTTPS is required for issuer, endpoints and non-loopback
	 * redirects. Only an explicit local development exception turns this off.
	 */
	public function is_https_required(): bool {
		$required = ! in_array( wp_get_environment_type(), [ 'local', 'development' ], true );

		/**
		 * Permit an explicit local development exception to the HTTPS
		 * requirement. Production must leave this true.
		 *
		 * @param bool $required Whether HTTPS is required.
		 */
		return (bool) apply_filters( 'oauth_pilot__https_required', $required );
	}

	public function is_https_issuer(): bool {
		return 'https' === strtolower( (string) wp_parse_url( $this->get_issuer(), PHP_URL_SCHEME ) );
	}

	/**
	 * Canonicalize a URL for storage and comparison: lowercase scheme and host,
	 * no default port, no fragment, no trailing slash.
	 */
	public function normalize_url( string $url ): string {
		$parts = wp_parse_url( trim( $url ) );

		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return rtrim( trim( $url ), '/' );
		}

		$scheme = strtolower( $parts['scheme'] );
		$host = strtolower( $parts['host'] );
		$port = '';

		if ( isset( $parts['port'] ) ) {
			$is_default_port = ( 'https' === $scheme && 443 === (int) $parts['port'] )
				|| ( 'http' === $scheme && 80 === (int) $parts['port'] );

			if ( ! $is_default_port ) {
				$port = ':' . (int) $parts['port'];
			}
		}

		return sprintf(
			'%s://%s%s%s%s',
			$scheme,
			$host,
			$port,
			rtrim( (string) ( $parts['path'] ?? '' ), '/' ),
			isset( $parts['query'] ) ? '?' . $parts['query'] : ''
		);
	}
}
