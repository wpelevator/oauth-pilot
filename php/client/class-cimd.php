<?php

namespace WPElevator\OAuth_Pilot\Client;

use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Rate_Limiter;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Settings;

/**
 * Client ID Metadata Documents (CIMD).
 *
 * The MCP 2026-07-28 specification deprecates dynamic client registration in
 * favor of Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
 * document): the client_id of an authorization request is an HTTPS URL, and
 * the authorization server fetches a client metadata document from exactly
 * that URL to learn who the client claims to be. The trust anchor is the
 * origin that serves the document, because the authorization code can only
 * ever be delivered to a redirect URI that the same origin published.
 *
 * This class is the only place that fetches attacker-chosen URLs, so every
 * network guard here is load-bearing: private address ranges are rejected,
 * redirects are never followed, and every fetch is rate limited, size capped
 * and cached.
 */
class Cimd {

	private Clients $clients;

	private Registration $registration;

	private Settings $settings;

	private Rate_Limiter $rate_limiter;

	public function __construct( Clients $clients, Registration $registration, Settings $settings, Rate_Limiter $rate_limiter ) {
		$this->clients = $clients;
		$this->registration = $registration;
		$this->settings = $settings;
		$this->rate_limiter = $rate_limiter;
	}

	/**
	 * Whether a client_id is shaped like a Client ID Metadata Document URL.
	 *
	 * The draft requires an HTTPS URL with a path, no fragment and no dot path
	 * segments: the client identifier is compared as a string, so ambiguous URL
	 * normalization is not allowed.
	 */
	public function is_cimd_client_id( string $client_id ): bool {
		if ( '' === $client_id || strlen( $client_id ) > (int) $this->settings->get_cimd_limits()['max_metadata_url_length'] ) {
			return false;
		}

		$parts = wp_parse_url( $client_id );

		if ( ! is_array( $parts ) ) {
			return false;
		}

		$path_segments = explode( '/', (string) ( $parts['path'] ?? '' ) );

		foreach ( $path_segments as $segment ) {
			$decoded_segment = rawurldecode( $segment );

			if ( '.' === $decoded_segment || '..' === $decoded_segment ) {
				return false;
			}
		}

		return 'https' === strtolower( (string) ( $parts['scheme'] ?? '' ) )
			&& ! empty( $parts['host'] )
			&& ! empty( $parts['path'] )
			&& ! isset( $parts['fragment'] )
			&& ! isset( $parts['user'] )
			&& ! isset( $parts['pass'] );
	}

	/**
	 * Resolve a CIMD client from the local cache only.
	 *
	 * Used by the token and revocation endpoints: they must resolve to the same
	 * client row the authorization was created against, so they never trigger
	 * a fetch that could mint a fresh row with a different internal identifier.
	 */
	public function resolve_cached( string $client_id ): ?Client {
		return $this->clients->get_by_metadata_url( $client_id );
	}

	/**
	 * Resolve a CIMD client for an authorization request, fetching and caching
	 * the metadata document when needed.
	 *
	 * @throws OAuth_Error When CIMD is disabled, the document cannot be fetched
	 *                     or validated, or a quota is exhausted.
	 */
	public function resolve_for_authorization( string $client_id ): Client {
		if ( ! $this->settings->is_cimd_enabled() ) {
			throw new OAuth_Error(
				'invalid_client',
				__( 'Unknown or inactive client.', 'wpelevator-oauth-pilot' ),
				401
			);
		}

		$client = $this->clients->get_by_metadata_url( $client_id );

		// An operator revoked client stays revoked, whatever its document says.
		if ( $client && ! $client->is_active() ) {
			throw new OAuth_Error(
				'invalid_client',
				__( 'Unknown or inactive client.', 'wpelevator-oauth-pilot' ),
				401
			);
		}

		if ( $client && ! $this->is_cache_stale( $client ) ) {
			return $client;
		}

		$fetched = $this->fetch_and_validate( $client_id );

		if ( $client ) {
			$this->clients->refresh_metadata( $client, $fetched );

			$refreshed = $this->clients->get_by_metadata_url( $client_id );

			if ( $refreshed ) {
				return $refreshed;
			}

			throw new OAuth_Error(
				'server_error',
				__( 'The client could not be stored.', 'wpelevator-oauth-pilot' ),
				500
			);
		}

		$limits = $this->settings->get_cimd_limits();

		if ( $this->clients->count_active_cimd() >= (int) $limits['max_active_clients'] ) {
			Security_Events::record( 'cimd_quota_exceeded', [ 'limit' => 'max_active_clients' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'This site has reached its client limit.', 'wpelevator-oauth-pilot' ),
				429
			);
		}

		$new_client = $this->clients->create(
			[
				'name' => $fetched['name'],
				'client_type' => Client::TYPE_PUBLIC,
				'token_endpoint_auth_method' => Client::AUTH_NONE,
				'redirect_uris' => $fetched['redirect_uris'],
				'grant_types' => $fetched['grant_types'],
				'scopes' => [],
				'source' => Client::SOURCE_CIMD,
				'metadata' => $fetched['metadata'],
				'metadata_url' => $client_id,
				'metadata_fetched_at' => current_time( 'mysql', true ),
				'metadata_expires_at' => gmdate( 'Y-m-d H:i:s', time() + $fetched['cache_ttl'] ),
			]
		);

		if ( ! $new_client ) {
			throw new OAuth_Error(
				'server_error',
				__( 'The client could not be stored.', 'wpelevator-oauth-pilot' ),
				500
			);
		}

		// The registration event fired by Clients::create() carries the
		// internal identifier only; the URL never needs to be re-derivable.
		return $new_client;
	}

	/**
	 * Fetch the metadata document from the client_id URL and validate it.
	 *
	 * @throws OAuth_Error On any fetch or validation failure.
	 *
	 * @return array Normalized client creation arguments.
	 */
	public function fetch_and_validate( string $client_id ): array {
		$limits = $this->settings->get_cimd_limits();

		$this->assert_within_quotas( $client_id, $limits );

		$response = $this->fetch( $client_id, $limits );

		$body = (string) wp_remote_retrieve_body( $response );
		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 !== $code ) {
			$this->fail_fetch( $client_id, 'http_' . $code );
		}

		if ( strlen( $body ) > (int) $limits['max_document_bytes'] ) {
			$this->fail_fetch( $client_id, 'document_too_large' );
		}

		$content_type = (string) wp_remote_retrieve_header( $response, 'content-type' );

		if ( '' === $content_type || 0 !== stripos( trim( $content_type ), 'application/json' ) ) {
			$this->fail_fetch( $client_id, 'content_type' );
		}

		$document = json_decode( $body, true );

		if ( ! is_array( $document ) ) {
			$this->fail_fetch( $client_id, 'invalid_json' );
		}

		// The document must name itself: a document that claims another
		// client_id is never accepted as that client's metadata.
		$documented_id = (string) ( $document['client_id'] ?? '' );

		if ( '' === $documented_id || ! hash_equals( $documented_id, $client_id ) ) {
			$this->fail_fetch( $client_id, 'client_id_mismatch' );
		}

		$client_name = $document['client_name'] ?? '';

		if ( ! is_string( $client_name ) || '' === trim( $client_name ) ) {
			$this->fail_fetch( $client_id, 'missing_client_name' );
		}

		$auth_method = $document['token_endpoint_auth_method'] ?? Client::AUTH_NONE;

		if ( Client::AUTH_NONE !== $auth_method ) {
			// The document is fetched from a public URL, so it cannot carry a
			// shared secret, and this server supports no asymmetric client
			// authentication. Every CIMD client is a public client.
			$this->fail_fetch( $client_id, 'unsupported_auth_method' );
		}

		$normalized = $this->registration->normalize( $document, $this->get_normalize_limits( $limits ) );

		if ( Client::AUTH_NONE !== $normalized['token_endpoint_auth_method'] ) {
			$this->fail_fetch( $client_id, 'unsupported_auth_method' );
		}

		return [
			'name' => $normalized['client_name'],
			'redirect_uris' => $normalized['redirect_uris'],
			'grant_types' => $normalized['grant_types'],
			'metadata' => $normalized['metadata'],
			'cache_ttl' => $this->get_cache_ttl( $response, $limits ),
		];
	}

	/**
	 * Perform the HTTP fetch with every network guard applied.
	 *
	 * @throws OAuth_Error When the URL is not allowed or the request failed.
	 */
	private function fetch( string $url, array $limits ) {
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			$this->fail_fetch( $url, 'invalid_url' );
		}

		/**
		 * Explicitly allow a metadata document URL that would otherwise be
		 * rejected. Intended for development and test fixtures, where the site
		 * fetches its own URL or a mocked host. Production must leave this
		 * returning false.
		 *
		 * @param bool   $allowed Whether the URL bypasses the network checks.
		 * @param string $url     The metadata document URL.
		 * @param array  $parts   The parsed URL parts.
		 */
		$allowed = (bool) apply_filters( 'oauth_pilot__cimd_url_allowed', false, $url, $parts );

		if ( ! $allowed && ! $this->is_publicly_routable( $parts ) ) {
			$this->fail_fetch( $url, 'private_host' );
		}

		$args = [
			'timeout' => (int) $limits['fetch_timeout_seconds'],
			// Read one byte beyond the limit so a response exactly at the cap can
			// be distinguished from a response WordPress truncated at the cap.
			'limit_response_size' => (int) $limits['max_document_bytes'] + 1,
			// Redirects are never followed: the trust anchor is the origin of the
			// client_id URL, not wherever it might point next.
			'redirection' => 0,
			'headers' => [ 'Accept' => 'application/json' ],
		];

		// The explicit development escape hatch must also bypass core's unsafe
		// URL check. Production fetches use both the stricter checks above and
		// WordPress's transport-adjacent SSRF validation as defense in depth.
		$response = $allowed
			? wp_remote_get( $url, $args )
			: wp_safe_remote_get( $url, $args );

		if ( is_wp_error( $response ) ) {
			$this->fail_fetch( $url, 'request_failed' );
		}

		return $response;
	}

	/**
	 * Whether the URL host is public and reachable, which is what keeps the
	 * server from being used to probe internal networks.
	 */
	private function is_publicly_routable( array $parts ): bool {
		$host = strtolower( (string) $parts['host'] );

		if ( '' === $host ) {
			return false;
		}

		// An IP literal needs no resolution.
		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return $this->is_public_ip( $host );
		}

		if ( '' === $host
			|| substr( $host, -6 ) === '.local'
			|| false === filter_var( $host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
			return false;
		}

		$ips = $this->resolve_host( $host );

		if ( empty( $ips ) ) {
			return false;
		}

		foreach ( $ips as $ip ) {
			if ( ! $this->is_public_ip( (string) $ip ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * The resolved addresses for a host.
	 *
	 * @return string[] IP addresses, or an empty array when resolution failed.
	 */
	private function resolve_host( string $host ): array {
		/**
		 * Override DNS resolution for a metadata document host.
		 *
		 * Return an array of IP addresses to use instead of resolving the
		 * host. The returned addresses still go through the public range
		 * check. Return null to use normal resolution.
		 *
		 * @param array|null $ips  The addresses, or null to resolve normally.
		 * @param string     $host The host being resolved.
		 */
		$ips = apply_filters( 'oauth_pilot__cimd_resolved_ips', null, $host );

		if ( is_array( $ips ) ) {
			return array_values( array_filter( array_map( 'strval', $ips ) ) );
		}

		$ip = gethostbyname( $host );

		// gethostbyname returns the hostname unchanged on failure.
		if ( ! is_string( $ip ) || $ip === $host || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return [];
		}

		$resolved = [ $ip ];

		// Best effort IPv6: a dual homed host must not sneak a private
		// address past the check through its AAAA record.
		if ( function_exists( 'dns_get_record' ) ) {
			$aaaa = @dns_get_record( $host, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best effort lookup, resolver warnings are expected and the failure path is handled below.

			foreach ( (array) $aaaa as $record ) {
				if ( ! empty( $record['ipv6'] ) ) {
					$resolved[] = (string) $record['ipv6'];
				}
			}
		}

		return array_values( array_unique( $resolved ) );
	}

	private function is_public_ip( string $ip ): bool {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * @throws OAuth_Error When a quota is exhausted.
	 */
	private function assert_within_quotas( string $url, array $limits ): void {
		$ip_hash = Security_Events::get_ip_hash();

		if ( '' !== $ip_hash && ! $this->rate_limiter->attempt( 'cimd_ip_' . $ip_hash, (int) $limits['per_ip_per_hour'], HOUR_IN_SECONDS ) ) {
			Security_Events::record( 'cimd_rate_limited', [ 'limit' => 'per_ip_per_hour' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'Too many client metadata fetches. Try again later.', 'wpelevator-oauth-pilot' ),
				429
			);
		}

		$host = strtolower( (string) ( wp_parse_url( $url, PHP_URL_HOST ) ?? '' ) );

		if ( '' !== $host && ! $this->rate_limiter->attempt( 'cimd_host_' . Random::hash( $host ), (int) $limits['per_host_per_hour'], HOUR_IN_SECONDS ) ) {
			Security_Events::record( 'cimd_rate_limited', [ 'limit' => 'per_host_per_hour' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'Too many client metadata fetches. Try again later.', 'wpelevator-oauth-pilot' ),
				429
			);
		}

		if ( ! $this->rate_limiter->attempt( 'cimd_site', (int) $limits['per_site_per_hour'], HOUR_IN_SECONDS ) ) {
			Security_Events::record( 'cimd_rate_limited', [ 'limit' => 'per_site_per_hour' ] );

			throw new OAuth_Error(
				'invalid_request',
				__( 'Too many client metadata fetches. Try again later.', 'wpelevator-oauth-pilot' ),
				429
			);
		}
	}

	/**
	 * How long a cached document stays fresh, from HTTP cache headers clamped
	 * to configured bounds, so a hostile document can neither pin itself in
	 * cache forever nor force a refetch on every request.
	 *
	 * @return int Seconds.
	 */
	private function get_cache_ttl( $response, array $limits ): int {
		$cache_control = (string) wp_remote_retrieve_header( $response, 'cache-control' );

		$ttl = 0;

		if ( preg_match( '/s-maxage\s*=\s*(\d+)/i', $cache_control, $matches ) || preg_match( '/max-age\s*=\s*(\d+)/i', $cache_control, $matches ) ) {
			$ttl = (int) $matches[1];
		} else {
			$expires = (string) wp_remote_retrieve_header( $response, 'expires' );

			if ( '' !== $expires ) {
				$parsed = strtotime( $expires );

				if ( false !== $parsed ) {
					$ttl = $parsed - time();
				}
			}
		}

		return max(
			(int) $limits['cache_min_seconds'],
			min( (int) $limits['cache_max_seconds'], $ttl > 0 ? $ttl : (int) $limits['cache_default_seconds'] )
		);
	}

	private function is_cache_stale( Client $client ): bool {
		$expires_at = $client->get_metadata_expires_at();

		if ( null === $expires_at ) {
			return true;
		}

		$parsed = strtotime( $expires_at . ' UTC' );

		if ( false === $parsed ) {
			return true;
		}

		return $parsed <= time();
	}

	/**
	 * @throws OAuth_Error Always, with a normalized failure reason recorded.
	 */
	private function fail_fetch( string $url, string $reason ): void {
		$host = (string) ( wp_parse_url( $url, PHP_URL_HOST ) ?? '' );

		Security_Events::record(
			'cimd_fetch_failed',
			[
				'reason' => $reason,
				'host' => $host,
			]
		);

		throw new OAuth_Error(
			'invalid_client',
			__( 'The client metadata document could not be fetched or is invalid.', 'wpelevator-oauth-pilot' ),
			401
		);
	}

	/**
	 * The limits array Registration::normalize() validates against.
	 */
	private function get_normalize_limits( array $limits ): array {
		return [
			'max_redirect_uris' => $limits['max_redirect_uris'],
			'max_string_length' => $limits['max_string_length'],
			'max_contacts' => $limits['max_contacts'],
		];
	}
}
