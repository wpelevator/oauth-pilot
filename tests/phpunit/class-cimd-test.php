<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Http\Form_Body;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;

require_once __DIR__ . '/class-test-case.php';

/**
 * Client ID Metadata Documents: the MCP 2026-07-28 replacement for dynamic
 * client registration.
 *
 * The metadata document fetch is mocked at the WordPress HTTP layer, so every
 * fetch and validation rule is exercised without network access. Hosts that
 * would need DNS resolution use the oauth_pilot__cimd_resolved_ips filter.
 */
class Cimd_Test extends Test_Case {

	private const METADATA_URL = 'https://client.example.com/oauth/client-metadata.json';

	/**
	 * The number of HTTP requests the current mock served.
	 *
	 * @var int
	 */
	private $http_requests = 0;

	public function tear_down(): void {
		remove_all_filters( 'pre_http_request' );
		remove_all_filters( 'oauth_pilot__cimd_resolved_ips' );
		remove_all_filters( 'oauth_pilot__cimd_enabled' );
		remove_all_filters( 'oauth_pilot__cimd_limits' );
		remove_all_filters( 'oauth_pilot__cimd_url_allowed' );

		parent::tear_down();
	}

	/**
	 * Serve a metadata document from the mocked HTTP layer.
	 *
	 * The host is pinned to a public address so the SSRF guard lets the fetch
	 * through to the mock; tests that need a hostile resolution pass their own
	 * addresses to mock_dns() afterwards.
	 */
	private function mock_metadata_response( array $document, array $headers = [] ): void {
		$this->mock_dns( [ '93.184.216.34' ] );

		$this->http_requests = 0;

		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) use ( $document, $headers ) {
				if ( self::METADATA_URL !== $url ) {
					return $pre;
				}

				++$this->http_requests;

				return [
					'response' => [
						'code' => 200,
						'message' => 'OK',
					],
					'headers' => array_merge( [ 'content-type' => 'application/json' ], $headers ),
					'body' => (string) wp_json_encode( $document ),
				];
			},
			10,
			3
		);
	}

	/**
	 * Make every HTTP request fail, for exercising the stale cache fallback.
	 */
	private function mock_broken_network(): void {
		add_filter(
			'pre_http_request',
			fn () => new \WP_Error( 'http_request_failed', 'Connection refused.' )
		);
	}

	/**
	 * Pretend the metadata host resolves to the given addresses.
	 */
	private function mock_dns( array $ips ): void {
		add_filter(
			'oauth_pilot__cimd_resolved_ips',
			fn () => $ips
		);
	}

	private function get_valid_document(): array {
		return [
			'client_id' => self::METADATA_URL,
			'client_name' => 'Example MCP Client',
			'client_uri' => 'https://client.example.com',
			'redirect_uris' => [ 'https://client.example.com/callback' ],
			'grant_types' => [ 'authorization_code', 'refresh_token' ],
			'response_types' => [ 'code' ],
			'token_endpoint_auth_method' => 'none',
		];
	}

	public function test_url_shaped_client_ids_are_recognized() {
		$cimd = $this->plugin->get_cimd();

		$this->assertTrue(
			$cimd->is_cimd_client_id( self::METADATA_URL ),
			'An HTTPS URL with a path and no fragment is a CIMD client identifier.'
		);

		$this->assertFalse( $cimd->is_cimd_client_id( 'http://client.example.com/metadata.json' ), 'The draft requires the https scheme.' );
		$this->assertFalse( $cimd->is_cimd_client_id( 'https://client.example.com' ), 'A URL without a path cannot name a document.' );
		$this->assertFalse( $cimd->is_cimd_client_id( 'https://client.example.com/metadata.json#fragment' ), 'A fragment is never sent to a server, so it cannot be fetched.' );
		$this->assertFalse( $cimd->is_cimd_client_id( 'https://user:secret@client.example.com/metadata.json' ), 'Userinfo in the URL is rejected.' );
		$this->assertFalse( $cimd->is_cimd_client_id( 'op_' . str_repeat( 'a', 64 ) ), 'Generated client identifiers take the registered client path.' );
		$this->assertFalse( $cimd->is_cimd_client_id( '' ), 'An empty client_id is not CIMD shaped.' );
		$this->assertFalse(
			$cimd->is_cimd_client_id( 'https://client.example.com/' . str_repeat( 'a', 600 ) ),
			'Absurdly long client identifiers are rejected outright.'
		);
	}

	public function test_resolution_fetches_validates_and_persists_the_client() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$this->assertNotNull( $client, 'A valid metadata document must produce a client.' );
		$this->assertTrue( $client->is_cimd(), 'The client row is sourced from CIMD.' );
		$this->assertSame( 'Example MCP Client', $client->get_name(), 'The document client_name is the display name.' );
		$this->assertSame( [ 'https://client.example.com/callback' ], $client->get_redirect_uris(), 'The document redirect URIs are registered exactly.' );
		$this->assertTrue( $client->is_public(), 'A metadata document fetched from a public URL can only yield a public client.' );
		$this->assertSame( self::METADATA_URL, $client->get_metadata_url(), 'The document URL is stored with the client.' );
		$this->assertSame( self::METADATA_URL, $client->get_display_client_id(), 'Humans are shown the URL, the actual trust anchor.' );
		$this->assertSame( $client->get_client_id(), $this->plugin->get_clients()->get_by_metadata_url( self::METADATA_URL )->get_client_id(), 'The client is resolvable by its metadata URL.' );
	}

	public function test_resolution_drops_an_extension_grant_the_server_cannot_run() {
		$document = $this->get_valid_document();

		// The document Claude publishes, which every server it connects to reads.
		$document['grant_types'] = [ 'authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer' ];

		$this->mock_metadata_response( $document );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$this->assertSame(
			[ 'authorization_code', 'refresh_token' ],
			$client->get_grant_types(),
			'A metadata document is published once for every server, so an extension grant this one cannot run is dropped rather than treated as a fatal document error.'
		);

		$this->assertFalse(
			$client->allows_grant( 'urn:ietf:params:oauth:grant-type:jwt-bearer' ),
			'Dropping the grant must not leave the client holding it.'
		);
	}

	public function test_resolution_accepts_live_http_header_dictionary() {
		$this->mock_dns( [ '93.184.216.34' ] );

		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) {
				if ( self::METADATA_URL !== $url ) {
					return $pre;
				}

				return [
					'response' => [
						'code' => 200,
						'message' => 'OK',
					],
					'headers' => new \WpOrg\Requests\Utility\CaseInsensitiveDictionary(
						[
							'content-type' => 'application/json',
							'cache-control' => 'max-age=300',
						]
					),
					'body' => (string) wp_json_encode( $this->get_valid_document() ),
				];
			},
			10,
			3
		);

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		$cache_seconds = strtotime( (string) $client->get_metadata_expires_at() . ' UTC' ) - time();

		$this->assertNotNull( $client, 'A valid live WordPress HTTP response must produce a client.' );
		$this->assertTrue( $client->is_cimd(), 'The live HTTP response headers must be read through the WordPress HTTP API.' );
		$this->assertGreaterThanOrEqual( 295, $cache_seconds, 'The live Cache-Control header must set the client metadata expiry.' );
		$this->assertLessThanOrEqual( 300, $cache_seconds, 'The live Cache-Control header must not exceed its max-age.' );
	}

	public function test_second_resolution_is_served_from_the_cache() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$this->assertSame( 1, $this->http_requests, 'A fresh cached document must not trigger a second fetch.' );
	}

	public function test_document_client_id_must_match_the_fetched_url() {
		$document = $this->get_valid_document();
		$document['client_id'] = 'https://elsewhere.example/metadata.json';

		$this->mock_metadata_response( $document );

		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		} finally {
			$this->assertNull(
				$this->plugin->get_clients()->get_by_metadata_url( self::METADATA_URL ),
				'A document claiming another client_id must not be persisted as client metadata.'
			);
		}
	}

	public function test_document_without_a_client_name_is_rejected() {
		$document = $this->get_valid_document();
		unset( $document['client_name'] );

		$this->mock_metadata_response( $document );

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_document_with_confidential_auth_method_is_rejected() {
		$document = $this->get_valid_document();
		$document['token_endpoint_auth_method'] = 'client_secret_basic';

		$this->mock_metadata_response( $document );

		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		} finally {
			$this->assertNull(
				$this->plugin->get_clients()->get_by_metadata_url( self::METADATA_URL ),
				'A document fetched from a public URL can never vouch for a client secret, so it must not register one.'
			);
		}
	}

	public function test_resolution_accepts_a_document_that_prefers_private_key_jwt_when_it_also_supports_none() {
		$document = $this->get_valid_document();

		// The document ChatGPT publishes, which every server it connects to reads.
		$document['token_endpoint_auth_method'] = 'private_key_jwt';
		$document['token_endpoint_auth_methods_supported'] = [ 'none', 'private_key_jwt' ];
		$document['token_endpoint_auth_signing_alg'] = 'RS256';
		$document['jwks_uri'] = 'https://chatgpt.com/oauth/jwks.json';

		$this->mock_metadata_response( $document );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$this->assertTrue(
			$client->is_public(),
			'A metadata document is published once for every server, so an asymmetric method this one cannot run is dropped when the document also supports none.'
		);

		$this->assertSame(
			Client::AUTH_NONE,
			$client->get_auth_method(),
			'ChatGPT picks none from the intersection with the methods this server advertises, so the stored client must be public.'
		);
	}

	public function test_document_that_only_supports_private_key_jwt_is_rejected() {
		$document = $this->get_valid_document();
		$document['token_endpoint_auth_method'] = 'private_key_jwt';
		$document['jwks_uri'] = 'https://chatgpt.com/oauth/jwks.json';

		$this->mock_metadata_response( $document );

		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		} finally {
			$this->assertNull(
				$this->plugin->get_clients()->get_by_metadata_url( self::METADATA_URL ),
				'A document that cannot authenticate as a public client must not be persisted: this server does not verify private_key_jwt assertions.'
			);
		}
	}

	public function test_document_with_an_invalid_redirect_uri_is_rejected() {
		$document = $this->get_valid_document();
		$document['redirect_uris'] = [ 'not a uri' ];

		$this->mock_metadata_response( $document );

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_non_json_content_type_is_rejected() {
		$this->mock_metadata_response( $this->get_valid_document(), [ 'content-type' => 'text/html' ] );

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_oversized_documents_are_rejected() {
		add_filter(
			'oauth_pilot__cimd_limits',
			fn ( $limits ) => array_merge( (array) $limits, [ 'max_document_bytes' => 10 ] )
		);

		$this->mock_metadata_response( $this->get_valid_document() );

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_private_ip_literal_hosts_are_rejected() {
		// No HTTP mock: the request must be refused before any network I/O.
		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( 'https://192.168.1.10/client-metadata.json' );
		} catch ( OAuth_Error $error ) {
			$this->assertStringContainsString(
				'could not be fetched',
				$error->getMessage(),
				'A metadata URL pointing into a private range must never be fetched.'
			);

			throw $error;
		}
	}

	public function test_hosts_resolving_to_private_addresses_are_rejected() {
		$this->mock_metadata_response( $this->get_valid_document() );
		$this->mock_dns( [ '10.0.0.5' ] );

		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		} finally {
			$this->assertSame( 0, $this->http_requests, 'A host that resolves into a private range must never be contacted.' );
		}
	}

	public function test_cache_ttl_respects_http_cache_headers() {
		$this->mock_metadata_response( $this->get_valid_document(), [ 'cache-control' => 'max-age=172800' ] );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$expires = strtotime( (string) $client->get_metadata_expires_at() . ' UTC' );

		$this->assertGreaterThan(
			time() + 80000,
			$expires,
			'A max-age above the clamp ceiling must be capped, not trusted verbatim, but still cache beyond the default.'
		);

		$this->assertLessThanOrEqual(
			time() + DAY_IN_SECONDS + 5,
			$expires,
			'Cache-Control headers from a hostile server must never cache a document longer than the configured ceiling.'
		);
	}

	/**
	 * There is no stale fallback. Serving expired metadata after a failed
	 * refetch would keep honoring callbacks the origin has since removed,
	 * which is exactly what a client whose domain was reassigned or
	 * compromised needs to be stripped of.
	 */
	public function test_a_failed_refetch_never_serves_expired_metadata() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		global $wpdb;
		$wpdb->update(
			$this->plugin->get_clients()->get_table_name(),
			[
				// Expired seconds ago: even the freshest possible stale
				// document is not good enough to authorize against.
				'metadata_expires_at' => gmdate( 'Y-m-d H:i:s', time() - 10 ),
				'metadata_fetched_at' => gmdate( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS ),
			],
			[ 'id' => $client->get_id() ]
		);

		$this->mock_broken_network();

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_revoked_cimd_clients_stay_revoked() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$this->plugin->get_clients()->revoke( $client );

		$this->expectException( OAuth_Error::class );

		$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
	}

	public function test_disabled_cimd_leaves_url_client_ids_unresolvable() {
		add_filter( 'oauth_pilot__cimd_enabled', '__return_false' );

		$this->mock_metadata_response( $this->get_valid_document() );

		$this->expectException( OAuth_Error::class );

		try {
			$this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		} finally {
			$this->assertSame( 0, $this->http_requests, 'A disabled feature must not fetch anything.' );
		}
	}

	public function test_full_authorization_and_token_flow_with_a_url_client_id() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		$verifier = 'test-verifier-extensions-of-pkce-usage-1234567890';
		$result = $this->complete_authorization( $client, $verifier, [ 'client_id' => self::METADATA_URL ] );

		$this->assertNotEmpty( $result['code'], 'A CIMD client must be able to run the full authorization code flow.' );

		$body = Form_Body::parse(
			http_build_query(
				[
					'grant_type' => 'authorization_code',
					'client_id' => self::METADATA_URL,
					'code' => $result['code'],
					'code_verifier' => $verifier,
					'redirect_uri' => 'https://client.example.com/callback',
				]
			)
		);

		$response = $this->plugin->get_token_service()->handle_token_request( $body, null );

		$this->assertArrayHasKey( 'access_token', $response, 'The token endpoint must accept a URL client identifier resolved from the cache.' );

		$context = $this->plugin->get_validator()->validate_token(
			(string) $response['access_token'],
			$this->get_default_resource_uri()
		);

		$this->assertNotWPError( $context, 'The issued access token must validate.' );
	}

	public function test_discovery_advertises_cimd_support() {
		$metadata = $this->plugin->get_metadata()->get_authorization_server_metadata();

		$this->assertTrue(
			$metadata['client_id_metadata_document_supported'] ?? false,
			'MCP clients pick CIMD over DCR only when the metadata advertises it.'
		);
	}

	public function test_cleanup_deletes_unused_cimd_clients() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );

		global $wpdb;
		$wpdb->update(
			$this->plugin->get_clients()->get_table_name(),
			[ 'created_at' => gmdate( 'Y-m-d H:i:s', time() - ( 2 * DAY_IN_SECONDS ) ) ],
			[ 'id' => $client->get_id() ]
		);

		$deleted = $this->plugin->get_clients()->delete_stale_ephemeral( DAY_IN_SECONDS, 90 * DAY_IN_SECONDS );

		$this->assertSame( 1, $deleted, 'A CIMD client that never completed an authorization must be cleaned up like a dynamic one.' );
	}

	public function test_client_snapshot_carries_the_metadata_url() {
		$this->mock_metadata_response( $this->get_valid_document() );

		$client = $this->plugin->get_cimd()->resolve_for_authorization( self::METADATA_URL );
		$snapshot = $client->to_snapshot();

		$this->assertSame(
			self::METADATA_URL,
			$snapshot['metadata_url'],
			'An in-flight authorization must keep showing the trust anchor even if the client row disappears.'
		);
	}
}
