<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Client\Client;
use WP_REST_Request;

require_once __DIR__ . '/class-test-case.php';

/**
 * Dynamic client registration is in the core feature set because agent clients
 * rely on it for a URL-only setup.
 */
class Client_Registration_Test extends Test_Case {

	/**
	 * The endpoint ships disabled, so every test that exercises it has to turn
	 * it on the way an operator would. test_registration_is_disabled_by_default()
	 * removes this filter again to assert the shipped default.
	 */
	public function set_up() {
		parent::set_up();

		add_filter( 'oauth_pilot__dynamic_registration_enabled', '__return_true' );
	}

	private function register( array $metadata, ?string $content_type = 'application/json' ): \WP_REST_Response {
		$request = new WP_REST_Request( 'POST', '/oauth-pilot/v1/register' );

		if ( isset( $content_type ) ) {
			$request->set_header( 'content-type', $content_type );
		}

		$request->set_body( (string) wp_json_encode( $metadata ) );

		return rest_do_request( $request );
	}

	public function test_registers_a_public_client_and_returns_its_metadata() {
		$response = $this->register(
			[
				'client_name' => 'Claude',
				'redirect_uris' => [ 'https://claude.ai/api/mcp/auth_callback' ],
				'grant_types' => [ 'authorization_code', 'refresh_token' ],
				'response_types' => [ 'code' ],
				'token_endpoint_auth_method' => 'none',
			]
		);

		$this->assertSame( 201, $response->get_status(), 'RFC 7591 registration answers with 201 Created.' );

		$data = $response->get_data();

		$this->assertMatchesRegularExpression( '/^op_[0-9a-f]{64}$/', $data['client_id'], 'The server generates the client identifier.' );
		$this->assertSame( [ 'https://claude.ai/api/mcp/auth_callback' ], $data['redirect_uris'], 'The registered callbacks are echoed back.' );
		$this->assertSame( 'none', $data['token_endpoint_auth_method'], 'Dynamic registration issues public clients only.' );
		$this->assertIsInt( $data['client_id_issued_at'], 'RFC 7591 requires the issue timestamp.' );

		$this->assertArrayNotHasKey(
			'client_secret',
			$data,
			'A dynamically registered client must never receive a secret.'
		);

		$this->assertArrayNotHasKey(
			'registration_access_token',
			$data,
			'Registration management is not implemented, so no management credential may be handed out.'
		);
	}

	public function test_registered_client_can_immediately_authorize() {
		$data = $this->register(
			[
				'client_name' => 'Claude',
				'redirect_uris' => [ 'https://claude.ai/api/mcp/auth_callback' ],
			]
		)->get_data();

		$client = $this->plugin->get_clients()->get_by_client_id( $data['client_id'] );

		$this->assertNotNull( $client, 'The registration must have produced a resolvable client.' );

		$this->assertTrue(
			$client->allows_grant( Client::GRANT_AUTHORIZATION_CODE ),
			'A registration with no explicit grants must still be able to run the code flow.'
		);

		$this->assertTrue(
			$client->allows_grant( Client::GRANT_REFRESH_TOKEN ),
			'Refresh must be available by default or the connection dies after the first hour.'
		);
	}

	public function test_rejects_a_missing_redirect_uri() {
		$response = $this->register( [ 'client_name' => 'No callback' ] );

		$this->assertSame( 400, $response->get_status(), 'A client with nowhere to send the code cannot work.' );
		$this->assertSame( 'invalid_redirect_uri', $response->get_data()['error'], 'RFC 7591 names this error.' );
	}

	public function test_rejects_an_unsafe_redirect_uri() {
		$response = $this->register(
			[
				'client_name' => 'Bad',
				'redirect_uris' => [ 'http://example.com/cb' ],
			]
		);

		$this->assertSame( 'invalid_redirect_uri', $response->get_data()['error'], 'Plain HTTP off loopback must never be registrable.' );
	}

	public function test_rejects_duplicate_redirect_uris() {
		$response = $this->register(
			[
				'client_name' => 'Dup',
				'redirect_uris' => [ 'https://a.example.com/cb', 'https://a.example.com/cb' ],
			]
		);

		$this->assertSame( 'invalid_redirect_uri', $response->get_data()['error'], 'Duplicates are rejected rather than silently collapsed.' );
	}

	public function test_rejects_a_confidential_registration() {
		$response = $this->register(
			[
				'client_name' => 'Wants a secret',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
				'token_endpoint_auth_method' => 'client_secret_basic',
			]
		);

		$this->assertSame(
			'invalid_client_metadata',
			$response->get_data()['error'],
			'Anonymous registration may not mint confidential clients.'
		);
	}

	public function test_drops_a_response_type_it_cannot_run_but_keeps_the_client() {
		$response = $this->register(
			[
				'client_name' => 'OIDC capable',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
				'response_types' => [ 'code', 'id_token' ],
				'token_endpoint_auth_method' => 'none',
			]
		);

		$this->assertSame(
			201,
			$response->get_status(),
			'A client that can also run an OIDC flow lists those response types in the one document it publishes, and must not be refused for it.'
		);

		$this->assertSame(
			[ 'code' ],
			$response->get_data()['response_types'],
			'Only the code response type is ever registered, and the response says so.'
		);
	}

	public function test_rejects_a_client_that_cannot_use_the_code_response_type() {
		$response = $this->register(
			[
				'client_name' => 'Implicit only',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
				'response_types' => [ 'id_token' ],
				'token_endpoint_auth_method' => 'none',
			]
		);

		$this->assertSame(
			'invalid_client_metadata',
			$response->get_data()['error'],
			'A client that cannot use the only response type this server implements would never complete a flow.'
		);
	}

	public function test_rejects_a_client_left_with_no_grant_it_can_run() {
		$response = $this->register(
			[
				'client_name' => 'Implicit',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
				'grant_types' => [ 'implicit' ],
			]
		);

		$this->assertSame(
			'invalid_client_metadata',
			$response->get_data()['error'],
			'A client that asks only for grants this server cannot run would never work, so it is refused rather than registered.'
		);
	}

	public function test_drops_an_extension_grant_but_keeps_the_client() {
		$response = $this->register(
			[
				'client_name' => 'Claude',
				'redirect_uris' => [ 'https://claude.ai/api/mcp/auth_callback' ],
				'grant_types' => [ 'authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer' ],
				'response_types' => [ 'code' ],
				'token_endpoint_auth_method' => 'none',
			]
		);

		$this->assertSame(
			201,
			$response->get_status(),
			'A client whose supported grants are a match must not be refused over an extension grant it also happens to advertise.'
		);

		$this->assertSame(
			[ 'authorization_code', 'refresh_token' ],
			$response->get_data()['grant_types'],
			'RFC 7591 has the server report the grants it actually stored, so the client learns the extension grant was not registered.'
		);
	}

	public function test_rejects_too_many_redirect_uris() {
		$uris = [];

		for ( $index = 0; $index < 11; $index++ ) {
			$uris[] = sprintf( 'https://a%d.example.com/cb', $index );
		}

		$response = $this->register(
			[
				'client_name' => 'Too many',
				'redirect_uris' => $uris,
			]
		);

		$this->assertSame( 'invalid_redirect_uri', $response->get_data()['error'], 'The per client callback limit bounds the stored row.' );
	}

	public function test_rejects_a_non_json_request() {
		$response = $this->register( [ 'client_name' => 'x' ], 'application/x-www-form-urlencoded' );

		$this->assertSame( 415, $response->get_status(), 'The registration endpoint is the only one that takes JSON, and it takes only JSON.' );
	}

	public function test_enforces_the_active_client_quota_exactly() {
		add_filter(
			'oauth_pilot__dynamic_registration_limits',
			function ( array $limits ): array {
				$limits['max_active_clients'] = 1;

				return $limits;
			}
		);

		$first = $this->register(
			[
				'client_name' => 'First',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
			]
		);

		$second = $this->register(
			[
				'client_name' => 'Second',
				'redirect_uris' => [ 'https://b.example.com/cb' ],
			]
		);

		$this->assertSame( 201, $first->get_status(), 'The first registration is within the quota.' );
		$this->assertSame( 429, $second->get_status(), 'The quota is enforced by counting the table, not a best effort counter.' );
	}

	/**
	 * Dynamic client registration is deprecated in favor of Client ID Metadata
	 * Documents, so a new site must not expose an unauthenticated endpoint that
	 * writes rows. The setting stays available for existing connectors.
	 */
	public function test_registration_is_disabled_by_default() {
		remove_filter( 'oauth_pilot__dynamic_registration_enabled', '__return_true' );

		$response = $this->register(
			[
				'client_name' => 'Nope',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
			]
		);

		$this->assertSame( 403, $response->get_status(), 'A fresh install must answer the registration endpoint with 403.' );

		$this->assertFalse(
			$this->plugin->get_settings()->is_dynamic_registration_enabled(),
			'The stored default, not just the endpoint, must be off.'
		);
	}

	public function test_sanitizes_and_bounds_optional_metadata() {
		$response = $this->register(
			[
				'client_name' => '<script>alert(1)</script>Claude',
				'redirect_uris' => [ 'https://a.example.com/cb' ],
				'client_uri' => 'https://claude.ai',
				'contacts' => [ 'ops@example.com', 'not an email' ],
			]
		);

		$data = $response->get_data();

		$this->assertStringNotContainsString(
			'<script>',
			$data['client_name'],
			'Client supplied metadata is rendered on the consent screen and must be sanitized on the way in.'
		);

		$this->assertSame(
			[ 'ops@example.com' ],
			$data['contacts'],
			'Invalid contact addresses are dropped rather than stored.'
		);
	}

	public function test_rejects_an_over_long_metadata_value() {
		$response = $this->register(
			[
				'client_name' => str_repeat( 'a', 1000 ),
				'redirect_uris' => [ 'https://a.example.com/cb' ],
			]
		);

		$this->assertSame( 'invalid_client_metadata', $response->get_data()['error'], 'Every public string has a documented maximum length.' );
	}

	public function test_allow_list_blocks_redirect_hosts_that_are_not_listed() {
		$this->plugin->get_settings()->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai chatgpt.com' ] );

		$response = $this->register(
			[
				'client_name' => 'Impostor',
				'redirect_uris' => [ 'https://evil.example.com/cb' ],
			]
		);

		$this->assertSame( 400, $response->get_status(), 'An unlisted host must not be able to register.' );
		$this->assertSame( 'invalid_redirect_uri', $response->get_data()['error'], 'The allow-list is a redirect URI rule, so RFC 7591 names this error.' );
		$this->assertSame( 0, $this->plugin->get_clients()->count_active_dynamic(), 'A rejected registration must not leave a client behind.' );
	}

	public function test_allow_list_accepts_listed_hosts() {
		$this->plugin->get_settings()->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai, chatgpt.com' ] );

		$response = $this->register(
			[
				'client_name' => 'Claude',
				'redirect_uris' => [ 'https://claude.ai/api/mcp/auth_callback' ],
			]
		);

		$this->assertSame( 201, $response->get_status(), 'A redirect URI on an allow-listed host registers normally.' );
	}

	public function test_allow_list_still_allows_loopback_callbacks() {
		$this->plugin->get_settings()->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai' ] );

		$response = $this->register(
			[
				'client_name' => 'Local CLI',
				'redirect_uris' => [ 'http://127.0.0.1:8911/callback' ],
			]
		);

		$this->assertSame( 201, $response->get_status(), 'Native and CLI agent clients use loopback callbacks, so the web connector allow-list must not block them.' );
	}

	public function test_allow_list_does_not_restrict_administrator_created_clients() {
		$this->plugin->get_settings()->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai' ] );

		$client = $this->plugin->get_client_registration()->register_admin(
			[
				'client_name' => 'Manually added',
				'redirect_uris' => [ 'https://anything.example.com/cb' ],
			],
			1
		);

		$this->assertNotNull( $client, 'The allow-list gates anonymous dynamic registration only, not clients an administrator added by hand.' );
	}
}
