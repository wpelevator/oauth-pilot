<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Token\Token;
use WP_REST_Request;

require_once __DIR__ . '/class-test-case.php';

/**
 * The end to end path an agent MCP client takes: authorize, consent, exchange
 * the code, refresh, and revoke.
 */
class Authorization_Flow_Test extends Test_Case {

	private function authorize_request( array $params ): \WP_REST_Response {
		$request = new WP_REST_Request( 'GET', '/oauth-pilot/v1/authorize' );
		$request->set_query_params( $params );

		return rest_do_request( $request );
	}

	private function get_authorize_params( Client $client, string $verifier, array $overrides = [] ): array {
		return array_merge(
			[
				'response_type' => 'code',
				'client_id' => $client->get_client_id(),
				'redirect_uri' => $client->get_redirect_uris()[0],
				'state' => 'client-state-value',
				'code_challenge' => PKCE::challenge_for( $verifier ),
				'code_challenge_method' => 'S256',
				'resource' => $this->get_default_resource_uri(),
				'scope' => 'wp:rest',
			],
			$overrides
		);
	}

	public function test_authorize_hands_the_browser_an_opaque_request_id() {
		$client = $this->create_public_client();
		$verifier = Random::credential();

		$response = $this->authorize_request( $this->get_authorize_params( $client, $verifier ) );

		$this->assertSame( 302, $response->get_status(), 'A valid authorization request redirects the browser onward.' );

		$location = $response->get_headers()['Location'];

		$this->assertStringContainsString(
			'action=oauth-pilot-consent',
			$location,
			'The browser is handed to the internal consent controller, not to another protocol endpoint.'
		);

		$query = [];
		parse_str( (string) wp_parse_url( $location, PHP_URL_QUERY ), $query );

		$this->assertNotEmpty( $query['request_id'], 'The consent controller receives an opaque request identifier.' );

		$this->assertStringNotContainsString(
			$client->get_redirect_uris()[0],
			$location,
			'No OAuth parameter may travel through the browser where it could be tampered with.'
		);
	}

	public function test_authorize_returns_a_local_error_for_an_untrusted_redirect_uri() {
		$client = $this->create_public_client();

		$response = $this->authorize_request(
			$this->get_authorize_params( $client, Random::credential(), [ 'redirect_uri' => 'https://attacker.example.com/cb' ] )
		);

		$this->assertSame(
			400,
			$response->get_status(),
			'An unregistered callback must produce a local error, never a redirect to the attacker.'
		);

		$this->assertArrayNotHasKey(
			'Location',
			$response->get_headers(),
			'Nothing may be redirected to a callback that failed validation.'
		);
	}

	public function test_authorize_returns_a_local_error_for_an_unknown_client() {
		$client = $this->create_public_client();

		$response = $this->authorize_request(
			$this->get_authorize_params( $client, Random::credential(), [ 'client_id' => 'op_unknown' ] )
		);

		$this->assertSame( 401, $response->get_status(), 'An unknown client cannot be trusted with a redirect.' );
		$this->assertSame( 'invalid_client', $response->get_data()['error'], 'The error code must be the standard one.' );
	}

	public function test_authorize_redirects_protocol_errors_back_to_the_client() {
		$client = $this->create_public_client();

		$response = $this->authorize_request(
			$this->get_authorize_params( $client, Random::credential(), [ 'code_challenge_method' => 'plain' ] )
		);

		$this->assertSame( 302, $response->get_status(), 'Once the callback is trusted, errors go back to the client.' );

		$query = [];
		parse_str( (string) wp_parse_url( $response->get_headers()['Location'], PHP_URL_QUERY ), $query );

		$this->assertSame( 'invalid_request', $query['error'], 'Downgrading PKCE to plain must be refused.' );
		$this->assertSame( 'client-state-value', $query['state'], 'The client state must be preserved exactly.' );
		$this->assertSame( $this->plugin->get_urls()->get_issuer(), $query['iss'], 'RFC 9207 requires the issuer on error redirects too.' );
	}

	public function test_authorize_rejects_an_unregistered_resource() {
		$client = $this->create_public_client();

		$response = $this->authorize_request(
			$this->get_authorize_params( $client, Random::credential(), [ 'resource' => 'https://example.com/wp-json/other/v1/mcp' ] )
		);

		$query = [];
		parse_str( (string) wp_parse_url( $response->get_headers()['Location'], PHP_URL_QUERY ), $query );

		$this->assertSame(
			'invalid_target',
			$query['error'],
			'A token must never be minted for an audience this server does not know.'
		);
	}

	public function test_full_public_client_flow_with_pkce() {
		$client = $this->create_public_client();
		$verifier = Random::credential();

		$approved = $this->complete_authorization( $client, $verifier );

		$this->assertNotEmpty( $approved['code'], 'Approval must produce an authorization code.' );
		$this->assertSame( 'client-state-value', $approved['state'], 'The state must round trip unchanged.' );
		$this->assertSame( $this->plugin->get_urls()->get_issuer(), $approved['iss'], 'The issuer must identify which server answered.' );

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		);

		$this->assertSame( 200, $response->get_status(), 'A correct code exchange must succeed.' );

		$data = $response->get_data();

		$this->assertNotEmpty( $data['access_token'], 'The exchange must return an access token.' );
		$this->assertSame( 'Bearer', $data['token_type'], 'Only bearer tokens are issued.' );
		$this->assertSame( 'wp:rest', $data['scope'], 'The response must state the exact granted scope set.' );
		$this->assertSame( $this->get_default_resource_uri(), $data['resource'], 'The token audience is reported back for interoperability.' );

		$this->assertNotEmpty(
			$data['refresh_token'],
			'A refresh token must be issued without the client asking for offline_access, or the connection dies in an hour.'
		);

		$this->assertSame(
			'no-store',
			$response->get_headers()['Cache-Control'],
			'A response carrying credentials must never be cached.'
		);
	}

	public function test_code_cannot_be_exchanged_twice_and_reuse_revokes_the_tokens() {
		$client = $this->create_public_client();
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$params = [
			'grant_type' => 'authorization_code',
			'code' => $approved['code'],
			'redirect_uri' => $client->get_redirect_uris()[0],
			'client_id' => $client->get_client_id(),
			'code_verifier' => $verifier,
		];

		$first = $this->post_form( '/oauth-pilot/v1/token', $params );
		$second = $this->post_form( '/oauth-pilot/v1/token', $params );

		$this->assertSame( 200, $first->get_status(), 'The first exchange succeeds.' );
		$this->assertSame( 400, $second->get_status(), 'The second exchange of the same code must fail.' );
		$this->assertSame( 'invalid_grant', $second->get_data()['error'], 'Replaying a code is an invalid grant.' );

		$token = $this->plugin->get_tokens()->get_by_value( $first->get_data()['access_token'], Token::TYPE_ACCESS );

		$this->assertTrue(
			$token->is_revoked(),
			'A replayed code means the code leaked, so everything it produced must be revoked defensively.'
		);
	}

	public function test_token_endpoint_rejects_a_wrong_pkce_verifier() {
		$client = $this->create_public_client();
		$approved = $this->complete_authorization( $client, Random::credential() );

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => Random::credential(),
			]
		);

		$this->assertSame( 400, $response->get_status(), 'Without the verifier the code is worthless to an interceptor.' );
		$this->assertSame( 'invalid_grant', $response->get_data()['error'], 'A failed PKCE check is an invalid grant.' );
	}

	public function test_token_endpoint_rejects_a_mismatched_redirect_uri() {
		$client = $this->create_public_client( [ 'redirect_uris' => [ 'https://a.example.com/cb', 'https://b.example.com/cb' ] ] );
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => 'https://b.example.com/cb',
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		);

		$this->assertSame(
			'invalid_grant',
			$response->get_data()['error'],
			'The redirect URI at the token endpoint must match the one the code was bound to, not merely be registered.'
		);
	}

	public function test_token_endpoint_rejects_another_clients_code() {
		$client = $this->create_public_client();
		$other = $this->create_public_client( [ 'name' => 'Other' ] );
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $other->get_client_id(),
				'code_verifier' => $verifier,
			]
		);

		$this->assertSame(
			'invalid_grant',
			$response->get_data()['error'],
			'A code belongs to the client that requested it.'
		);
	}

	public function test_token_endpoint_rejects_json_bodies() {
		$request = new WP_REST_Request( 'POST', '/oauth-pilot/v1/token' );
		$request->set_header( 'content-type', 'application/json' );
		$request->set_body( (string) wp_json_encode( [ 'grant_type' => 'authorization_code' ] ) );

		$response = rest_do_request( $request );

		$this->assertSame( 415, $response->get_status(), 'The token endpoint accepts form encoded requests only.' );
	}

	public function test_token_endpoint_rejects_repeated_security_parameters() {
		$request = new WP_REST_Request( 'POST', '/oauth-pilot/v1/token' );
		$request->set_header( 'content-type', 'application/x-www-form-urlencoded' );
		$request->set_body( 'grant_type=authorization_code&code=one&code=two' );

		$response = rest_do_request( $request );

		$this->assertSame( 400, $response->get_status(), 'A repeated code parameter is ambiguous and must be refused.' );
		$this->assertSame( 'invalid_request', $response->get_data()['error'], 'Ambiguous requests are invalid requests.' );
	}

	public function test_refresh_rotates_and_detects_reuse() {
		$client = $this->create_public_client();
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$first = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		)->get_data();

		$refreshed = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => $first['refresh_token'],
				'client_id' => $client->get_client_id(),
			]
		);

		$this->assertSame( 200, $refreshed->get_status(), 'Refreshing keeps a connector alive without the user present.' );

		$second = $refreshed->get_data();

		$this->assertNotSame(
			$first['refresh_token'],
			$second['refresh_token'],
			'Every use of a refresh token must rotate it.'
		);

		$reused = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => $first['refresh_token'],
				'client_id' => $client->get_client_id(),
			]
		);

		$this->assertSame( 'invalid_grant', $reused->get_data()['error'], 'Presenting a spent refresh token must fail.' );

		$this->assertTrue(
			$this->plugin->get_tokens()->get_by_value( $second['access_token'], Token::TYPE_ACCESS )->is_revoked(),
			'Reuse means the family leaked, so the tokens issued by the legitimate rotation must be revoked too.'
		);
	}

	public function test_a_scope_this_server_never_registered_is_ignored_end_to_end() {
		$resource_uri = rest_url( 'ignored-scope-test/v1' );
		$read_scope = 'ignored-scope-test:read';

		add_action(
			'oauth_pilot__register_scopes',
			function ( Scopes $scopes ) use ( $read_scope ) {
				$scopes->register( [ 'name' => $read_scope ] );
			}
		);

		add_action(
			'oauth_pilot__register_resources',
			function ( Protected_Resources $resources ) use ( $read_scope, $resource_uri ) {
				$resources->register(
					[
						'uri' => $resource_uri,
						'name' => 'Ignored scope test resource',
						'scopes' => [ $read_scope ],
						'defaults' => [ $read_scope ],
						'requires_resource' => true,
					]
				);
			}
		);
		$this->plugin->get_scopes()->reset();
		$this->plugin->get_resources()->reset();

		$client = $this->create_public_client();
		$verifier = Random::credential();

		// What a client asking for a refresh token sends every server it meets.
		$approved = $this->complete_authorization(
			$client,
			$verifier,
			[
				'resource' => $resource_uri,
				'scope' => $read_scope . ' offline_access',
			]
		);

		$issued = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		)->get_data();

		$this->assertSame(
			$read_scope,
			$issued['scope'],
			'offline_access names nothing on this server, so it is dropped and the token reports the scope that was actually granted.'
		);

		$refreshed = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => $issued['refresh_token'],
				'client_id' => $client->get_client_id(),
				'scope' => $read_scope . ' offline_access',
			]
		);

		$this->assertSame(
			$read_scope,
			$refreshed->get_data()['scope'],
			'A client echoing its original scope string on refresh must not be refused over a scope that was ignored when the grant was made.'
		);
	}

	public function test_refresh_may_narrow_but_not_widen_the_grant() {
		$resource_uri = rest_url( 'scope-test/v1' );
		$read_scope = 'scope-test:read';
		$write_scope = 'scope-test:write';

		add_action(
			'oauth_pilot__register_scopes',
			function ( Scopes $scopes ) use ( $read_scope, $write_scope ) {
				$scopes->register( [ 'name' => $read_scope ] );
				$scopes->register(
					[
						'name' => $write_scope,
						'implies' => [ $read_scope ],
					]
				);
			}
		);

		add_action(
			'oauth_pilot__register_resources',
			function ( Protected_Resources $resources ) use ( $read_scope, $resource_uri, $write_scope ) {
				$resources->register(
					[
						'uri' => $resource_uri,
						'name' => 'Scope test resource',
						'scopes' => [ $read_scope, $write_scope ],
						'defaults' => [ $read_scope ],
						'requires_resource' => true,
					]
				);
			}
		);
		$this->plugin->get_scopes()->reset();
		$this->plugin->get_resources()->reset();

		$client = $this->create_public_client();
		$verifier = Random::credential();
		$approved = $this->complete_authorization(
			$client,
			$verifier,
			[
				'resource' => $resource_uri,
				'scope' => $write_scope,
			]
		);

		$issued = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		)->get_data();

		$narrowed = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => $issued['refresh_token'],
				'client_id' => $client->get_client_id(),
				'scope' => $read_scope,
			]
		);

		$this->assertSame( $read_scope, $narrowed->get_data()['scope'], 'A client may ask for less than it was granted.' );

		$widened = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => $narrowed->get_data()['refresh_token'],
				'client_id' => $client->get_client_id(),
				'scope' => $write_scope,
			]
		);

		$this->assertSame(
			'invalid_scope',
			$widened->get_data()['error'],
			'A refresh must never be able to escalate beyond what the user approved.'
		);
	}

	public function test_confidential_client_authenticates_with_basic_and_post() {
		foreach ( [ Client::AUTH_BASIC, Client::AUTH_POST ] as $method ) {
			$client = $this->create_confidential_client( [ 'token_endpoint_auth_method' => $method ] );
			$secret = (string) $client->get_new_secret();
			$verifier = Random::credential();
			$approved = $this->complete_authorization( $client, $verifier );

			$params = [
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'code_verifier' => $verifier,
			];

			$headers = [];

			if ( Client::AUTH_BASIC === $method ) {
				$headers['authorization'] = 'Basic ' . base64_encode( $client->get_client_id() . ':' . $secret );
			} else {
				$params['client_id'] = $client->get_client_id();
				$params['client_secret'] = $secret;
			}

			$response = $this->post_form( '/oauth-pilot/v1/token', $params, $headers );

			$this->assertSame(
				200,
				$response->get_status(),
				sprintf( 'A confidential client using %s must be able to complete the exchange.', $method )
			);
		}
	}

	public function test_confidential_client_is_rejected_with_a_wrong_secret() {
		$client = $this->create_confidential_client();
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'code_verifier' => $verifier,
			],
			[ 'authorization' => 'Basic ' . base64_encode( $client->get_client_id() . ':wrong' ) ]
		);

		$this->assertSame( 401, $response->get_status(), 'A bad secret must fail client authentication.' );
		$this->assertSame( 'invalid_client', $response->get_data()['error'], 'The standard error code for failed client authentication.' );
	}

	public function test_credentials_in_both_header_and_body_are_refused() {
		$client = $this->create_confidential_client();
		$secret = (string) $client->get_new_secret();

		$response = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'refresh_token',
				'refresh_token' => 'whatever',
				'client_id' => $client->get_client_id(),
				'client_secret' => $secret,
			],
			[ 'authorization' => 'Basic ' . base64_encode( $client->get_client_id() . ':' . $secret ) ]
		);

		$this->assertSame(
			'invalid_request',
			$response->get_data()['error'],
			'Two credential locations in one request is ambiguous and must be refused.'
		);
	}

	public function test_revocation_kills_the_family_and_hides_unknown_tokens() {
		$client = $this->create_public_client();
		$verifier = Random::credential();
		$approved = $this->complete_authorization( $client, $verifier );

		$issued = $this->post_form(
			'/oauth-pilot/v1/token',
			[
				'grant_type' => 'authorization_code',
				'code' => $approved['code'],
				'redirect_uri' => $client->get_redirect_uris()[0],
				'client_id' => $client->get_client_id(),
				'code_verifier' => $verifier,
			]
		)->get_data();

		$response = $this->post_form(
			'/oauth-pilot/v1/revoke',
			[
				'token' => $issued['refresh_token'],
				'client_id' => $client->get_client_id(),
			]
		);

		$this->assertSame( 200, $response->get_status(), 'Revocation succeeded.' );

		$this->assertTrue(
			$this->plugin->get_tokens()->get_by_value( $issued['access_token'], Token::TYPE_ACCESS )->is_revoked(),
			'Revoking a refresh token must take its access tokens with it.'
		);

		$this->assertSame(
			200,
			$this->post_form(
				'/oauth-pilot/v1/revoke',
				[
					'token' => 'not-a-real-token',
					'client_id' => $client->get_client_id(),
				]
			)->get_status(),
			'RFC 7009 requires an unknown token to be answered with success, so revocation cannot be used as an oracle.'
		);
	}
}
