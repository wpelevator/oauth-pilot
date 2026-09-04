<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WP_REST_Request;
use WP_REST_Response;
use WPElevator\OAuth_Pilot\Token\Token;

require_once __DIR__ . '/class-test-case.php';

/**
 * The OAuth protocol routes must be immune to WordPress request
 * authentication, and nothing else may be.
 */
class REST_Authentication_Test extends Test_Case {

	public function tear_down() {
		unset( $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REQUEST_METHOD'], $GLOBALS['wp']->query_vars['rest_route'] );

		parent::tear_down();
	}

	private function set_route( string $route ): void {
		$GLOBALS['wp']->query_vars['rest_route'] = $route;
	}

	private function issue_rest_token( int $user_id, array $scopes ): string {
		$issued = $this->plugin->get_tokens()->issue(
			[
				'token_type' => Token::TYPE_ACCESS,
				'client_id' => $this->create_public_client()->get_client_id(),
				'user_id' => $user_id,
				'scopes' => $scopes,
				'resource' => $this->get_default_resource_uri(),
			]
		);

		return $issued['value'];
	}

	/**
	 * @dataProvider data_protocol_routes
	 */
	public function test_recognizes_the_protocol_routes( string $route, bool $expected, string $reason ) {
		$this->assertSame(
			$expected,
			$this->plugin->get_rest_authentication()->is_protocol_route( $route ),
			$reason
		);
	}

	public function data_protocol_routes(): array {
		return [
			[ '/oauth-pilot/v1/authorize', true, 'The authorization endpoint is an anonymous protocol route.' ],
			[ '/oauth-pilot/v1/token', true, 'The token endpoint performs its own client authentication.' ],
			[ '/oauth-pilot/v1/register', true, 'Dynamic registration is unauthenticated by design.' ],
			[ '/oauth-pilot/v1/revoke', true, 'Revocation authenticates the client itself.' ],
			[ '/oauth-pilot/v1/authorize/', true, 'A trailing slash is the same route.' ],
			[ '/wp/v2/posts', false, 'Ordinary REST routes must keep normal WordPress authentication.' ],
			[ '/oauth-pilot/v1/something-else', false, 'Only the four advertised endpoints are isolated.' ],
			[ '', false, 'An empty route is not a protocol route.' ],
		];
	}

	public function test_protocol_routes_are_dispatched_anonymously() {
		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		wp_set_current_user( $user_id );

		$this->set_route( '/oauth-pilot/v1/token' );

		$this->assertTrue(
			$this->plugin->get_rest_authentication()->filter_isolate_protocol_routes( null ),
			'Returning true short circuits the cookie nonce check that would otherwise reject an agent client request.'
		);

		$this->assertSame(
			0,
			get_current_user_id(),
			'A logged in cookie must not leak a WordPress user into a protocol request.'
		);
	}

	public function test_other_routes_keep_their_authentication_result() {
		$this->set_route( '/wp/v2/posts' );

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_isolate_protocol_routes( null ),
			'The isolation must be scoped to the OAuth routes and nothing else.'
		);
	}

	public function test_application_passwords_are_disabled_only_on_protocol_routes() {
		$this->set_route( '/oauth-pilot/v1/token' );

		$this->assertFalse(
			$this->plugin->get_rest_authentication()->filter_application_passwords_available( true ),
			'Application Passwords read HTTP Basic credentials, which collide with client_secret_basic.'
		);

		$this->set_route( '/wp/v2/posts' );

		$this->assertTrue(
			$this->plugin->get_rest_authentication()->filter_application_passwords_available( true ),
			'Application Passwords must keep working everywhere else.'
		);
	}

	public function test_rest_bearer_authentication_is_off_by_default() {
		$this->assertFalse(
			$this->plugin->get_settings()->is_rest_authentication_enabled(),
			'A REST access token must not reach the whole REST API until a site opts in.'
		);

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'With the integration off, bearer tokens must not authenticate REST requests.'
		);
	}

	public function test_rest_resource_uses_one_authentication_scope() {
		$resource = $this->plugin->get_resources()->get( $this->get_default_resource_uri() );

		$this->assertSame(
			[ 'wp:rest' ],
			$resource->get_scopes(),
			'The generic REST audience should express authentication without pretending to classify endpoint permissions.'
		);
		$this->assertSame(
			[ 'wp:rest' ],
			$resource->get_default_scopes(),
			'A client that omits scope should receive the authentication scope needed to connect.'
		);
	}

	public function test_existing_authentication_is_never_overridden() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		wp_set_current_user( self::factory()->user->create() );

		$this->set_route( '/wp/v2/posts' );

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'A request already authenticated as a WordPress user must be left alone.'
		);
	}

	public function test_bearer_authentication_is_agnostic_to_the_rest_route_owner() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->issue_rest_token( $user_id, [ 'wp:rest' ] );
		$this->set_route( '/third-party/v1/endpoint' );

		$this->assertTrue(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'A valid token should authenticate a REST route without OAuth Pilot knowing which plugin registered it.'
		);
		$this->assertSame(
			$user_id,
			get_current_user_id(),
			'The route permission callback should see the WordPress user represented by the token.'
		);
	}

	public function test_anonymous_protected_route_advertises_resource_metadata_on_authentication_errors() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$this->set_route( '/third-party/v1/endpoint' );

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'An anonymous request without a bearer token must continue to WordPress so the route can produce its normal authentication error.'
		);

		$response = $this->plugin->get_rest_authentication()->filter_add_challenge_header(
			new WP_REST_Response( null, 401 ),
			rest_get_server(),
			new WP_REST_Request( 'GET', '/third-party/v1/endpoint' )
		);
		$headers = $response->get_headers();
		$resource = $this->plugin->get_resources()->get( $this->get_default_resource_uri() );

		$this->assertSame(
			'Bearer resource_metadata="' . $resource->get_metadata_url() . '"',
			$headers['WWW-Authenticate'] ?? null,
			'The bearer challenge must tell an OAuth client where to discover the protected resource metadata.'
		);
		$this->assertSame(
			'WWW-Authenticate',
			$headers['Access-Control-Expose-Headers'] ?? null,
			'Browser clients must be allowed to read the bearer challenge.'
		);
	}

	public function test_anonymous_protected_route_does_not_add_a_challenge_to_successful_responses() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$this->set_route( '/wp/v2/posts' );
		$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null );

		$response = $this->plugin->get_rest_authentication()->filter_add_challenge_header(
			new WP_REST_Response( [], 200 ),
			rest_get_server(),
			new WP_REST_Request( 'GET', '/wp/v2/posts' )
		);

		$this->assertArrayNotHasKey(
			'WWW-Authenticate',
			$response->get_headers(),
			'A public response must not be presented as an OAuth authentication failure.'
		);
	}

	public function test_a_challenge_is_not_reused_after_rest_authentication_is_disabled() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$this->set_route( '/third-party/v1/endpoint' );
		$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null );

		remove_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );
		$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null );

		$response = $this->plugin->get_rest_authentication()->filter_add_challenge_header(
			new WP_REST_Response( null, 401 ),
			rest_get_server(),
			new WP_REST_Request( 'GET', '/third-party/v1/endpoint' )
		);

		$this->assertArrayNotHasKey(
			'WWW-Authenticate',
			$response->get_headers(),
			'The generic OAuth challenge must be advertised only while REST API authentication is enabled.'
		);
	}
}
