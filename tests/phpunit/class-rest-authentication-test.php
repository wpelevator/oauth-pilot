<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WP_REST_Request;
use WP_REST_Response;

require_once __DIR__ . '/class-test-case.php';

/**
 * The OAuth protocol routes must be immune to WordPress request
 * authentication, and nothing else may be.
 */
class REST_Authentication_Test extends Test_Case {

	public function tear_down() {
		unset( $GLOBALS['wp']->query_vars['rest_route'] );

		parent::tear_down();
	}

	private function set_route( string $route ): void {
		$GLOBALS['wp']->query_vars['rest_route'] = $route;
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
			'An MCP scoped token must not reach the whole REST API until a site opts in.'
		);

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'With the integration off, bearer tokens must not authenticate REST requests.'
		);
	}

	public function test_required_scopes_follow_the_request_method() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$resource = $this->plugin->get_resources()->get( $this->get_default_resource_uri() );

		$_SERVER['REQUEST_METHOD'] = 'GET';

		$this->assertSame(
			[ 'wp:read' ],
			$this->plugin->get_rest_authentication()->get_required_scopes( $resource ),
			'A safe method needs only read access.'
		);

		$_SERVER['REQUEST_METHOD'] = 'POST';

		$this->assertSame(
			[ 'wp:write' ],
			$this->plugin->get_rest_authentication()->get_required_scopes( $resource ),
			'A mutating method needs write access.'
		);

		$_SERVER['REQUEST_METHOD'] = 'GET';
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

	public function test_anonymous_protected_route_advertises_resource_metadata_on_authentication_errors() {
		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$this->set_route( '/wp/v2/users/me' );

		$this->assertNull(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'An anonymous request without a bearer token must continue to WordPress so the route can produce its normal authentication error.'
		);

		$response = $this->plugin->get_rest_authentication()->filter_add_challenge_header(
			new WP_REST_Response( null, 401 ),
			rest_get_server(),
			new WP_REST_Request( 'GET', '/wp/v2/users/me' )
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
}
