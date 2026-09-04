<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WP_REST_Request;
use WP_REST_Response;
use WPElevator\OAuth_Pilot\Integrations\MCP_Adapter;
use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Token\Token;

require_once __DIR__ . '/class-test-case.php';

/**
 * OAuth Pilot gives MCP Adapter routes exact audiences without taking over the
 * adapter's own transport or ability authorization.
 */
class MCP_Adapter_Integration_Test extends Test_Case {

	private const ROUTE = '/mcp/mcp-adapter-test-server';

	/**
	 * @var callable
	 */
	private $routes_filter;

	private string $resource_uri;

	public function set_up() {
		parent::set_up();

		add_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );

		$this->resource_uri = rest_url( ltrim( self::ROUTE, '/' ) );
		$this->routes_filter = fn(): array => [ self::ROUTE => $this->resource_uri ];

		add_filter( 'oauth_pilot__mcp_adapter_routes', $this->routes_filter );

		$this->plugin->get_resources()->reset();
		wp_set_current_user( 0 );
	}

	public function tear_down() {
		unset( $_SERVER['HTTP_AUTHORIZATION'], $GLOBALS['wp']->query_vars['rest_route'] );

		remove_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );
		remove_filter( 'oauth_pilot__mcp_adapter_routes', $this->routes_filter );

		parent::tear_down();
	}

	private function set_route( string $route ): void {
		$GLOBALS['wp']->query_vars['rest_route'] = $route;
	}

	private function issue_token( int $user_id, string $resource_uri ): string {
		$issued = $this->plugin->get_tokens()->issue(
			[
				'token_type' => Token::TYPE_ACCESS,
				'client_id' => $this->create_public_client()->get_client_id(),
				'user_id' => $user_id,
				'scopes' => [ Plugin::SCOPE_REST ],
				'resource' => $resource_uri,
			]
		);

		return $issued['value'];
	}

	private function discover_routes_from_endpoints( MCP_Adapter $integration, array $endpoints ): array {
		$method = new \ReflectionMethod( $integration, 'get_adapter_routes_from_endpoints' );
		$method->setAccessible( true );

		return $method->invoke( $integration, $endpoints );
	}

	public function test_only_registered_mcp_rest_transport_handlers_are_discovered() {
		$transport = $this->getMockBuilder( \WP\MCP\Transport\Contracts\McpRestTransportInterface::class )
			->disableOriginalConstructor()
			->getMock();
		$lookalike = new class() {
			public function handle_request( WP_REST_Request $request ): WP_REST_Response {
				return new WP_REST_Response();
			}
		};
		$endpoints = [
			self::ROUTE => [
				[
					'callback' => [ $transport, 'handle_request' ],
				],
			],
			'/mcp/not-the-request-handler' => [
				[
					'callback' => [ $transport, 'check_permission' ],
				],
			],
			'/mcp/lookalike' => [
				[
					'callback' => [ $lookalike, 'handle_request' ],
				],
			],
		];

		$this->assertSame(
			[ self::ROUTE => $this->resource_uri ],
			$this->discover_routes_from_endpoints( new MCP_Adapter( $this->plugin->get_settings() ), $endpoints ),
			'Only a handle_request callback owned by an MCP REST transport should identify an adapter endpoint.'
		);
	}

	public function test_adapter_endpoint_is_registered_as_an_exact_oauth_audience() {
		$resource = $this->plugin->get_resources()->get( $this->resource_uri );

		$this->assertNotNull( $resource, 'An MCP Adapter endpoint should receive its own protected resource.' );
		$this->assertSame( [ Plugin::SCOPE_REST ], $resource->get_scopes(), 'The endpoint should share the authentication-only REST scope.' );
		$this->assertSame( [ Plugin::SCOPE_REST ], $resource->get_default_scopes(), 'A client that omits scope should receive the shared REST authentication scope.' );
		$this->assertTrue( $resource->requires_resource(), 'An MCP client must explicitly request a token for the exact adapter server.' );
	}

	public function test_integration_is_inert_until_rest_authentication_is_enabled() {
		remove_filter( 'oauth_pilot__enable_rest_authentication', '__return_true' );
		$this->plugin->get_resources()->reset();

		$this->assertNull(
			$this->plugin->get_resources()->get( $this->resource_uri ),
			'The adapter endpoint should not become an OAuth resource while REST authentication is disabled.'
		);
		$this->assertSame(
			$this->get_default_resource_uri(),
			( new MCP_Adapter( $this->plugin->get_settings() ) )->filter_rest_resource_uri( $this->get_default_resource_uri(), self::ROUTE ),
			'The integration should not alter REST authentication while the shared feature is disabled.'
		);
	}

	public function test_adapter_filter_selects_its_endpoint_resource_only_for_its_route() {
		$integration = new MCP_Adapter( $this->plugin->get_settings() );
		$shared_resource = $this->get_default_resource_uri();

		$this->assertSame(
			$this->resource_uri,
			$integration->filter_rest_resource_uri( $shared_resource, self::ROUTE ),
			'The adapter route should replace the shared REST audience with its canonical endpoint.'
		);
		$this->assertSame(
			$shared_resource,
			$integration->filter_rest_resource_uri( $shared_resource, '/wp/v2/posts' ),
			'Ordinary REST routes should keep using the shared WordPress REST audience.'
		);
	}

	public function test_tokenless_adapter_refusal_advertises_endpoint_metadata() {
		$this->set_route( self::ROUTE );
		$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null );

		$response = $this->plugin->get_rest_authentication()->filter_add_challenge_header(
			new WP_REST_Response( null, 401 ),
			rest_get_server(),
			new WP_REST_Request( 'POST', self::ROUTE )
		);
		$resource = $this->plugin->get_resources()->get( $this->resource_uri );

		$this->assertSame(
			'Bearer resource_metadata="' . $resource->get_metadata_url() . '"',
			$response->get_headers()['WWW-Authenticate'] ?? null,
			'An MCP client should discover metadata whose resource is the exact adapter endpoint.'
		);
	}

	public function test_endpoint_token_establishes_the_user_for_adapter_permissions() {
		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->issue_token( $user_id, $this->resource_uri );
		$this->set_route( self::ROUTE );

		$this->assertTrue(
			$this->plugin->get_rest_authentication()->filter_authenticate_bearer( null ),
			'A token issued to the endpoint should authenticate before the adapter permission callback runs.'
		);
		$this->assertSame( $user_id, get_current_user_id(), 'The adapter should see the WordPress user represented by the token.' );
	}

	public function test_shared_rest_token_cannot_open_an_adapter_endpoint() {
		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->issue_token( $user_id, $this->get_default_resource_uri() );
		$this->set_route( self::ROUTE );

		$result = $this->plugin->get_rest_authentication()->filter_authenticate_bearer( null );

		$this->assertWPError( $result, 'A token for the shared REST audience must not be accepted by an endpoint-specific MCP server.' );
		$this->assertSame( 0, get_current_user_id(), 'A token with the wrong audience must not establish a WordPress user.' );
	}
}
