<?php

namespace WPElevator\OAuth_Pilot\Integrations;

use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Settings;

/**
 * Gives official MCP Adapter HTTP servers exact OAuth audiences.
 *
 * OAuth Pilot's REST authentication already does the credential work the
 * adapter needs: it establishes the represented WordPress user before the
 * adapter runs its transport and ability permission callbacks. MCP additionally
 * requires the server's canonical endpoint to be the token audience, so this
 * integration registers every adapter server as a protected resource and
 * selects it for requests to that route.
 */
class MCP_Adapter {

	private Settings $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	public function init(): void {
		add_action( 'oauth_pilot__register_resources', [ $this, 'action_register_resources' ] );
		add_filter( 'oauth_pilot__rest_authentication_resource_uri', [ $this, 'filter_rest_resource_uri' ], 10, 2 );
	}

	/**
	 * Register each MCP Adapter server with the shared REST authentication scope.
	 */
	public function action_register_resources( Protected_Resources $resources ): void {
		if ( ! $this->settings->is_rest_authentication_enabled() ) {
			return;
		}

		foreach ( $this->get_server_routes() as $route => $uri ) {
			$resources->register(
				[
					'uri' => $uri,
					'name' => sprintf(
						/* translators: %s: the MCP Adapter server route. */
						__( 'MCP Adapter server: %s', 'wpelevator-oauth-pilot' ),
						$route
					),
					'scopes' => [ Plugin::SCOPE_REST ],
					'defaults' => [ Plugin::SCOPE_REST ],
					'requires_resource' => true,
				]
			);
		}
	}

	/**
	 * Select an endpoint-specific audience for an MCP Adapter REST route.
	 */
	public function filter_rest_resource_uri( string $resource_uri, string $route ): string {
		if ( ! $this->settings->is_rest_authentication_enabled() ) {
			return $resource_uri;
		}

		$route = '/' . trim( $route, '/' );

		return $this->get_server_routes()[ $route ] ?? $resource_uri;
	}

	/**
	 * Every registered REST route handled by an MCP Adapter transport.
	 *
	 * @return array<string, string> REST route to canonical resource URI.
	 */
	public function get_server_routes(): array {
		$routes = $this->get_adapter_routes();

		/**
		 * Filter MCP Adapter routes that receive endpoint-specific OAuth resources.
		 *
		 * @param array<string, string> $routes REST route to resource URI.
		 */
		$routes = (array) apply_filters( 'oauth_pilot__mcp_adapter_routes', $routes );
		$validated = [];

		foreach ( $routes as $route => $uri ) {
			if ( is_string( $route ) && is_string( $uri ) && '' !== trim( $route, '/' ) && '' !== trim( $uri ) ) {
				$validated[ '/' . trim( $route, '/' ) ] = $uri;
			}
		}

		return $validated;
	}

	/**
	 * Discover the routes owned by active MCP Adapter REST transports.
	 *
	 * Building the public REST server lets MCP Adapter initialize at its normal
	 * rest_api_init priorities. Inspecting the resulting callbacks excludes
	 * servers that only expose non-HTTP transports and avoids calling adapter
	 * internals or inferring ownership from route names.
	 *
	 * @return array<string, string>
	 */
	private function get_adapter_routes(): array {
		if ( ! did_action( 'wp_mcp_init' ) || ! interface_exists( 'WP\MCP\Transport\Contracts\McpRestTransportInterface' ) ) {
			return [];
		}

		return $this->get_adapter_routes_from_endpoints( rest_get_server()->get_routes() );
	}

	/**
	 * Find MCP Adapter request handlers in the WordPress REST endpoint table.
	 *
	 * @param array<string, array> $endpoints Registered REST endpoints by route.
	 *
	 * @return array<string, string>
	 */
	private function get_adapter_routes_from_endpoints( array $endpoints ): array {
		$routes = [];

		foreach ( $endpoints as $route => $handlers ) {
			if ( is_string( $route ) && is_array( $handlers ) && $this->has_adapter_request_handler( $handlers ) ) {
				$routes[ $route ] = rest_url( ltrim( $route, '/' ) );
			}
		}

		return $routes;
	}

	/**
	 * Whether a route has an MCP Adapter REST request handler.
	 *
	 * @param array $handlers Registered handlers for one REST route.
	 */
	private function has_adapter_request_handler( array $handlers ): bool {
		foreach ( $handlers as $handler ) {
			$callback = is_array( $handler ) ? ( $handler['callback'] ?? null ) : null;

			if (
				is_array( $callback )
				&& isset( $callback[0], $callback[1] )
				&& is_object( $callback[0] )
				&& $callback[0] instanceof \WP\MCP\Transport\Contracts\McpRestTransportInterface
				&& 'handle_request' === $callback[1]
			) {
				return true;
			}
		}

		return false;
	}
}
