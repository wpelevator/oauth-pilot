<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Plugin;
use function WPElevator\OAuth_Pilot\plugin;

/**
 * Shared setup for every OAuth Pilot test.
 *
 * tools/local/phpunit-bootstrap.php fires the activation hooks, so the tables
 * already exist by the time a test runs. The guard below is a cheap option read
 * that keeps the suite self sufficient if it is ever run against a bootstrap
 * that does not.
 */
abstract class Test_Case extends \WP_UnitTestCase {

	protected Plugin $plugin;

	public function set_up() {
		parent::set_up();

		$this->plugin = plugin();
		$this->plugin->get_schema()->install_if_needed();

		$this->plugin->get_scopes()->reset();
		$this->plugin->get_resources()->reset();
	}

	public function tear_down() {
		$this->plugin->get_scopes()->reset();
		$this->plugin->get_resources()->reset();

		parent::tear_down();
	}

	protected function get_default_resource_uri(): string {
		return $this->plugin->get_urls()->normalize_url( rest_url() );
	}

	protected function create_public_client( array $args = [] ): Client {
		return $this->plugin->get_clients()->create(
			array_merge(
				[
					'name' => 'Test Agent',
					'client_type' => Client::TYPE_PUBLIC,
					'token_endpoint_auth_method' => Client::AUTH_NONE,
					'redirect_uris' => [ 'https://claude.example.com/api/mcp/auth_callback' ],
					'grant_types' => [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ],
					'source' => Client::SOURCE_DYNAMIC,
				],
				$args
			)
		);
	}

	protected function create_confidential_client( array $args = [] ): Client {
		return $this->plugin->get_clients()->create(
			array_merge(
				[
					'name' => 'Test Connector',
					'client_type' => Client::TYPE_CONFIDENTIAL,
					'token_endpoint_auth_method' => Client::AUTH_BASIC,
					'redirect_uris' => [ 'https://connector.example.com/callback' ],
					'grant_types' => [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ],
					'source' => Client::SOURCE_ADMIN,
				],
				$args
			)
		);
	}

	/**
	 * Run one authorization from the protocol endpoint through consent and
	 * return the issued authorization code.
	 */
	protected function complete_authorization( Client $client, string $verifier, array $overrides = [] ): array {
		$params = array_merge(
			[
				'response_type' => 'code',
				'client_id' => $client->get_client_id(),
				'redirect_uri' => $client->get_redirect_uris()[0],
				'state' => 'client-state-value',
				'code_challenge' => PKCE::challenge_for( $verifier ),
				'code_challenge_method' => 'S256',
				'resource' => $this->get_default_resource_uri(),
				'scope' => 'wp:read',
			],
			$overrides
		);

		$service = $this->plugin->get_authorization_service();
		$validated = $service->validate_request( $params );
		$created = $service->create_pending( $validated );

		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );
		wp_set_current_user( $user_id );

		$this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-token' );

		$authorization = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );

		$redirect = $service->approve( $authorization, $user_id );

		$query = [];
		parse_str( (string) wp_parse_url( $redirect, PHP_URL_QUERY ), $query );

		return [
			'user_id' => $user_id,
			'redirect' => $redirect,
			'code' => (string) ( $query['code'] ?? '' ),
			'state' => (string) ( $query['state'] ?? '' ),
			'iss' => (string) ( $query['iss'] ?? '' ),
			'authorization' => $authorization,
		];
	}

	/**
	 * Dispatch a form encoded POST to one of the protocol routes.
	 */
	protected function post_form( string $route, array $params, array $headers = [] ): \WP_REST_Response {
		$request = new \WP_REST_Request( 'POST', $route );
		$request->set_header( 'content-type', 'application/x-www-form-urlencoded' );

		foreach ( $headers as $name => $value ) {
			$request->set_header( $name, $value );
		}

		$request->set_body( http_build_query( $params ) );

		return rest_do_request( $request );
	}
}
