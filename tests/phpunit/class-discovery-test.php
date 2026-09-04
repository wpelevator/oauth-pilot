<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Discovery\Controller;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;

require_once __DIR__ . '/class-test-case.php';

class Discovery_Test extends Test_Case {

	public function test_registers_the_well_known_rewrite_rules_outside_wp_json() {
		global $wp_rewrite;

		$this->plugin->get_discovery()->action_add_rewrite_rules();

		$this->assertSame(
			'index.php?' . Controller::QUERY_METADATA . '=' . Controller::TYPE_AUTHORIZATION_SERVER,
			$wp_rewrite->extra_rules_top['^\.well-known/oauth-authorization-server/?$'],
			'RFC 8414 fixes this path, so it cannot be served from the REST API.'
		);

		$this->assertSame(
			'index.php?' . Controller::QUERY_METADATA . '=' . Controller::TYPE_PROTECTED_RESOURCE . '&' . Controller::QUERY_RESOURCE_PATH . '=$matches[1]',
			$wp_rewrite->extra_rules_top['^\.well-known/oauth-protected-resource/(.+)$'],
			'RFC 9728 addresses a resource by appending its path after the well-known segment.'
		);
	}

	public function test_authorization_server_metadata_advertises_only_implemented_behavior() {
		$metadata = $this->plugin->get_discovery()->get_authorization_server_response()->get_data();

		$this->assertSame(
			$this->plugin->get_urls()->get_issuer(),
			$metadata['issuer'],
			'The issuer must be the canonical value the tokens are issued under.'
		);

		$this->assertSame(
			[ 'code' ],
			$metadata['response_types_supported'],
			'Only the authorization code response type is implemented.'
		);

		$this->assertSame(
			[ 'S256' ],
			$metadata['code_challenge_methods_supported'],
			'The plain PKCE method must never be advertised.'
		);

		$this->assertSame(
			[ 'authorization_code', 'refresh_token' ],
			$metadata['grant_types_supported'],
			'Only the two user delegated grants are implemented.'
		);

		$this->assertContains(
			'client_secret_post',
			$metadata['token_endpoint_auth_methods_supported'],
			'Connectors configured with a pasted client secret commonly send it in the request body.'
		);

		$this->assertTrue(
			$metadata['authorization_response_iss_parameter_supported'],
			'RFC 9207 issuer identification is implemented and must be advertised.'
		);

		$this->assertArrayNotHasKey(
			'introspection_endpoint',
			$metadata,
			'Introspection is not implemented, so advertising it would mislead a client.'
		);
	}

	public function test_registration_endpoint_is_advertised_only_while_dcr_is_enabled() {
		$this->assertArrayNotHasKey(
			'registration_endpoint',
			$this->plugin->get_discovery()->get_authorization_server_response()->get_data(),
			'Dynamic registration is off by default, so a new site advertises no unauthenticated registration endpoint.'
		);

		add_filter( 'oauth_pilot__dynamic_registration_enabled', '__return_true' );

		$this->assertArrayHasKey(
			'registration_endpoint',
			$this->plugin->get_discovery()->get_authorization_server_response()->get_data(),
			'An operator who turns the endpoint on must see it advertised.'
		);
	}

	public function test_metadata_filter_cannot_remove_a_core_security_capability() {
		add_filter(
			'oauth_pilot__authorization_server_metadata',
			function ( array $metadata ): array {
				$metadata['code_challenge_methods_supported'] = [ 'plain' ];
				$metadata['issuer'] = 'https://attacker.example.com';

				return $metadata;
			}
		);

		$metadata = $this->plugin->get_discovery()->get_authorization_server_response()->get_data();

		$this->assertSame(
			[ 'S256' ],
			$metadata['code_challenge_methods_supported'],
			'A filter must not be able to advertise a PKCE method the server refuses to accept.'
		);

		$this->assertSame(
			$this->plugin->get_urls()->get_issuer(),
			$metadata['issuer'],
			'A filter must not be able to redirect clients to a different issuer.'
		);
	}

	public function test_protected_resource_metadata_describes_a_registered_resource() {
		add_action(
			'oauth_pilot__register_resources',
			function ( Protected_Resources $resources ) {
				$resources->register(
					[
						'uri' => rest_url( 'example-mcp/v1/mcp' ),
						'name' => 'Example MCP Server',
						'scopes' => [ 'mcp:tools' ],
					]
				);
			}
		);

		$resource = $this->plugin->get_resources()->get( rest_url( 'example-mcp/v1/mcp' ) );
		$response = $this->plugin->get_discovery()->get_protected_resource_response( $resource->get_metadata_path() );
		$metadata = $response->get_data();

		$this->assertSame( 200, $response->get_status(), 'A registered resource must publish its metadata document.' );

		$this->assertSame(
			$this->plugin->get_urls()->normalize_url( rest_url( 'example-mcp/v1/mcp' ) ),
			$metadata['resource'],
			'The document must name the exact canonical resource URI tokens are bound to.'
		);

		$this->assertSame(
			[ $this->plugin->get_urls()->get_issuer() ],
			$metadata['authorization_servers'],
			'The document is how a client finds the authorization server for this resource.'
		);

		$this->assertSame(
			[ 'header' ],
			$metadata['bearer_methods_supported'],
			'Only the Authorization header is an accepted credential location.'
		);
	}

	public function test_unknown_resource_metadata_path_is_not_found() {
		$this->assertSame(
			404,
			$this->plugin->get_discovery()->get_protected_resource_response( 'wp-json/nope/v1' )->get_status(),
			'An unregistered resource must not resolve to another resource document.'
		);
	}

	public function test_discovery_responses_expose_the_challenge_header_to_browsers() {
		$response = $this->plugin->get_discovery()->get_authorization_server_response();

		$this->assertSame(
			'WWW-Authenticate',
			$response->get_header( 'Access-Control-Expose-Headers' ),
			'A browser based client cannot read the challenge that starts discovery unless it is exposed.'
		);
	}
}
