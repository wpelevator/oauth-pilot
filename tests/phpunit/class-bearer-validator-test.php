<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Token\Context;
use WPElevator\OAuth_Pilot\Token\Token;
use function WPElevator\OAuth_Pilot\plugin;

require_once __DIR__ . '/class-test-case.php';

/**
 * The API an MCP server calls in its own permission layer.
 */
class Bearer_Validator_Test extends Test_Case {

	private string $mcp_resource;

	public function set_up() {
		parent::set_up();

		$this->mcp_resource = $this->plugin->get_urls()->normalize_url( rest_url( 'example-mcp/v1/mcp' ) );

		add_action(
			'oauth_pilot__register_resources',
			function ( Protected_Resources $resources ) {
				$resources->register(
					[
						'uri' => rest_url( 'example-mcp/v1/mcp' ),
						'name' => 'Example MCP Server',
						'scopes' => [ 'mcp:tools', 'mcp:resources' ],
						'defaults' => [ 'mcp:tools' ],
					]
				);
			}
		);

		add_action(
			'oauth_pilot__register_scopes',
			function ( Scopes $scopes ) {
				$scopes->register( [ 'name' => 'mcp:tools' ] );
				$scopes->register( [ 'name' => 'mcp:resources' ] );
			}
		);
	}

	public function tear_down() {
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		parent::tear_down();
	}

	private function issue_token( array $args = [] ): string {
		$user_id = self::factory()->user->create( [ 'role' => 'editor' ] );

		$issued = $this->plugin->get_tokens()->issue(
			array_merge(
				[
					'token_type' => Token::TYPE_ACCESS,
					'client_id' => $this->create_public_client()->get_client_id(),
					'user_id' => $user_id,
					'scopes' => [ 'mcp:tools' ],
					'resource' => $this->mcp_resource,
				],
				$args
			)
		);

		return $issued['value'];
	}

	public function test_validates_a_correctly_scoped_token() {
		$token = $this->issue_token();

		$context = $this->plugin->get_validator()->validate_token( $token, $this->mcp_resource, [ 'mcp:tools' ] );

		$this->assertInstanceOf( Context::class, $context, 'A live, correctly scoped token must validate.' );

		$this->assertTrue(
			$context->has_scope( 'mcp:tools' ),
			'The context must answer scope questions for the calling plugin.'
		);

		$this->assertSame(
			$this->mcp_resource,
			$context->get_resource_uri(),
			'The context reports the audience the token was bound to.'
		);
	}

	public function test_rejects_a_token_minted_for_another_resource() {
		$token = $this->issue_token( [ 'resource' => $this->get_default_resource_uri() ] );

		$error = $this->plugin->get_validator()->validate_token( $token, $this->mcp_resource, [ 'mcp:tools' ] );

		$this->assertWPError( $error, 'A token for the WordPress REST API must not open an MCP endpoint nested under wp-json.' );

		$this->assertSame(
			401,
			$error->get_error_data()['status'],
			'An audience mismatch is an invalid token, not a permission problem.'
		);
	}

	public function test_rejects_an_under_scoped_token_with_a_step_up_challenge() {
		$token = $this->issue_token( [ 'scopes' => [ 'mcp:tools' ] ] );

		$error = $this->plugin->get_validator()->validate_token( $token, $this->mcp_resource, [ 'mcp:resources' ] );

		$this->assertWPError( $error, 'A valid token that lacks the scope must still fail.' );

		$data = $error->get_error_data();

		$this->assertSame( 403, $data['status'], 'Insufficient scope is 403, not 401.' );

		$this->assertStringContainsString(
			'error="insufficient_scope"',
			$data['www_authenticate'],
			'The challenge must tell the client what went wrong.'
		);

		$this->assertStringContainsString(
			'scope="mcp:resources"',
			$data['www_authenticate'],
			'The challenge must name the complete scope set required, so the client can step up.'
		);
	}

	public function test_rejects_revoked_and_expired_tokens() {
		$token = $this->issue_token();
		$stored = $this->plugin->get_tokens()->get_by_value( $token, Token::TYPE_ACCESS );

		$this->plugin->get_tokens()->revoke( $stored );

		$this->assertWPError(
			$this->plugin->get_validator()->validate_token( $token, $this->mcp_resource, [ 'mcp:tools' ] ),
			'Revocation must take effect immediately, with no cached positive result.'
		);
	}

	public function test_rejects_a_token_whose_client_was_revoked() {
		$client = $this->create_public_client();
		$token = $this->issue_token( [ 'client_id' => $client->get_client_id() ] );

		$this->plugin->get_clients()->revoke( $client );

		$this->assertWPError(
			$this->plugin->get_validator()->validate_token( $token, $this->mcp_resource, [ 'mcp:tools' ] ),
			'Revoking a client must immediately close every session it holds.'
		);
	}

	public function test_challenge_points_at_the_resource_metadata_document() {
		$challenge = $this->plugin->get_validator()->get_challenge( $this->mcp_resource, 'invalid_token', 'nope' );

		$this->assertStringStartsWith( 'Bearer ', $challenge, 'The challenge must name the bearer scheme.' );

		$this->assertStringContainsString(
			'resource_metadata="' . $this->plugin->get_urls()->get_protected_resource_metadata_url( $this->mcp_resource ) . '"',
			$challenge,
			'RFC 9728 discovery starts from the resource_metadata pointer in this challenge.'
		);
	}

	public function test_reads_the_credential_only_from_the_authorization_header() {
		$token = $this->issue_token();

		$_GET['access_token'] = $token;

		$this->assertWPError(
			$this->plugin->get_validator()->validate_request( $this->mcp_resource, [ 'mcp:tools' ] ),
			'A bearer token in the query string must never be accepted.'
		);

		unset( $_GET['access_token'] );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

		$this->assertInstanceOf(
			Context::class,
			$this->plugin->get_validator()->validate_request( $this->mcp_resource, [ 'mcp:tools' ] ),
			'The Authorization header is the one accepted credential location.'
		);
	}

	public function test_rejects_a_malformed_authorization_header() {
		$this->assertNull(
			$this->plugin->get_validator()->parse_bearer_token( 'Basic abc' ),
			'Only the Bearer scheme carries an access token.'
		);

		$this->assertNull(
			$this->plugin->get_validator()->parse_bearer_token( 'Bearer one two' ),
			'More than one credential in the header is ambiguous and must be refused.'
		);
	}

	public function test_singleton_exposes_the_validator_to_other_plugins() {
		$token = $this->issue_token();

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

		$this->assertInstanceOf(
			Context::class,
			plugin()->get_validator()->validate_request( $this->mcp_resource, [ 'mcp:tools' ] ),
			'The namespaced plugin() singleton is the documented integration point.'
		);
	}

	public function test_declares_no_global_functions() {
		foreach ( [ 'oauth_pilot_validate_request', 'oauth_pilot_validate_token', 'oauth_pilot_bearer_challenge' ] as $name ) {
			$this->assertFalse(
				function_exists( $name ),
				sprintf( 'OAuth Pilot must not pollute the global namespace with %s(); no other plugin in this repository does.', $name )
			);
		}
	}
}
