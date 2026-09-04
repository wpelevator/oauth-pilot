<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Scopes;

class Scopes_Test extends \WP_UnitTestCase {

	private Scopes $scopes;

	public function set_up() {
		parent::set_up();

		$this->scopes = new Scopes();

		add_action(
			'oauth_pilot__register_scopes',
			function ( Scopes $scopes ) {
				$scopes->register(
					[
						'name' => 'mcp:read',
						'label' => 'Read',
					]
				);
				$scopes->register(
					[
						'name' => 'mcp:tools',
						'label' => 'Tools',
						'implies' => [ 'mcp:read' ],
					]
				);
			}
		);
	}

	private function get_resource( array $args = [] ): Protected_Resource {
		return new Protected_Resource(
			array_merge(
				[
					'uri' => 'https://example.com/wp-json/mcp/v1/mcp',
					'scopes' => [ 'mcp:read', 'mcp:tools' ],
					'defaults' => [ 'mcp:read' ],
				],
				$args
			)
		);
	}

	private function get_client( array $scopes = [] ): Client {
		return Client::from_row(
			[
				'client_id' => 'op_test',
				'client_type' => Client::TYPE_PUBLIC,
				'scopes' => implode( ' ', $scopes ),
			]
		);
	}

	public function test_parses_a_space_delimited_scope_parameter() {
		$this->assertSame(
			[ 'mcp:read', 'mcp:tools' ],
			$this->scopes->parse( 'mcp:read  mcp:tools' ),
			'Multiple spaces between scopes must not produce empty entries.'
		);
	}

	public function test_rejects_duplicate_scopes() {
		$this->expectException( OAuth_Error::class );

		$this->scopes->parse( 'mcp:read mcp:read' );
	}

	public function test_rejects_malformed_scope_names() {
		$this->expectException( OAuth_Error::class );

		$this->scopes->parse( 'mcp:' . chr( 34 ) . 'read' . chr( 34 ) );
	}

	public function test_expands_implied_scopes_into_a_stable_order() {
		$this->assertSame(
			[ 'mcp:read', 'mcp:tools' ],
			$this->scopes->expand( [ 'mcp:tools' ] ),
			'A granted scope must always carry the scopes it implies, in a normalized order.'
		);
	}

	public function test_empty_request_falls_back_to_the_resource_defaults() {
		$this->assertSame(
			[ 'mcp:read' ],
			$this->scopes->resolve_requested( [], $this->get_resource(), $this->get_client() ),
			'Agent clients routinely omit the scope parameter, so the resource defaults must apply.'
		);
	}

	public function test_rejects_a_scope_the_resource_does_not_support() {
		$this->expectException( OAuth_Error::class );

		$this->scopes->resolve_requested(
			[ 'mcp:tools' ],
			$this->get_resource( [ 'scopes' => [ 'mcp:read' ] ] ),
			$this->get_client()
		);
	}

	public function test_rejects_a_scope_above_the_client_ceiling() {
		$this->expectException( OAuth_Error::class );

		$this->scopes->resolve_requested(
			[ 'mcp:tools' ],
			$this->get_resource(),
			$this->get_client( [ 'mcp:read' ] )
		);
	}

	public function test_rejects_an_unknown_scope() {
		$this->expectException( OAuth_Error::class );

		$this->scopes->resolve_requested( [ 'mcp:admin' ], $this->get_resource(), $this->get_client() );
	}

	public function test_satisfies_uses_implications() {
		$this->assertTrue(
			$this->scopes->satisfies( [ 'mcp:tools' ], [ 'mcp:read' ] ),
			'A token carrying an implying scope must satisfy the implied requirement.'
		);

		$this->assertFalse(
			$this->scopes->satisfies( [ 'mcp:read' ], [ 'mcp:tools' ] ),
			'Implication must not work in the other direction.'
		);
	}

	public function test_user_can_grant_respects_the_scope_callback() {
		$scopes = new Scopes();

		add_action(
			'oauth_pilot__register_scopes',
			function ( Scopes $registry ) {
				$registry->register(
					[
						'name' => 'mcp:tools',
						'user_can_grant' => fn ( int $user_id ): bool => user_can( $user_id, 'edit_posts' ),
					]
				);
			},
			20
		);

		$editor = self::factory()->user->create( [ 'role' => 'editor' ] );
		$subscriber = self::factory()->user->create( [ 'role' => 'subscriber' ] );

		$this->assertTrue(
			$scopes->user_can_grant( $editor, [ 'mcp:tools' ], $this->get_resource(), $this->get_client() ),
			'A user with the underlying capability may grant the scope.'
		);

		$this->assertFalse(
			$scopes->user_can_grant( $subscriber, [ 'mcp:tools' ], $this->get_resource(), $this->get_client() ),
			'A scope must never let a user delegate a capability they do not have.'
		);
	}
}
