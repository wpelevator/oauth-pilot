<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Authorization\Authorization;
use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Random;

require_once __DIR__ . '/class-test-case.php';

class Authorizations_Test extends Test_Case {

	private function create_pending( array $args = [] ): array {
		$client = $this->create_public_client();

		return $this->plugin->get_authorizations()->create(
			array_merge(
				[
					'client_id' => $client->get_client_id(),
					'client_snapshot' => $client->to_snapshot(),
					'redirect_uri' => $client->get_redirect_uris()[0],
					'scopes' => [ 'wp:read' ],
					'resource' => $this->get_default_resource_uri(),
					'code_challenge' => PKCE::challenge_for( Random::credential() ),
					'state' => 'abc',
				],
				$args
			)
		);
	}

	public function test_stores_only_the_hash_of_the_request_identifier() {
		global $wpdb;

		$created = $this->create_pending();
		$table = $this->plugin->get_authorizations()->get_table_name();

		$row = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed internal table name.
			$wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $created['authorization']->get_id() ),
			ARRAY_A
		);

		$this->assertStringNotContainsString(
			$created['request_id'],
			(string) wp_json_encode( $row ),
			'The opaque request identifier handed to the browser must never be stored in the clear.'
		);

		$this->assertNotNull(
			$this->plugin->get_authorizations()->get_by_request_id( $created['request_id'] ),
			'The request must still be findable by presenting the identifier.'
		);
	}

	public function test_binds_an_unbound_request_to_a_user_and_session() {
		$created = $this->create_pending();
		$user_id = self::factory()->user->create();

		$this->assertTrue(
			$this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-a' ),
			'The consent controller binds the pending request to whoever is signed in.'
		);

		$bound = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );

		$this->assertSame( $user_id, $bound->get_user_id(), 'The bound user must be recorded.' );

		$this->assertTrue(
			$bound->is_bound_to_session( $user_id, 'session-a' ),
			'The session token binding is what stops another browser from finishing this flow.'
		);
	}

	public function test_rejects_binding_a_request_that_belongs_to_another_session() {
		$created = $this->create_pending();
		$first = self::factory()->user->create();
		$second = self::factory()->user->create();

		$this->plugin->get_authorizations()->bind_user( $created['authorization'], $first, 'session-a' );

		$this->assertFalse(
			$this->plugin->get_authorizations()->bind_user( $created['authorization'], $second, 'session-b' ),
			'A pending request already claimed by one session must not be completed by another.'
		);

		$this->assertFalse(
			$this->plugin->get_authorizations()->bind_user( $created['authorization'], $first, 'session-b' ),
			'The same user in a different session is still a different session.'
		);

		$this->assertTrue(
			$this->plugin->get_authorizations()->bind_user( $created['authorization'], $first, 'session-a' ),
			'Reloading the consent screen in the same session must keep working.'
		);
	}

	public function test_approval_is_claimed_exactly_once() {
		$created = $this->create_pending();
		$user_id = self::factory()->user->create();

		$this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-a' );

		$authorization = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );

		$code = $this->plugin->get_authorizations()->approve( $authorization, $user_id, [ 'wp:read' ] );

		$this->assertNotEmpty( $code, 'Approving a bound pending request must produce a code.' );

		$this->assertNull(
			$this->plugin->get_authorizations()->approve( $authorization, $user_id, [ 'wp:read' ] ),
			'The conditional update must refuse a second approval of the same row, which is the whole atomicity contract.'
		);
	}

	public function test_code_is_consumed_exactly_once() {
		$created = $this->create_pending();
		$user_id = self::factory()->user->create();

		$this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-a' );

		$authorization = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );
		$code = $this->plugin->get_authorizations()->approve( $authorization, $user_id, [ 'wp:read' ] );

		$approved = $this->plugin->get_authorizations()->get_by_code( $code );

		$this->assertTrue(
			$this->plugin->get_authorizations()->consume( $approved ),
			'The first token request claims the code.'
		);

		$this->assertFalse(
			$this->plugin->get_authorizations()->consume( $approved ),
			'A concurrent second token request must lose the race and receive nothing.'
		);

		$this->assertTrue(
			$this->plugin->get_authorizations()->get_by_id( $approved->get_id() )->is_consumed(),
			'The row must record that the code was spent.'
		);
	}

	public function test_denial_closes_the_request() {
		$created = $this->create_pending();
		$user_id = self::factory()->user->create();

		$this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-a' );

		$authorization = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );

		$this->assertTrue(
			$this->plugin->get_authorizations()->deny( $authorization, $user_id ),
			'Denying must consume the pending request.'
		);

		$this->assertSame(
			Authorization::STATUS_DENIED,
			$this->plugin->get_authorizations()->get_by_id( $authorization->get_id() )->get_status(),
			'A denied request must not remain approvable.'
		);
	}

	public function test_expired_requests_cannot_be_bound() {
		global $wpdb;

		$created = $this->create_pending();
		$table = $this->plugin->get_authorizations()->get_table_name();

		$wpdb->update(
			$table,
			[ 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ) ],
			[ 'id' => $created['authorization']->get_id() ]
		);

		$authorization = $this->plugin->get_authorizations()->get_by_id( $created['authorization']->get_id() );

		$this->assertTrue( $authorization->is_expired(), 'The fixture must be expired.' );

		$this->assertFalse(
			$this->plugin->get_authorizations()->bind_user( $authorization, self::factory()->user->create(), 'session-a' ),
			'An expired authorization request must not be revivable by signing in.'
		);
	}

	public function test_cleanup_removes_long_expired_requests() {
		global $wpdb;

		$created = $this->create_pending();
		$table = $this->plugin->get_authorizations()->get_table_name();

		$wpdb->update(
			$table,
			[ 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - ( 2 * DAY_IN_SECONDS ) ) ],
			[ 'id' => $created['authorization']->get_id() ]
		);

		$this->assertSame(
			1,
			$this->plugin->get_authorizations()->delete_expired(),
			'Scheduled cleanup is what bounds the authorizations table.'
		);
	}
}
