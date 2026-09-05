<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Token\Token;

require_once __DIR__ . '/class-test-case.php';

class Tokens_Test extends Test_Case {

	/**
	 * Rewrite a stored row directly, which is the only way to reach the states
	 * that would otherwise take an hour or a month of wall clock to produce.
	 */
	private function set_row( int $token_id, array $data ): void {
		global $wpdb;

		$wpdb->update( $this->plugin->get_tokens()->get_table_name(), $data, [ 'id' => $token_id ] );
	}

	private function expire( int $token_id ): void {
		$this->set_row( $token_id, [ 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS ) ] );
	}

	private function get_state( int $token_id ): string {
		return $this->plugin->get_tokens()->get_by_id( $token_id )->get_state();
	}

	private function issue( array $args = [] ): array {
		return $this->plugin->get_tokens()->issue(
			array_merge(
				[
					'token_type' => Token::TYPE_ACCESS,
					'client_id' => 'op_client',
					'user_id' => 1,
					'scopes' => [ 'wp:rest' ],
					'resource' => $this->get_default_resource_uri(),
				],
				$args
			)
		);
	}

	public function test_stores_only_the_token_hash() {
		global $wpdb;

		$issued = $this->issue();
		$table = $this->plugin->get_tokens()->get_table_name();

		$row = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed internal table name.
			$wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $issued['token']->get_id() ),
			ARRAY_A
		);

		$this->assertStringNotContainsString(
			$issued['value'],
			(string) wp_json_encode( $row ),
			'The raw token must never be persisted.'
		);

		$this->assertNotNull(
			$this->plugin->get_tokens()->get_by_value( $issued['value'] ),
			'Presenting the raw token must still resolve the stored row.'
		);
	}

	public function test_lookup_respects_the_token_type() {
		$issued = $this->issue( [ 'token_type' => Token::TYPE_REFRESH ] );

		$this->assertNull(
			$this->plugin->get_tokens()->get_by_value( $issued['value'], Token::TYPE_ACCESS ),
			'A refresh token must not be usable where an access token is expected.'
		);
	}

	public function test_hook_receives_no_raw_credential() {
		$captured = null;

		add_action(
			'oauth_pilot__token_issued',
			function ( Token $token ) use ( &$captured ) {
				$captured = $token->to_array();
			}
		);

		$issued = $this->issue();

		$this->assertStringNotContainsString(
			$issued['value'],
			(string) wp_json_encode( $captured ),
			'Integrations must never be handed the credential itself.'
		);
	}

	public function test_refresh_token_is_consumed_exactly_once() {
		$issued = $this->issue( [ 'token_type' => Token::TYPE_REFRESH ] );

		$this->assertTrue(
			$this->plugin->get_tokens()->consume_refresh_token( $issued['token'] ),
			'The first rotation claims the presented refresh token.'
		);

		$this->assertFalse(
			$this->plugin->get_tokens()->consume_refresh_token( $issued['token'] ),
			'A concurrent second rotation must lose the race, which is what makes reuse detectable.'
		);
	}

	public function test_reuse_revokes_the_whole_family() {
		$family = $this->plugin->get_tokens()->new_family_id();

		$refresh = $this->issue(
			[
				'token_type' => Token::TYPE_REFRESH,
				'family_id' => $family,
			]
		);

		$access = $this->issue( [ 'family_id' => $family ] );

		$this->plugin->get_tokens()->handle_refresh_reuse( $refresh['token'] );

		$this->assertTrue(
			$this->plugin->get_tokens()->get_by_id( $refresh['token']->get_id() )->is_revoked(),
			'The reused refresh token must be revoked.'
		);

		$this->assertTrue(
			$this->plugin->get_tokens()->get_by_id( $access['token']->get_id() )->is_revoked(),
			'Every access token in the same family must be revoked as well, because the family is compromised.'
		);
	}

	public function test_active_grant_requires_a_scope_superset() {
		$this->issue(
			[
				'user_id' => 7,
				'client_id' => 'op_a',
				'scopes' => [ 'test:read', 'test:write' ],
			]
		);

		$resource = $this->get_default_resource_uri();

		$this->assertTrue(
			$this->plugin->get_tokens()->has_active_grant( 7, 'op_a', $resource, [ 'test:read' ] ),
			'Remembered consent applies when the new request asks for no more than was already granted.'
		);

		$this->assertFalse(
			$this->plugin->get_tokens()->has_active_grant( 7, 'op_a', $resource, [ 'test:read', 'test:extra' ] ),
			'Asking for an additional scope must require consent again.'
		);

		$this->assertFalse(
			$this->plugin->get_tokens()->has_active_grant( 7, 'op_b', $resource, [ 'test:read' ] ),
			'A grant belongs to one client only.'
		);

		$this->assertFalse(
			$this->plugin->get_tokens()->has_active_grant( 7, 'op_a', 'https://example.com/other', [ 'test:read' ] ),
			'A grant belongs to one resource only.'
		);
	}

	public function test_revoked_tokens_stop_being_grants() {
		$issued = $this->issue( [ 'user_id' => 9 ] );

		$this->plugin->get_tokens()->revoke( $issued['token'] );

		$this->assertFalse(
			$this->plugin->get_tokens()->has_active_grant( 9, 'op_client', $this->get_default_resource_uri(), [ 'wp:rest' ] ),
			'A revoked token must not keep a remembered consent alive.'
		);

		$this->assertSame(
			[],
			$this->plugin->get_tokens()->get_grants_for_user( 9 ),
			'A revoked token must disappear from the user facing grant list.'
		);
	}

	public function test_grants_are_grouped_by_client_and_resource() {
		$this->issue(
			[
				'user_id' => 11,
				'client_id' => 'op_a',
				'scopes' => [ 'test:read' ],
			]
		);
		$this->issue(
			[
				'user_id' => 11,
				'client_id' => 'op_a',
				'token_type' => Token::TYPE_REFRESH,
				'scopes' => [ 'test:write' ],
			]
		);

		$grants = $this->plugin->get_tokens()->get_grants_for_user( 11 );

		$this->assertCount( 1, $grants, 'One client and one resource is one grant, however many tokens it holds.' );

		$this->assertEqualSets(
			[ 'test:read', 'test:write' ],
			$grants[0]['scopes'],
			'The grant must show every scope the user actually gave that client.'
		);
	}

	public function test_last_used_writes_are_throttled() {
		$issued = $this->issue();

		$this->plugin->get_tokens()->touch_last_used( $issued['token'] );

		$after_first = $this->plugin->get_tokens()->get_by_id( $issued['token']->get_id() );

		$this->assertNotNull( $after_first->get_last_used_at(), 'The first use must be recorded.' );

		$this->plugin->get_tokens()->touch_last_used( $after_first );

		$this->assertSame(
			$after_first->get_last_used_at(),
			$this->plugin->get_tokens()->get_by_id( $issued['token']->get_id() )->get_last_used_at(),
			'A second use inside the throttle window must not write again.'
		);
	}

	public function test_a_fresh_token_reads_as_active() {
		$issued = $this->issue();

		$this->assertSame( Token::STATE_ACTIVE, $issued['token']->get_state() );
	}

	public function test_an_expired_token_reads_as_expired() {
		$issued = $this->issue();

		$this->expire( $issued['token']->get_id() );

		$this->assertSame( Token::STATE_EXPIRED, $this->get_state( $issued['token']->get_id() ) );
	}

	public function test_a_rotated_refresh_token_reads_as_consumed() {
		$issued = $this->issue( [ 'token_type' => Token::TYPE_REFRESH ] );

		$this->plugin->get_tokens()->consume_refresh_token( $issued['token'] );

		$this->assertSame( Token::STATE_CONSUMED, $this->get_state( $issued['token']->get_id() ) );
	}

	public function test_revocation_outranks_consumption() {
		$issued = $this->issue( [ 'token_type' => Token::TYPE_REFRESH ] );

		$this->plugin->get_tokens()->consume_refresh_token( $issued['token'] );
		$this->plugin->get_tokens()->revoke_family( $issued['token']->get_family_id() );

		$this->assertSame(
			Token::STATE_REVOKED,
			$this->get_state( $issued['token']->get_id() ),
			'A consumed token whose family was revoked is a security relevant row, not rotation history.'
		);
	}

	public function test_revocation_outranks_expiry() {
		$issued = $this->issue();

		$this->plugin->get_tokens()->revoke( $issued['token'] );
		$this->expire( $issued['token']->get_id() );

		$this->assertSame( Token::STATE_REVOKED, $this->get_state( $issued['token']->get_id() ) );
	}

	public function test_consumption_outranks_expiry() {
		$issued = $this->issue( [ 'token_type' => Token::TYPE_REFRESH ] );

		$this->plugin->get_tokens()->consume_refresh_token( $issued['token'] );
		$this->expire( $issued['token']->get_id() );

		$this->assertSame( Token::STATE_CONSUMED, $this->get_state( $issued['token']->get_id() ) );
	}

	public function test_active_only_excludes_every_unusable_state() {
		$user_id = self::factory()->user->create();

		$active = $this->issue( [ 'user_id' => $user_id ] );
		$expired = $this->issue( [ 'user_id' => $user_id ] );
		$revoked = $this->issue( [ 'user_id' => $user_id ] );
		$consumed = $this->issue(
			[
				'user_id' => $user_id,
				'token_type' => Token::TYPE_REFRESH,
			]
		);

		$this->expire( $expired['token']->get_id() );
		$this->plugin->get_tokens()->revoke( $revoked['token'] );
		$this->plugin->get_tokens()->consume_refresh_token( $consumed['token'] );

		$found = $this->plugin->get_tokens()->find_for_user( $user_id, [ 'active_only' => true ] );

		$this->assertSame(
			[ $active['token']->get_id() ],
			array_map( fn ( Token $token ): int => $token->get_id(), $found ),
			'active_only must agree with Token::is_active(), which counts consumption too.'
		);

		$this->assertCount( 4, $this->plugin->get_tokens()->find_for_user( $user_id ) );
	}

	public function test_rows_minted_in_the_same_second_keep_a_stable_order() {
		$user_id = self::factory()->user->create();
		$created_at = current_time( 'mysql', true );

		$first = $this->issue( [ 'user_id' => $user_id ] );
		$second = $this->issue( [ 'user_id' => $user_id ] );

		// A refresh mints its pair inside one second, so created_at alone
		// cannot order them.
		$this->set_row( $first['token']->get_id(), [ 'created_at' => $created_at ] );
		$this->set_row( $second['token']->get_id(), [ 'created_at' => $created_at ] );

		$found = $this->plugin->get_tokens()->find_for_user( $user_id );

		$this->assertSame(
			[ $second['token']->get_id(), $first['token']->get_id() ],
			array_map( fn ( Token $token ): int => $token->get_id(), $found ),
			'The newest row must come first, and the order must not depend on the second they share.'
		);
	}

	public function test_counts_agree_with_the_listing() {
		$user_id = self::factory()->user->create();

		$this->issue( [ 'user_id' => $user_id ] );
		$expired = $this->issue( [ 'user_id' => $user_id ] );

		$this->expire( $expired['token']->get_id() );

		$tokens = $this->plugin->get_tokens();

		$this->assertSame( 2, $tokens->count_for_user( $user_id ) );
		$this->assertSame( 1, $tokens->count_for_user( $user_id, [ 'active_only' => true ] ) );
		$this->assertCount( $tokens->count_for_user( $user_id ), $tokens->find_for_user( $user_id ) );
	}

	public function test_the_listing_can_be_filtered_by_client() {
		$this->issue( [ 'client_id' => 'op_one' ] );
		$this->issue( [ 'client_id' => 'op_two' ] );

		$found = $this->plugin->get_tokens()->find( [ 'client_id' => 'op_one' ] );

		$this->assertCount( 1, $found );
		$this->assertSame( 'op_one', $found[0]->get_client_id() );
	}

	public function test_the_listing_is_limited_and_offset() {
		$user_id = self::factory()->user->create();

		$this->issue( [ 'user_id' => $user_id ] );
		$newest = $this->issue( [ 'user_id' => $user_id ] );

		$page = $this->plugin->get_tokens()->find_for_user( $user_id, [ 'limit' => 1 ] );

		$this->assertCount( 1, $page );
		$this->assertSame( $newest['token']->get_id(), $page[0]->get_id() );

		$this->assertCount(
			1,
			$this->plugin->get_tokens()->find_for_user(
				$user_id,
				[
					'limit' => 1,
					'offset' => 1,
				]
			)
		);
		$this->assertCount(
			0,
			$this->plugin->get_tokens()->find_for_user(
				$user_id,
				[
					'limit' => 1,
					'offset' => 2,
				]
			)
		);
	}

	public function test_cleanup_removes_long_expired_tokens() {
		global $wpdb;

		$issued = $this->issue();
		$table = $this->plugin->get_tokens()->get_table_name();

		$wpdb->update(
			$table,
			[ 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - ( 30 * DAY_IN_SECONDS ) ) ],
			[ 'id' => $issued['token']->get_id() ]
		);

		$this->assertSame(
			1,
			$this->plugin->get_tokens()->delete_expired(),
			'Scheduled cleanup is what bounds the tokens table.'
		);
	}
}
