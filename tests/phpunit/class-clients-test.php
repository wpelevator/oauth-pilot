<?php

namespace WPElevator\OAuth_Pilot_Tests;

require_once __DIR__ . '/class-test-case.php';

class Clients_Test extends Test_Case {

	public function test_generates_a_lowercase_prefixed_client_id() {
		$client = $this->create_public_client();

		$this->assertMatchesRegularExpression(
			'/^op_[0-9a-f]{64}$/',
			$client->get_client_id(),
			'Client identifiers are lowercase hexadecimal so a case insensitive collation cannot collide two clients.'
		);
	}

	public function test_public_clients_get_no_secret() {
		$client = $this->create_public_client();

		$this->assertNull(
			$client->get_new_secret(),
			'A public client authenticates with PKCE only and must never receive a secret.'
		);

		$this->assertFalse(
			$client->has_secret(),
			'No secret hash may be stored for a public client.'
		);
	}

	public function test_confidential_client_secret_is_returned_once_and_stored_hashed() {
		$client = $this->create_confidential_client();
		$secret = $client->get_new_secret();

		$this->assertNotEmpty( $secret, 'The plaintext secret must be available once, at creation.' );

		$stored = $this->plugin->get_clients()->get_by_client_id( $client->get_client_id() );

		$this->assertNull(
			$stored->get_new_secret(),
			'A client loaded from storage must never be able to reveal its secret.'
		);

		$this->assertTrue(
			$stored->verify_secret( $secret ),
			'The stored hash must verify the secret that was handed out.'
		);

		$this->assertFalse(
			$stored->verify_secret( $secret . 'x' ),
			'A different secret must not verify.'
		);
	}

	public function test_no_raw_secret_is_written_to_the_table() {
		global $wpdb;

		$client = $this->create_confidential_client();
		$secret = (string) $client->get_new_secret();

		$table = $this->plugin->get_clients()->get_table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed internal table name.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE client_id = %s", $client->get_client_id() ), ARRAY_A );

		$this->assertStringNotContainsString(
			$secret,
			(string) wp_json_encode( $row ),
			'The raw secret must not appear anywhere in the stored row.'
		);
	}

	public function test_lookup_is_exact() {
		$client = $this->create_public_client();

		$this->assertNull(
			$this->plugin->get_clients()->get_by_client_id( strtoupper( $client->get_client_id() ) ),
			'A collation insensitive match must not resolve a client identifier.'
		);

		$this->assertNull(
			$this->plugin->get_clients()->get_by_client_id( '' ),
			'An empty client identifier must never resolve.'
		);
	}

	public function test_revoking_a_client_revokes_its_tokens() {
		$client = $this->create_public_client();

		$issued = $this->plugin->get_tokens()->issue(
			[
				'client_id' => $client->get_client_id(),
				'user_id' => 1,
				'scopes' => [ 'wp:rest' ],
				'resource' => $this->get_default_resource_uri(),
			]
		);

		$this->plugin->get_clients()->revoke( $client );

		$token = $this->plugin->get_tokens()->get_by_id( $issued['token']->get_id() );

		$this->assertTrue(
			$token->is_revoked(),
			'Revoking a client must immediately invalidate every token issued to it.'
		);

		$this->assertFalse(
			$this->plugin->get_clients()->get_by_client_id( $client->get_client_id() )->is_active(),
			'A revoked client must no longer be active.'
		);
	}

	public function test_counts_only_active_dynamic_clients() {
		$first = $this->create_public_client();
		$this->create_public_client();
		$this->create_confidential_client();

		$this->assertSame(
			2,
			$this->plugin->get_clients()->count_active_dynamic(),
			'The dynamic client quota is enforced with an exact count, not a best effort counter.'
		);

		$this->plugin->get_clients()->revoke( $first );

		$this->assertSame(
			1,
			$this->plugin->get_clients()->count_active_dynamic(),
			'A revoked client no longer occupies a slot in the quota.'
		);
	}

	public function test_deletes_dynamic_clients_that_were_never_used() {
		global $wpdb;

		$client = $this->create_public_client();
		$table = $this->plugin->get_clients()->get_table_name();

		$wpdb->update(
			$table,
			[ 'created_at' => gmdate( 'Y-m-d H:i:s', time() - ( 2 * DAY_IN_SECONDS ) ) ],
			[ 'id' => $client->get_id() ]
		);

		$deleted = $this->plugin->get_clients()->delete_stale_ephemeral( DAY_IN_SECONDS, 90 * DAY_IN_SECONDS );

		$this->assertSame( 1, $deleted, 'A dynamic client that never completed an authorization must be cleaned up.' );

		$this->assertNull(
			$this->plugin->get_clients()->get_by_client_id( $client->get_client_id() ),
			'The stale client row must be gone.'
		);
	}

	public function test_client_snapshot_captures_what_an_authorization_needs() {
		$client = $this->create_public_client();
		$snapshot = $client->to_snapshot();

		$this->assertSame(
			$client->get_redirect_uris(),
			$snapshot['redirect_uris'],
			'The snapshot exists so a later client change cannot alter an in flight authorization.'
		);

		$this->assertArrayNotHasKey(
			'secret_hash',
			$snapshot,
			'A snapshot must never carry credential material.'
		);
	}
}
