<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Schema;

require_once __DIR__ . '/class-test-case.php';

/**
 * Upgrading an installed site must not look like a mass revocation.
 *
 * A site's own prefix and its network's base prefix are the same string on
 * single site, so the tables this release reads are the very tables the
 * previous release wrote. Their rows survive the upgrade, and dbDelta gives
 * them the new blog_id column at its default of 0, which matches no site.
 *
 * These tests reproduce that state directly, by writing rows with blog_id 0
 * rather than by altering the table, so they stay inside the transaction the
 * WP test case wraps around them and leave nothing behind.
 */
class Schema_Upgrade_Test extends Test_Case {

	/**
	 * A row as the upgrade leaves it: written by the previous release, then
	 * given the new column at its default.
	 */
	private function insert_pre_upgrade_token( string $value ): void {
		global $wpdb;

		$wpdb->insert(
			$this->plugin->get_schema()->get_table_name( Schema::TABLE_TOKENS ),
			[
				'blog_id' => 0,
				'token_type' => 'access',
				'token_hash' => hash( 'sha256', $value ),
				'client_id' => 'op_installed',
				'user_id' => 1,
				'scopes' => 'wp:rest',
				'resource' => $this->get_default_resource_uri(),
				'family_id' => 'family',
				'created_at' => current_time( 'mysql', true ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', time() + HOUR_IN_SECONDS ),
			]
		);
	}

	private function insert_pre_upgrade_authorization( string $request_id ): void {
		global $wpdb;

		$wpdb->insert(
			$this->plugin->get_schema()->get_table_name( Schema::TABLE_AUTHORIZATIONS ),
			[
				'blog_id' => 0,
				'request_id_hash' => hash( 'sha256', $request_id ),
				'client_id' => 'op_installed',
				'client_snapshot' => '{}',
				'redirect_uri' => 'https://example.com/callback',
				'scopes' => 'wp:rest',
				'resource' => $this->get_default_resource_uri(),
				'code_challenge' => 'challenge',
				'state' => '',
				'status' => 'pending',
				'created_at' => current_time( 'mysql', true ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', time() + HOUR_IN_SECONDS ),
			]
		);
	}

	public function test_a_pre_upgrade_row_would_be_invisible_without_adoption() {
		$this->insert_pre_upgrade_token( 'an-unadopted-token' );

		$this->assertNull(
			$this->plugin->get_tokens()->get_by_value( 'an-unadopted-token' ),
			'Blog 0 matches no site: this is the breakage the adoption pass exists to prevent.'
		);
	}

	public function test_an_existing_token_survives_the_upgrade() {
		$this->insert_pre_upgrade_token( 'a-token-issued-before-the-upgrade' );

		// The state a site running the previous release is in.
		update_network_option( null, Schema::OPTION_VERSION, 2 );

		$this->plugin->get_schema()->install_if_needed();

		$this->assertNotNull(
			$this->plugin->get_tokens()->get_by_value( 'a-token-issued-before-the-upgrade' ),
			'An upgrade must not silently invalidate the tokens a site already issued.'
		);
	}

	public function test_an_existing_authorization_survives_the_upgrade() {
		$this->insert_pre_upgrade_authorization( 'a-pending-request' );

		update_network_option( null, Schema::OPTION_VERSION, 2 );

		$this->plugin->get_schema()->install_if_needed();

		$this->assertNotNull(
			$this->plugin->get_authorizations()->get_by_request_id( 'a-pending-request' ),
			'A request in flight during the upgrade must still be completable.'
		);
	}

	public function test_the_upgrade_records_the_new_version() {
		update_network_option( null, Schema::OPTION_VERSION, 2 );

		$this->plugin->get_schema()->install_if_needed();

		$this->assertSame(
			Schema::VERSION,
			(int) get_network_option( null, Schema::OPTION_VERSION, 0 ),
			'The upgrade must record the version so it does not run on every request.'
		);

		$this->assertFalse( $this->plugin->get_schema()->needs_install() );
	}

	public function test_a_fresh_install_does_not_run_the_adoption_pass() {
		$this->insert_pre_upgrade_token( 'a-token-on-a-site-that-never-ran-v2' );

		// No recorded version at all is a first install, not an upgrade.
		delete_network_option( null, Schema::OPTION_VERSION );

		$this->plugin->get_schema()->install_if_needed();

		$this->assertNull(
			$this->plugin->get_tokens()->get_by_value( 'a-token-on-a-site-that-never-ran-v2' ),
			'A first install has nothing to adopt and must not claim stray rows.'
		);
	}
}
