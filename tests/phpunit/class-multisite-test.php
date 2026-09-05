<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Authorization\Authorization;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Schema;
use WPElevator\OAuth_Pilot\Token\Token;

require_once __DIR__ . '/class-test-case.php';

/**
 * The network wide storage contract.
 *
 * One registration per network, but authority strictly per site. These tests
 * exist because table separation used to enforce the second half for free and
 * now a WHERE clause does: they assert the isolation directly rather than
 * trusting the happy path.
 *
 * @group ms-required
 */
class Multisite_Test extends Test_Case {

	private int $second_blog_id;

	public function set_up() {
		parent::set_up();

		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires a multisite installation.' );
		}

		$this->second_blog_id = (int) self::factory()->blog->create();
	}

	private function issue( array $args = [] ): array {
		return $this->plugin->get_tokens()->issue(
			array_merge(
				[
					'token_type' => Token::TYPE_ACCESS,
					'client_id' => 'op_client',
					'user_id' => 1,
					'scopes' => [ 'wp:read' ],
					'resource' => $this->get_default_resource_uri(),
				],
				$args
			)
		);
	}

	public function test_tables_are_shared_by_the_whole_network() {
		global $wpdb;

		$on_main_site = $this->plugin->get_schema()->get_table_names();

		switch_to_blog( $this->second_blog_id );
		$on_second_site = ( new Schema( $wpdb ) )->get_table_names();
		restore_current_blog();

		$this->assertSame(
			$on_main_site,
			$on_second_site,
			'Every site of the network must read and write the same tables.'
		);

		$this->assertStringStartsWith(
			$wpdb->base_prefix,
			$on_main_site[0],
			'The tables must be named from the network prefix, not a site prefix.'
		);
	}

	public function test_a_client_registered_on_one_site_resolves_on_another() {
		$client = $this->create_public_client( [ 'name' => 'Shared Agent' ] );

		switch_to_blog( $this->second_blog_id );
		$resolved = $this->plugin->get_clients()->get_by_client_id( $client->get_client_id() );
		restore_current_blog();

		$this->assertNotNull( $resolved, 'A client must not have to register again per site.' );
		$this->assertSame( 'Shared Agent', $resolved->get_name() );
		$this->assertSame( $client->get_client_id(), $resolved->get_client_id() );
	}

	public function test_a_client_records_the_site_that_registered_it() {
		switch_to_blog( $this->second_blog_id );
		$client = $this->create_public_client();
		restore_current_blog();

		$resolved = $this->plugin->get_clients()->get_by_client_id( $client->get_client_id() );

		$this->assertSame( $this->second_blog_id, $resolved->get_blog_id() );
		$this->assertFalse(
			$resolved->is_managed_by_current_site(),
			'A site must not manage a registration another site owns.'
		);
	}

	public function test_a_token_issued_on_one_site_does_not_resolve_on_another() {
		$issued = $this->issue();

		switch_to_blog( $this->second_blog_id );
		$elsewhere = $this->plugin->get_tokens()->get_by_value( $issued['value'] );
		restore_current_blog();

		$this->assertNull(
			$elsewhere,
			'A token must be invisible to every site but the one that issued it.'
		);

		$this->assertNotNull(
			$this->plugin->get_tokens()->get_by_value( $issued['value'] ),
			'The issuing site must still resolve its own token.'
		);
	}

	public function test_a_token_cannot_be_loaded_by_id_from_another_site() {
		$issued = $this->issue();

		switch_to_blog( $this->second_blog_id );
		$elsewhere = $this->plugin->get_tokens()->get_by_id( $issued['token']->get_id() );
		restore_current_blog();

		$this->assertNull( $elsewhere );
	}

	public function test_an_authorization_code_cannot_be_exchanged_on_another_site() {
		$client = $this->create_public_client();
		$completed = $this->complete_authorization( $client, 'verifier-value-for-the-multisite-test' );

		$this->assertNotEmpty( $completed['code'] );

		switch_to_blog( $this->second_blog_id );
		$elsewhere = $this->plugin->get_authorizations()->get_by_code( $completed['code'] );
		restore_current_blog();

		$this->assertNull(
			$elsewhere,
			'A code issued against one site must not be redeemable on another.'
		);
	}

	public function test_a_pending_request_cannot_be_bound_from_another_site() {
		$client = $this->create_public_client();
		$service = $this->plugin->get_authorization_service();

		$validated = $service->validate_request(
			[
				'response_type' => 'code',
				'client_id' => $client->get_client_id(),
				'redirect_uri' => $client->get_redirect_uris()[0],
				'code_challenge' => \WPElevator\OAuth_Pilot\Authorization\PKCE::challenge_for( 'another-verifier-value-here' ),
				'code_challenge_method' => 'S256',
				'resource' => $this->get_default_resource_uri(),
				'scope' => 'wp:rest',
			]
		);

		$created = $service->create_pending( $validated );
		$user_id = self::factory()->user->create( [ 'role' => 'administrator' ] );

		switch_to_blog( $this->second_blog_id );
		$bound = $this->plugin->get_authorizations()->bind_user( $created['authorization'], $user_id, 'session-token' );
		restore_current_blog();

		$this->assertFalse( $bound, 'Another site must not be able to advance the request.' );
	}

	public function test_grants_are_listed_per_site() {
		$user_id = self::factory()->user->create();

		$this->issue( [ 'user_id' => $user_id ] );

		switch_to_blog( $this->second_blog_id );
		$grants_elsewhere = $this->plugin->get_tokens()->get_grants_for_user( $user_id );
		restore_current_blog();

		$this->assertCount( 0, $grants_elsewhere, 'A site must only list its own grants.' );
		$this->assertCount( 1, $this->plugin->get_tokens()->get_grants_for_user( $user_id ) );
	}

	public function test_remembered_consent_does_not_cross_sites() {
		$user_id = self::factory()->user->create();
		$resource = $this->get_default_resource_uri();

		$this->issue(
			[
				'user_id' => $user_id,
				'client_id' => 'op_consent',
				'scopes' => [ 'wp:read' ],
			]
		);

		$this->assertTrue(
			$this->plugin->get_tokens()->has_active_grant( $user_id, 'op_consent', $resource, [ 'wp:read' ] )
		);

		switch_to_blog( $this->second_blog_id );
		$remembered = $this->plugin->get_tokens()->has_active_grant( $user_id, 'op_consent', $resource, [ 'wp:read' ] );
		restore_current_blog();

		$this->assertFalse(
			$remembered,
			'Consent approved on one site must be asked for again on another.'
		);
	}

	public function test_revoking_access_locally_leaves_other_sites_working() {
		$client = $this->create_public_client();

		$here = $this->issue( [ 'client_id' => $client->get_client_id() ] );

		switch_to_blog( $this->second_blog_id );
		$there = $this->issue( [ 'client_id' => $client->get_client_id() ] );
		restore_current_blog();

		$this->plugin->get_clients()->revoke_access_on_this_site( $client );

		$this->assertTrue(
			$this->plugin->get_tokens()->get_by_value( $here['value'] )->is_revoked(),
			'The revoking site loses its own tokens.'
		);

		switch_to_blog( $this->second_blog_id );
		$still_live = $this->plugin->get_tokens()->get_by_value( $there['value'] );
		restore_current_blog();

		$this->assertFalse(
			$still_live->is_revoked(),
			'Another site of the network keeps working.'
		);

		$this->assertTrue(
			$this->plugin->get_clients()->get_by_client_id( $client->get_client_id() )->is_active(),
			'The shared registration itself survives a local revocation.'
		);
	}

	public function test_revoking_the_registration_reaches_every_site() {
		$client = $this->create_public_client();

		switch_to_blog( $this->second_blog_id );
		$there = $this->issue( [ 'client_id' => $client->get_client_id() ] );
		restore_current_blog();

		$this->plugin->get_clients()->revoke( $client );

		switch_to_blog( $this->second_blog_id );
		$token = $this->plugin->get_tokens()->get_by_value( $there['value'] );
		restore_current_blog();

		$this->assertTrue(
			$token->is_revoked(),
			'Revoking a network wide registration must revoke its tokens everywhere.'
		);
	}

	public function test_deleting_a_user_clears_their_tokens_on_every_site() {
		$user_id = self::factory()->user->create();

		$this->issue( [ 'user_id' => $user_id ] );

		switch_to_blog( $this->second_blog_id );
		$there = $this->issue( [ 'user_id' => $user_id ] );
		restore_current_blog();

		$this->plugin->get_profile()->action_delete_user_data( $user_id );

		switch_to_blog( $this->second_blog_id );
		$token = $this->plugin->get_tokens()->get_by_value( $there['value'] );
		restore_current_blog();

		$this->assertNull( $token, 'A deleted account leaves nothing behind on any site.' );
	}

	public function test_removing_a_user_from_one_site_spares_the_others() {
		$user_id = self::factory()->user->create();

		$here = $this->issue( [ 'user_id' => $user_id ] );

		switch_to_blog( $this->second_blog_id );
		$there = $this->issue( [ 'user_id' => $user_id ] );
		restore_current_blog();

		$this->plugin->get_profile()->action_remove_user_from_blog( $user_id, $this->second_blog_id );

		switch_to_blog( $this->second_blog_id );
		$removed = $this->plugin->get_tokens()->get_by_value( $there['value'] );
		restore_current_blog();

		$this->assertNull( $removed, 'The site they left must drop their tokens.' );

		$this->assertNotNull(
			$this->plugin->get_tokens()->get_by_value( $here['value'] ),
			'Their grants on other sites must survive.'
		);
	}

	public function test_deleting_a_site_drops_its_rows_but_keeps_shared_clients() {
		$in_use_elsewhere = $this->create_public_client( [ 'name' => 'Still Used' ] );

		switch_to_blog( $this->second_blog_id );

		$abandoned = $this->create_public_client( [ 'name' => 'Abandoned' ] );
		$there = $this->issue( [ 'client_id' => $in_use_elsewhere->get_client_id() ] );

		restore_current_blog();

		// The client that lives on has a token on the surviving site.
		$this->issue( [ 'client_id' => $in_use_elsewhere->get_client_id() ] );

		$deleted = $this->plugin->get_schema()->delete_site_data( $this->second_blog_id );

		$this->assertSame( 1, $deleted['tokens'], 'The deleted site loses its tokens.' );

		$this->assertNull(
			$this->plugin->get_clients()->get_by_client_id( $abandoned->get_client_id() ),
			'A registration nothing uses any more goes with its site.'
		);

		$survivor = $this->plugin->get_clients()->get_by_client_id( $in_use_elsewhere->get_client_id() );

		$this->assertNotNull(
			$survivor,
			'A registration other sites still use must outlive its registering site.'
		);

		$this->assertNotNull( $there, 'Sanity: the second site had issued a token.' );
	}

	/**
	 * The shape a real network takes: the plugin is activated on one site,
	 * which is not necessarily the main one, and no other site ever loads it.
	 */
	public function test_a_subsite_creates_the_shared_tables() {
		global $wpdb;

		// No record of the schema anywhere the main site can see, because the
		// plugin has never run there.
		delete_network_option( null, Schema::OPTION_VERSION );
		delete_blog_option( get_main_site_id(), Schema::OPTION_VERSION );

		switch_to_blog( $this->second_blog_id );

		$schema = new Schema( $wpdb );

		$this->assertTrue( $schema->needs_install(), 'The only site running the plugin must install the tables.' );

		$schema->install_if_needed();

		$table_names = $schema->get_table_names();

		restore_current_blog();

		foreach ( $table_names as $table_name ) {
			$this->assertSame(
				$table_name,
				$wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ),
				'Installing from a subsite must create the table it is going to read.'
			);

			$this->assertStringStartsWith(
				$wpdb->base_prefix . 'oauth_pilot_',
				$table_name,
				'A subsite must not create a set of tables of its own.'
			);
		}
	}

	public function test_a_subsite_can_issue_and_resolve_its_own_tokens() {
		$client = null;
		$issued = null;

		switch_to_blog( $this->second_blog_id );

		$client = $this->create_public_client( [ 'name' => 'Subsite Agent' ] );
		$issued = $this->issue( [ 'client_id' => $client->get_client_id() ] );
		$resolved = $this->plugin->get_tokens()->get_by_value( $issued['value'] );

		restore_current_blog();

		$this->assertNotNull( $resolved, 'The site running the plugin must be able to use the shared tables.' );
		$this->assertSame( $client->get_client_id(), $resolved->get_client_id() );

		$this->assertNull(
			$this->plugin->get_tokens()->get_by_value( $issued['value'] ),
			'The main site, which does not run the plugin, still must not see its tokens.'
		);
	}

	public function test_the_schema_version_is_recorded_for_the_network() {
		$this->assertSame(
			Schema::VERSION,
			(int) get_network_option( null, Schema::OPTION_VERSION, 0 ),
			'One set of tables means one version record for the network.'
		);

		switch_to_blog( $this->second_blog_id );
		$needs_install = $this->plugin->get_schema()->needs_install();
		restore_current_blog();

		$this->assertFalse( $needs_install, 'A new site must not re-run the installer.' );
	}

	public function test_an_authorization_request_is_recorded_against_its_site() {
		global $wpdb;

		$client = $this->create_public_client();
		$service = $this->plugin->get_authorization_service();

		$validated = $service->validate_request(
			[
				'response_type' => 'code',
				'client_id' => $client->get_client_id(),
				'redirect_uri' => $client->get_redirect_uris()[0],
				'code_challenge' => \WPElevator\OAuth_Pilot\Authorization\PKCE::challenge_for( 'yet-another-verifier-value' ),
				'code_challenge_method' => 'S256',
				'resource' => $this->get_default_resource_uri(),
				'scope' => 'wp:rest',
			]
		);

		$created = $service->create_pending( $validated );
		$table = $this->plugin->get_authorizations()->get_table_name();

		$blog_id = (int) $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed internal table name.
			$wpdb->prepare( "SELECT blog_id FROM $table WHERE id = %d", $created['authorization']->get_id() )
		);

		$this->assertSame( get_current_blog_id(), $blog_id );
		$this->assertSame( Authorization::STATUS_PENDING, $created['authorization']->get_status() );
	}

	public function test_a_client_registered_on_one_site_keeps_its_secret_on_another() {
		$client = $this->create_confidential_client();

		switch_to_blog( $this->second_blog_id );
		$authenticated = $this->plugin->get_clients()->get_by_client_id( $client->get_client_id() );
		restore_current_blog();

		$this->assertNotNull( $authenticated );
		$this->assertSame( Client::TYPE_CONFIDENTIAL, $authenticated->get_type() );
		$this->assertTrue(
			$authenticated->verify_secret( $client->get_new_secret() ),
			'The shared registration keeps the credential it was issued.'
		);
	}
}
