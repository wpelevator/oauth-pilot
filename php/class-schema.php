<?php

namespace WPElevator\OAuth_Pilot;

use wpdb;

/**
 * Installs and upgrades the three OAuth Pilot tables.
 *
 * The tables are network global: they use $wpdb->base_prefix, so a multisite
 * network has one set of them, not one set per site. Client registrations are
 * therefore shared across the network and a client never has to register again
 * per site, which is the whole point of the shared table.
 *
 * Sharing the storage does not share the authority. WordPress keeps identity
 * global (wp_users) but capabilities per site, and this plugin follows that
 * split: every authorization and token row carries the blog_id it was issued
 * for and every read of those two tables is filtered by it. A token minted on
 * one site is invisible to every other site.
 *
 * install() is a plain public method on purpose. Activation hooks never run in
 * the PHPUnit environment, so the installer has to be reachable from tests,
 * WP-CLI and a schema version check, not only from register_activation_hook().
 */
class Schema {

	public const VERSION = 3;

	public const OPTION_VERSION = 'oauth_pilot_schema_version';

	public const TABLE_CLIENTS = 'oauth_pilot_clients';

	public const TABLE_AUTHORIZATIONS = 'oauth_pilot_authorizations';

	public const TABLE_TOKENS = 'oauth_pilot_tokens';

	private wpdb $db;

	public function __construct( wpdb $wpdb ) {
		$this->db = $wpdb;
	}

	/**
	 * Table names use base_prefix so every site on a network shares one table.
	 */
	public function get_table_name( string $table ): string {
		return $this->db->base_prefix . $table;
	}

	public function get_table_names(): array {
		return array_map(
			[ $this, 'get_table_name' ],
			[ self::TABLE_CLIENTS, self::TABLE_AUTHORIZATIONS, self::TABLE_TOKENS ]
		);
	}

	/**
	 * Create or upgrade the tables. Idempotent.
	 */
	public function install(): void {
		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		$installed_version = $this->get_installed_version();
		$charset_collate = $this->db->get_charset_collate();

		foreach ( $this->get_table_definitions( $charset_collate ) as $sql ) {
			dbDelta( $sql );
		}

		if ( $installed_version > 0 && $installed_version < 3 ) {
			$this->adopt_rows_written_before_blog_id();
		}

		// The tables are network wide, so the version that describes them is too.
		update_network_option( null, self::OPTION_VERSION, self::VERSION );
	}

	/**
	 * Give existing tokens and grants the site they were issued for.
	 *
	 * A site's own prefix and its network's base prefix are the same string on
	 * single site, and on the main site of a network, so the table the network
	 * wide name now resolves to is the very table that site was already using.
	 * Its rows are still there after the upgrade, with blog_id defaulted to 0
	 * by the new column.
	 *
	 * Zero matches no site. Left alone, every token and pending authorization
	 * that existed before the upgrade would stop resolving and every live
	 * connection would quietly break, which looks like the credentials were
	 * revoked rather than like a schema change. Those rows can only have been
	 * written by the site whose prefix equals the base prefix, so the main site
	 * adopts them.
	 *
	 * Subsites of a network kept their rows in their own prefixed tables, which
	 * this release stops reading. Nothing here can reach them.
	 */
	private function adopt_rows_written_before_blog_id(): void {
		$main_site_id = is_multisite() ? (int) get_main_site_id() : get_current_blog_id();

		// Only clients use 0 as a real value, meaning the network owns them.
		foreach ( [ self::TABLE_TOKENS, self::TABLE_AUTHORIZATIONS ] as $table ) {
			$this->db->update(
				$this->get_table_name( $table ),
				[ 'blog_id' => $main_site_id ],
				[ 'blog_id' => 0 ],
				[ '%d' ],
				[ '%d' ]
			);
		}
	}

	/**
	 * Whether the stored schema version is older than the code.
	 */
	public function needs_install(): bool {
		return $this->get_installed_version() < self::VERSION;
	}

	/**
	 * The schema version this installation last recorded.
	 *
	 * The version describes network wide tables, so it is a network option. It
	 * was a per-site option before those tables were shared, and on multisite
	 * the two are different rows: a network option lives in sitemeta, and the
	 * old value is still sitting in the main site's options table. Reading only
	 * the new location would report a fresh install, skip the pass that gives
	 * pre-upgrade rows their site, and silently strand every token the main
	 * site had issued.
	 *
	 * On single site the two functions read the same row and the fallback never
	 * comes into play.
	 */
	private function get_installed_version(): int {
		$version = (int) get_network_option( null, self::OPTION_VERSION, 0 );

		if ( 0 === $version && is_multisite() ) {
			$version = (int) get_blog_option( get_main_site_id(), self::OPTION_VERSION, 0 );
		}

		return $version;
	}

	public function install_if_needed(): void {
		if ( $this->needs_install() ) {
			$this->install();
		}
	}

	public function uninstall(): void {
		foreach ( $this->get_table_names() as $table_name ) {
			$this->db->query( "DROP TABLE IF EXISTS $table_name" );
		}

		delete_network_option( null, self::OPTION_VERSION );
	}

	/**
	 * Drop every row belonging to one site.
	 *
	 * Called when a site is deleted from a network. The tables survive because
	 * other sites still use them, so the rows have to go individually.
	 *
	 * Clients registered by the deleted site are only removed when nothing else
	 * on the network still holds a live token for them. A client that other
	 * sites are actively using outlives its registering site as a network owned
	 * registration (blog_id 0) rather than breaking those integrations.
	 *
	 * @return array Deleted row counts, keyed by table.
	 */
	public function delete_site_data( int $blog_id ): array {
		if ( $blog_id <= 0 ) {
			return [];
		}

		$tokens = $this->get_table_name( self::TABLE_TOKENS );
		$authorizations = $this->get_table_name( self::TABLE_AUTHORIZATIONS );
		$clients = $this->get_table_name( self::TABLE_CLIENTS );

		$deleted = [
			'tokens' => (int) $this->db->delete( $tokens, [ 'blog_id' => $blog_id ], [ '%d' ] ),
			'authorizations' => (int) $this->db->delete( $authorizations, [ 'blog_id' => $blog_id ], [ '%d' ] ),
		];

		$deleted['clients'] = (int) $this->db->query(
			$this->db->prepare(
				"DELETE c FROM $clients AS c
				LEFT JOIN $tokens AS t ON t.client_id = c.client_id
				WHERE c.blog_id = %d
				AND t.id IS NULL",
				$blog_id
			)
		);

		// Whatever survived is still in use elsewhere, so the network adopts it.
		$this->db->update( $clients, [ 'blog_id' => 0 ], [ 'blog_id' => $blog_id ], [ '%d' ], [ '%d' ] );

		return $deleted;
	}

	private function get_table_definitions( string $charset_collate ): array {
		$clients = $this->get_table_name( self::TABLE_CLIENTS );
		$authorizations = $this->get_table_name( self::TABLE_AUTHORIZATIONS );
		$tokens = $this->get_table_name( self::TABLE_TOKENS );

		return [
			"CREATE TABLE $clients (
				id bigint(20) unsigned NOT NULL auto_increment,
				blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
				client_id varchar(191) NOT NULL,
				name text NOT NULL,
				client_type varchar(20) NOT NULL,
				secret_hash char(64) DEFAULT NULL,
				token_endpoint_auth_method varchar(32) NOT NULL,
				redirect_uris longtext NOT NULL,
				grant_types varchar(191) NOT NULL,
				scopes text NOT NULL,
				source varchar(20) NOT NULL,
				owner_user_id bigint(20) unsigned DEFAULT NULL,
				metadata longtext NOT NULL,
				metadata_url longtext NOT NULL,
				metadata_url_hash char(64) NOT NULL DEFAULT '',
				metadata_fetched_at datetime DEFAULT NULL,
				metadata_expires_at datetime DEFAULT NULL,
				status varchar(20) NOT NULL,
				created_at datetime NOT NULL,
				updated_at datetime NOT NULL,
				last_used_at datetime DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY client_id (client_id),
				KEY status_source (status,source),
				KEY metadata_url_hash (metadata_url_hash),
				KEY blog_id (blog_id),
				KEY created_at (created_at)
			) $charset_collate;",

			"CREATE TABLE $authorizations (
				id bigint(20) unsigned NOT NULL auto_increment,
				blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
				request_id_hash char(64) NOT NULL,
				code_hash char(64) DEFAULT NULL,
				client_id varchar(191) NOT NULL,
				client_snapshot longtext NOT NULL,
				user_id bigint(20) unsigned DEFAULT NULL,
				session_token_hash char(64) DEFAULT NULL,
				redirect_uri text NOT NULL,
				scopes text NOT NULL,
				resource text NOT NULL,
				code_challenge varchar(191) NOT NULL,
				state text NOT NULL,
				status varchar(20) NOT NULL,
				created_at datetime NOT NULL,
				expires_at datetime NOT NULL,
				approved_at datetime DEFAULT NULL,
				consumed_at datetime DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY request_id_hash (request_id_hash),
				UNIQUE KEY code_hash (code_hash),
				KEY blog_client (blog_id,client_id),
				KEY expires_at (expires_at)
			) $charset_collate;",

			"CREATE TABLE $tokens (
				id bigint(20) unsigned NOT NULL auto_increment,
				blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
				token_type varchar(10) NOT NULL,
				token_hash char(64) NOT NULL,
				client_id varchar(191) NOT NULL,
				user_id bigint(20) unsigned NOT NULL,
				scopes text NOT NULL,
				resource text NOT NULL,
				family_id char(32) NOT NULL,
				parent_id bigint(20) unsigned DEFAULT NULL,
				authorization_id bigint(20) unsigned DEFAULT NULL,
				created_at datetime NOT NULL,
				expires_at datetime NOT NULL,
				last_used_at datetime DEFAULT NULL,
				consumed_at datetime DEFAULT NULL,
				revoked_at datetime DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY family_id (family_id),
				KEY blog_client_user (blog_id,client_id,user_id),
				KEY blog_user (blog_id,user_id),
				KEY client_id (client_id),
				KEY expires_at (expires_at),
				KEY authorization_id (authorization_id)
			) $charset_collate;",
		];
	}
}
