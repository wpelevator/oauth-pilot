<?php

namespace WPElevator\OAuth_Pilot;

use wpdb;

/**
 * Installs and upgrades the three OAuth Pilot tables.
 *
 * install() is a plain public method on purpose. Activation hooks never run in
 * the PHPUnit environment, so the installer has to be reachable from tests,
 * WP-CLI, new multisite sites and a schema version check, not only from
 * register_activation_hook().
 */
class Schema {

	public const VERSION = 2;

	public const OPTION_VERSION = 'oauth_pilot_schema_version';

	public const TABLE_CLIENTS = 'oauth_pilot_clients';

	public const TABLE_AUTHORIZATIONS = 'oauth_pilot_authorizations';

	public const TABLE_TOKENS = 'oauth_pilot_tokens';

	private wpdb $db;

	public function __construct( wpdb $wpdb ) {
		$this->db = $wpdb;
	}

	public function get_table_name( string $table ): string {
		return $this->db->prefix . $table;
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

		$charset_collate = $this->db->get_charset_collate();

		foreach ( $this->get_table_definitions( $charset_collate ) as $sql ) {
			dbDelta( $sql );
		}

		update_option( self::OPTION_VERSION, self::VERSION, false );
	}

	/**
	 * Whether the stored schema version is older than the code.
	 */
	public function needs_install(): bool {
		return (int) get_option( self::OPTION_VERSION, 0 ) < self::VERSION;
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

		delete_option( self::OPTION_VERSION );
	}

	private function get_table_definitions( string $charset_collate ): array {
		$clients = $this->get_table_name( self::TABLE_CLIENTS );
		$authorizations = $this->get_table_name( self::TABLE_AUTHORIZATIONS );
		$tokens = $this->get_table_name( self::TABLE_TOKENS );

		return [
			"CREATE TABLE $clients (
				id bigint(20) unsigned NOT NULL auto_increment,
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
				KEY created_at (created_at)
			) $charset_collate;",

			"CREATE TABLE $authorizations (
				id bigint(20) unsigned NOT NULL auto_increment,
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
				KEY client_id (client_id),
				KEY expires_at (expires_at)
			) $charset_collate;",

			"CREATE TABLE $tokens (
				id bigint(20) unsigned NOT NULL auto_increment,
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
				KEY client_user (client_id,user_id),
				KEY expires_at (expires_at),
				KEY authorization_id (authorization_id)
			) $charset_collate;",
		];
	}
}
