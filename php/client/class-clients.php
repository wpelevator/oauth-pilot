<?php

namespace WPElevator\OAuth_Pilot\Client;

use wpdb;
use WPElevator\OAuth_Pilot\Authorization\Authorizations;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * The only place client rows are read or written.
 *
 * The table is network global and, unlike tokens and authorizations, lookups
 * are deliberately *not* constrained to the current site. That is the point: a
 * client registered anywhere on a network is known everywhere on it, keeps its
 * client_id and its secret, and never has to register again per site.
 *
 * The blog_id column records which site registered a client, which decides who
 * may revoke or delete the registration. It never decides where the client may
 * be used.
 */
class Clients {

	/**
	 * Client identifiers are lowercase so that case-insensitive database
	 * collations cannot collide two distinct clients.
	 */
	public const ID_PREFIX = 'op_';

	private wpdb $db;

	private string $table_name;

	private Tokens $tokens;

	private Authorizations $authorizations;

	public function __construct( wpdb $wpdb, string $table_name, Tokens $tokens, Authorizations $authorizations ) {
		$this->db = $wpdb;
		$this->table_name = $table_name;
		$this->tokens = $tokens;
		$this->authorizations = $authorizations;
	}

	public function get_table_name(): string {
		return $this->table_name;
	}

	/**
	 * Resolve a client by its identifier, from any site of the network.
	 */
	public function get_by_client_id( string $client_id ): ?Client {
		if ( '' === $client_id ) {
			return null;
		}

		$row = $this->db->get_row(
			$this->db->prepare( "SELECT * FROM $this->table_name WHERE client_id = %s", $client_id ),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			return null;
		}

		// The stored identifier is authoritative: a collation-insensitive match must not resolve.
		if ( ! hash_equals( (string) $row['client_id'], $client_id ) ) {
			return null;
		}

		return Client::from_row( $row );
	}

	public function get_by_id( int $id ): ?Client {
		$row = $this->db->get_row(
			$this->db->prepare( "SELECT * FROM $this->table_name WHERE id = %d", $id ),
			ARRAY_A
		);

		return empty( $row ) ? null : Client::from_row( $row );
	}

	/**
	 * Look up a Client ID Metadata Document client by its document URL.
	 *
	 * The hash column makes the lookup indexable despite URL length, and the
	 * stored URL is compared with hash_equals so that hash truncation or
	 * collation quirks can never resolve the wrong client.
	 */
	public function get_by_metadata_url( string $url ): ?Client {
		if ( '' === $url ) {
			return null;
		}

		$row = $this->db->get_row(
			$this->db->prepare( "SELECT * FROM $this->table_name WHERE metadata_url_hash = %s", Random::hash( $url ) ),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			return null;
		}

		if ( ! hash_equals( (string) $row['metadata_url'], $url ) ) {
			return null;
		}

		return Client::from_row( $row );
	}

	/**
	 * Persist a validated client.
	 *
	 * The caller is responsible for validating redirect URIs, grants and the
	 * authentication method; this method only generates credentials and writes
	 * the row.
	 *
	 * @param array $args {
	 *     @type string   $name                       Display name.
	 *     @type array    $redirect_uris              Exact validated URIs.
	 *     @type string   $client_type                public or confidential.
	 *     @type string   $token_endpoint_auth_method Client authentication method.
	 *     @type array    $grant_types                Allowed grants.
	 *     @type array    $scopes                     Scope ceiling.
	 *     @type string   $source                     admin or dynamic.
	 *     @type int|null $owner_user_id              Creating administrator.
	 *     @type array    $metadata                   Sanitized registration metadata.
	 * }
	 */
	public function create( array $args ): ?Client {
		$now = current_time( 'mysql', true );
		$client_id = self::ID_PREFIX . Random::hex( 32 );

		$auth_method = (string) ( $args['token_endpoint_auth_method'] ?? Client::AUTH_NONE );
		$secret = null;
		$secret_hash = null;

		if ( Client::AUTH_NONE !== $auth_method ) {
			$secret = Random::credential();
			$secret_hash = Random::hash( $secret );
		}

		$metadata_url = (string) ( $args['metadata_url'] ?? '' );

		$data = [
			'blog_id' => isset( $args['blog_id'] ) ? (int) $args['blog_id'] : get_current_blog_id(),
			'client_id' => $client_id,
			'name' => (string) ( $args['name'] ?? '' ),
			'client_type' => (string) ( $args['client_type'] ?? Client::TYPE_PUBLIC ),
			'secret_hash' => $secret_hash,
			'token_endpoint_auth_method' => $auth_method,
			'redirect_uris' => (string) wp_json_encode( array_values( (array) ( $args['redirect_uris'] ?? [] ) ) ),
			'grant_types' => implode( ' ', (array) ( $args['grant_types'] ?? [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ] ) ),
			'scopes' => implode( ' ', (array) ( $args['scopes'] ?? [] ) ),
			'source' => (string) ( $args['source'] ?? Client::SOURCE_ADMIN ),
			'owner_user_id' => empty( $args['owner_user_id'] ) ? null : (int) $args['owner_user_id'],
			'metadata' => (string) wp_json_encode( (array) ( $args['metadata'] ?? [] ) ),
			'metadata_url' => $metadata_url,
			'metadata_url_hash' => '' === $metadata_url ? '' : Random::hash( $metadata_url ),
			'metadata_fetched_at' => empty( $args['metadata_fetched_at'] ) ? null : (string) $args['metadata_fetched_at'],
			'metadata_expires_at' => empty( $args['metadata_expires_at'] ) ? null : (string) $args['metadata_expires_at'],
			'status' => Client::STATUS_ACTIVE,
			'created_at' => $now,
			'updated_at' => $now,
		];

		if ( ! $this->db->insert( $this->table_name, $data ) ) {
			return null;
		}

		$data['id'] = (int) $this->db->insert_id;

		$client = Client::from_row( $data );

		if ( isset( $secret ) ) {
			$client = $client->with_new_secret( $secret );
		}

		/**
		 * Fires after a client is registered by an administrator or through
		 * dynamic client registration.
		 *
		 * @param Client $client The registered client. Never carries a secret.
		 */
		do_action( 'oauth_pilot__client_registered', Client::from_row( $data ) );

		return $client;
	}

	/**
	 * Revoke the registration and everything issued to it, on every site.
	 *
	 * The client row is a network wide record, so revoking it is a network wide
	 * act. A site that only wants to stop trusting a client it did not register
	 * wants revoke_access_on_this_site() instead.
	 */
	public function revoke( Client $client ): bool {
		$this->tokens->revoke_for_client_on_every_site( $client->get_client_id() );
		$this->authorizations->delete_for_client_on_every_site( $client->get_client_id() );

		$updated = $this->db->update(
			$this->table_name,
			[
				'status' => Client::STATUS_REVOKED,
				'updated_at' => current_time( 'mysql', true ),
			],
			[ 'id' => $client->get_id() ]
		);

		if ( false === $updated ) {
			return false;
		}

		/**
		 * Fires after a client and all of its grants and tokens were revoked.
		 *
		 * @param Client $client The revoked client.
		 */
		do_action( 'oauth_pilot__client_revoked', $client );

		return true;
	}

	/**
	 * Delete a client. Revokes its grants and tokens on every site first.
	 */
	public function delete( Client $client ): bool {
		$this->tokens->revoke_for_client_on_every_site( $client->get_client_id() );
		$this->tokens->delete_for_client_on_every_site( $client->get_client_id() );
		$this->authorizations->delete_for_client_on_every_site( $client->get_client_id() );

		return (bool) $this->db->delete( $this->table_name, [ 'id' => $client->get_id() ] );
	}

	/**
	 * Stop trusting a client on the current site without touching the shared
	 * registration.
	 *
	 * This is what an administrator of a site that did not register the client
	 * gets. Their users' tokens die, their pending requests go, and every other
	 * site on the network is unaffected.
	 *
	 * @return int Tokens revoked on this site.
	 */
	public function revoke_access_on_this_site( Client $client ): int {
		$revoked = $this->tokens->revoke_for_client( $client->get_client_id() );

		$this->authorizations->delete_for_client( $client->get_client_id() );

		/**
		 * Fires after one site revoked its own access for a client without
		 * revoking the network wide registration.
		 *
		 * @param Client $client  The client that lost access on this site.
		 * @param int    $revoked Number of tokens revoked.
		 */
		do_action( 'oauth_pilot__client_access_revoked_on_site', $client, $revoked );

		return $revoked;
	}

	public function touch_last_used( Client $client ): void {
		$this->db->update(
			$this->table_name,
			[ 'last_used_at' => current_time( 'mysql', true ) ],
			[ 'id' => $client->get_id() ]
		);
	}

	/**
	 * Refresh a CIMD client from a newly fetched metadata document.
	 *
	 * Security-sensitive metadata changes revoke existing grants and pending
	 * authorizations. A domain reassignment must not let a new document inherit
	 * consent that users granted to the previous controller of that domain.
	 */
	public function refresh_metadata( Client $client, array $args ): bool {
		if ( ! $client->is_cimd() ) {
			return false;
		}

		$redirect_uris = array_values( (array) ( $args['redirect_uris'] ?? $client->get_redirect_uris() ) );
		$grant_types = array_values( (array) ( $args['grant_types'] ?? $client->get_grant_types() ) );
		$security_metadata_changed = $this->sets_differ( $redirect_uris, $client->get_redirect_uris() )
			|| $this->sets_differ( $grant_types, $client->get_grant_types() );

		$updated = $this->db->update(
			$this->table_name,
			[
				'name' => (string) ( $args['name'] ?? $client->get_name() ),
				'redirect_uris' => (string) wp_json_encode( $redirect_uris ),
				'grant_types' => implode( ' ', $grant_types ),
				'metadata' => (string) wp_json_encode( (array) ( $args['metadata'] ?? $client->get_metadata() ) ),
				'metadata_fetched_at' => (string) ( $args['metadata_fetched_at'] ?? current_time( 'mysql', true ) ),
				'metadata_expires_at' => (string) ( $args['metadata_expires_at'] ?? gmdate( 'Y-m-d H:i:s', time() + (int) ( $args['cache_ttl'] ?? 0 ) ) ),
				'updated_at' => current_time( 'mysql', true ),
			],
			[ 'id' => $client->get_id() ]
		);

		if ( false === $updated ) {
			return false;
		}

		if ( $security_metadata_changed ) {
			// The document is shared, so a domain reassignment invalidates the
			// consent users granted on every site, not only on this one.
			$this->tokens->revoke_for_client_on_every_site( $client->get_client_id() );
			$this->authorizations->delete_for_client_on_every_site( $client->get_client_id() );

			/**
			 * Fires after a CIMD refresh changed redirect URIs or grant types and
			 * existing grants were defensively revoked.
			 *
			 * @param Client $client The client whose security metadata changed.
			 */
			do_action( 'oauth_pilot__cimd_security_metadata_changed', $client );
		}

		return true;
	}

	private function sets_differ( array $left, array $right ): bool {
		$left = array_values( array_unique( array_map( 'strval', $left ) ) );
		$right = array_values( array_unique( array_map( 'strval', $right ) ) );

		sort( $left );
		sort( $right );

		return $left !== $right;
	}

	/**
	 * The exact count of active dynamically registered clients.
	 *
	 * This quota is enforced with a real query rather than a best-effort
	 * counter because it is the one that bounds the table. The table is shared
	 * by the network, so the count is too: the quota exists to bound storage,
	 * and a per-site count would bound nothing.
	 */
	public function count_active_dynamic(): int {
		return (int) $this->db->get_var(
			$this->db->prepare(
				"SELECT COUNT(*) FROM $this->table_name WHERE source = %s AND status = %s",
				Client::SOURCE_DYNAMIC,
				Client::STATUS_ACTIVE
			)
		);
	}

	/**
	 * The exact count of active Client ID Metadata Document clients.
	 */
	public function count_active_cimd(): int {
		return (int) $this->db->get_var(
			$this->db->prepare(
				"SELECT COUNT(*) FROM $this->table_name WHERE source = %s AND status = %s",
				Client::SOURCE_CIMD,
				Client::STATUS_ACTIVE
			)
		);
	}

	public function count( array $args = [] ): int {
		$where = $this->build_where( $args );

		return (int) $this->db->get_var( "SELECT COUNT(*) FROM $this->table_name $where" );
	}

	/**
	 * @return Client[]
	 */
	public function find( array $args = [] ): array {
		$where = $this->build_where( $args );
		$limit = isset( $args['limit'] ) ? (int) $args['limit'] : 100;
		$offset = isset( $args['offset'] ) ? (int) $args['offset'] : 0;

		$rows = $this->db->get_results(
			"SELECT * FROM $this->table_name $where ORDER BY created_at DESC, id DESC LIMIT $limit OFFSET $offset",
			ARRAY_A
		);

		return array_map( [ Client::class, 'from_row' ], (array) $rows );
	}

	/**
	 * Self-registered clients (dynamic and CIMD) that were registered but
	 * never used, and inactive ones that no longer hold tokens.
	 *
	 * The token join spans the whole network on purpose: a client is only
	 * stale when no site is still using it. Every site's cron runs this over
	 * the shared table, which is harmless because it is idempotent.
	 *
	 * @return int Number of deleted clients.
	 */
	public function delete_stale_ephemeral( int $unused_seconds, int $inactive_seconds ): int {
		$tokens_table = $this->tokens->get_table_name();
		$sources = [ Client::SOURCE_DYNAMIC, Client::SOURCE_CIMD ];
		$source_placeholders = implode( ', ', array_fill( 0, count( $sources ), '%s' ) );

		$never_used = (array) $this->db->get_col(
			$this->db->prepare(
				"SELECT id FROM $this->table_name
				WHERE source IN ( $source_placeholders )
				AND last_used_at IS NULL
				AND created_at < %s",
				array_merge( $sources, [ gmdate( 'Y-m-d H:i:s', time() - $unused_seconds ) ] )
			)
		);

		$inactive = (array) $this->db->get_col(
			$this->db->prepare(
				"SELECT c.id FROM $this->table_name AS c
				LEFT JOIN $tokens_table AS t ON t.client_id = c.client_id AND t.revoked_at IS NULL AND t.expires_at > %s
				WHERE c.source IN ( $source_placeholders )
				AND c.last_used_at IS NOT NULL
				AND c.last_used_at < %s
				AND t.id IS NULL",
				array_merge(
					[ current_time( 'mysql', true ) ],
					$sources,
					[ gmdate( 'Y-m-d H:i:s', time() - $inactive_seconds ) ]
				)
			)
		);

		$deleted = 0;

		foreach ( array_unique( array_map( 'intval', array_merge( $never_used, $inactive ) ) ) as $id ) {
			$client = $this->get_by_id( $id );

			if ( $client && $this->delete( $client ) ) {
				++$deleted;
			}
		}

		return $deleted;
	}

	private function build_where( array $args ): string {
		$conditions = [];

		if ( ! empty( $args['status'] ) ) {
			$conditions[] = $this->db->prepare( 'status = %s', $args['status'] );
		}

		if ( ! empty( $args['source'] ) ) {
			$conditions[] = $this->db->prepare( 'source = %s', $args['source'] );
		}

		// Only for listing by owner. Never pass this when resolving a client.
		if ( isset( $args['blog_id'] ) ) {
			$conditions[] = $this->db->prepare( 'blog_id = %d', (int) $args['blog_id'] );
		}

		if ( ! empty( $args['search'] ) ) {
			$conditions[] = $this->db->prepare(
				'(name LIKE %s OR client_id LIKE %s)',
				'%' . $this->db->esc_like( $args['search'] ) . '%',
				'%' . $this->db->esc_like( $args['search'] ) . '%'
			);
		}

		if ( empty( $conditions ) ) {
			return '';
		}

		return 'WHERE ' . implode( ' AND ', $conditions );
	}
}
