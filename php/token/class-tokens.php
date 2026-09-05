<?php

namespace WPElevator\OAuth_Pilot\Token;

use wpdb;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Security_Events;

/**
 * Access and refresh token storage.
 *
 * Both token types share this table because they share every column that
 * matters and every revocation query. Only SHA-256 hashes are stored.
 *
 * The table is network global, so a token is only meaningful on the site that
 * issued it: every statement below is constrained to the current blog_id. The
 * handful of operations that must span the network say so in their name.
 */
class Tokens {

	public const ACCESS_LIFETIME = HOUR_IN_SECONDS;

	public const REFRESH_LIFETIME = 30 * DAY_IN_SECONDS;

	/**
	 * How stale last_used_at may get before another write is worth it.
	 */
	private const LAST_USED_THROTTLE = 300;

	private wpdb $db;

	private string $table_name;

	public function __construct( wpdb $wpdb, string $table_name ) {
		$this->db = $wpdb;
		$this->table_name = $table_name;
	}

	public function get_table_name(): string {
		return $this->table_name;
	}

	/**
	 * The site every query below is constrained to.
	 *
	 * Resolved per call rather than cached in the constructor: the plugin is
	 * built once per request, and a switch_to_blog() during that request must
	 * move the repository with it.
	 */
	private function get_blog_id(): int {
		return get_current_blog_id();
	}

	public function new_family_id(): string {
		return Random::hex( 16 );
	}

	/**
	 * Issue one token and return it together with the raw credential, which is
	 * the only moment the raw value exists.
	 *
	 * @return array|null [ 'token' => Token, 'value' => string ]
	 */
	public function issue( array $args ): ?array {
		$value = Random::credential();
		$type = (string) ( $args['token_type'] ?? Token::TYPE_ACCESS );

		$lifetime = isset( $args['lifetime'] )
			? (int) $args['lifetime']
			: ( Token::TYPE_REFRESH === $type ? self::REFRESH_LIFETIME : self::ACCESS_LIFETIME );

		$data = [
			'blog_id' => $this->get_blog_id(),
			'token_type' => $type,
			'token_hash' => Random::hash( $value ),
			'client_id' => (string) $args['client_id'],
			'user_id' => (int) $args['user_id'],
			'scopes' => implode( ' ', (array) ( $args['scopes'] ?? [] ) ),
			'resource' => (string) $args['resource'],
			'family_id' => (string) ( $args['family_id'] ?? $this->new_family_id() ),
			'parent_id' => empty( $args['parent_id'] ) ? null : (int) $args['parent_id'],
			'authorization_id' => empty( $args['authorization_id'] ) ? null : (int) $args['authorization_id'],
			'created_at' => current_time( 'mysql', true ),
			'expires_at' => gmdate( 'Y-m-d H:i:s', time() + max( 1, $lifetime ) ),
		];

		if ( ! $this->db->insert( $this->table_name, $data ) ) {
			return null;
		}

		$data['id'] = (int) $this->db->insert_id;

		$token = Token::from_row( $data );

		/**
		 * Fires after a token is issued.
		 *
		 * @param Token $token A redacted record. The raw credential is never passed.
		 */
		do_action( 'oauth_pilot__token_issued', $token );

		return [
			'token' => $token,
			'value' => $value,
		];
	}

	/**
	 * Resolve a presented credential.
	 *
	 * The blog condition is what stops a token minted on one site of a network
	 * from authenticating against another. It is not a filter on the result: a
	 * foreign token does not resolve at all.
	 */
	public function get_by_value( string $value, ?string $type = null ): ?Token {
		if ( '' === $value ) {
			return null;
		}

		$row = $this->db->get_row(
			$this->db->prepare(
				"SELECT * FROM $this->table_name WHERE token_hash = %s AND blog_id = %d",
				Random::hash( $value ),
				$this->get_blog_id()
			),
			ARRAY_A
		);

		if ( empty( $row ) ) {
			return null;
		}

		if ( isset( $type ) && $type !== $row['token_type'] ) {
			return null;
		}

		return Token::from_row( $row );
	}

	public function get_by_id( int $id ): ?Token {
		$row = $this->db->get_row(
			$this->db->prepare(
				"SELECT * FROM $this->table_name WHERE id = %d AND blog_id = %d",
				$id,
				$this->get_blog_id()
			),
			ARRAY_A
		);

		return empty( $row ) ? null : Token::from_row( $row );
	}

	/**
	 * Atomically consume a refresh token.
	 *
	 * Claiming the presented token is the only step that has to be atomic, so
	 * this is a single conditional UPDATE rather than a SQL transaction. An
	 * explicit transaction here would also implicitly commit the outer
	 * transaction the WordPress test case wraps every test in.
	 *
	 * @return bool True when this caller claimed it, false when someone else did.
	 */
	public function consume_refresh_token( Token $token ): bool {
		$now = current_time( 'mysql', true );

		$updated = $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET consumed_at = %s
				WHERE id = %d
				AND blog_id = %d
				AND token_type = %s
				AND consumed_at IS NULL
				AND revoked_at IS NULL
				AND expires_at > %s",
				$now,
				$token->get_id(),
				$this->get_blog_id(),
				Token::TYPE_REFRESH,
				$now
			)
		);

		return 1 === (int) $updated;
	}

	/**
	 * A consumed refresh token presented again means the credential leaked.
	 */
	public function handle_refresh_reuse( Token $token ): void {
		$this->revoke_family( $token->get_family_id() );

		/**
		 * Fires when a refresh token was presented after it had been used and
		 * the whole family was revoked.
		 *
		 * @param Token $token The reused token.
		 */
		do_action( 'oauth_pilot__refresh_token_reuse_detected', $token );

		Security_Events::record(
			'refresh_token_reuse',
			[
				'client_id' => $token->get_client_id(),
				'user_id' => $token->get_user_id(),
				'family_id' => $token->get_family_id(),
			]
		);
	}

	public function revoke( Token $token ): bool {
		$updated = $this->db->update(
			$this->table_name,
			[ 'revoked_at' => current_time( 'mysql', true ) ],
			[
				'id' => $token->get_id(),
				'blog_id' => $this->get_blog_id(),
				'revoked_at' => null,
			]
		);

		if ( $updated ) {
			/**
			 * Fires when a token or a token family was revoked.
			 *
			 * @param Token $token A redacted record.
			 */
			do_action( 'oauth_pilot__token_revoked', $token );
		}

		return (bool) $updated;
	}

	public function revoke_family( string $family_id ): int {
		if ( '' === $family_id ) {
			return 0;
		}

		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE family_id = %s AND blog_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$family_id,
				$this->get_blog_id()
			)
		);
	}

	public function revoke_for_authorization( int $authorization_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE authorization_id = %d AND blog_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$authorization_id,
				$this->get_blog_id()
			)
		);
	}

	/**
	 * Revoke a client's tokens on this site only.
	 *
	 * This is what a site administrator gets for a client another site of the
	 * network registered: their site stops trusting it, everyone else's keeps
	 * working.
	 */
	public function revoke_for_client( string $client_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE client_id = %s AND blog_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$client_id,
				$this->get_blog_id()
			)
		);
	}

	/**
	 * Revoke a client's tokens everywhere. Only for revoking the registration
	 * itself, which is a network wide record.
	 */
	public function revoke_for_client_on_every_site( string $client_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE client_id = %s AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$client_id
			)
		);
	}

	public function revoke_for_user( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE user_id = %d AND blog_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$user_id,
				$this->get_blog_id()
			)
		);
	}

	/**
	 * Revoke one user's tokens everywhere. For a user leaving the network, not
	 * for one leaving a single site.
	 */
	public function revoke_for_user_on_every_site( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name SET revoked_at = %s
				WHERE user_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$user_id
			)
		);
	}

	/**
	 * Revoke one user's grant of one client for one resource.
	 */
	public function revoke_grant( int $user_id, string $client_id, string $resource_uri ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET revoked_at = %s
				WHERE user_id = %d AND client_id = %s AND resource = %s
				AND blog_id = %d AND revoked_at IS NULL",
				current_time( 'mysql', true ),
				$user_id,
				$client_id,
				$resource_uri,
				$this->get_blog_id()
			)
		);
	}

	public function delete_for_client( string $client_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"DELETE FROM $this->table_name WHERE client_id = %s AND blog_id = %d",
				$client_id,
				$this->get_blog_id()
			)
		);
	}

	public function delete_for_client_on_every_site( string $client_id ): int {
		return (int) $this->db->query(
			$this->db->prepare( "DELETE FROM $this->table_name WHERE client_id = %s", $client_id )
		);
	}

	public function delete_for_user( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"DELETE FROM $this->table_name WHERE user_id = %d AND blog_id = %d",
				$user_id,
				$this->get_blog_id()
			)
		);
	}

	public function delete_for_user_on_every_site( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare( "DELETE FROM $this->table_name WHERE user_id = %d", $user_id )
		);
	}

	/**
	 * Record use of an access token, but not on every single request.
	 */
	public function touch_last_used( Token $token ): void {
		$last_used = $token->get_last_used_at();

		if ( isset( $last_used ) && strtotime( $last_used . ' UTC' ) > time() - self::LAST_USED_THROTTLE ) {
			return;
		}

		$this->db->update(
			$this->table_name,
			[ 'last_used_at' => current_time( 'mysql', true ) ],
			[
				'id' => $token->get_id(),
				'blog_id' => $this->get_blog_id(),
			]
		);
	}

	/**
	 * Active tokens for a user on this site, newest first.
	 *
	 * @return Token[]
	 */
	public function get_active_for_user( int $user_id ): array {
		$rows = $this->db->get_results(
			$this->db->prepare(
				"SELECT * FROM $this->table_name
				WHERE user_id = %d AND blog_id = %d AND revoked_at IS NULL AND expires_at > %s
				ORDER BY created_at DESC",
				$user_id,
				$this->get_blog_id(),
				current_time( 'mysql', true )
			),
			ARRAY_A
		);

		return array_map( [ Token::class, 'from_row' ], (array) $rows );
	}

	/**
	 * The user's active grants on this site, one per client and resource pair.
	 */
	public function get_grants_for_user( int $user_id ): array {
		$grants = [];

		foreach ( $this->get_active_for_user( $user_id ) as $token ) {
			$key = $token->get_client_id() . '|' . $token->get_resource();

			if ( ! isset( $grants[ $key ] ) ) {
				$grants[ $key ] = [
					'client_id' => $token->get_client_id(),
					'resource' => $token->get_resource(),
					'scopes' => [],
					'created_at' => $token->get_created_at(),
					'last_used_at' => $token->get_last_used_at(),
					'tokens' => 0,
				];
			}

			$grants[ $key ]['scopes'] = array_values( array_unique( array_merge( $grants[ $key ]['scopes'], $token->get_scopes() ) ) );
			++$grants[ $key ]['tokens'];

			$last_used = $token->get_last_used_at();

			if ( isset( $last_used ) && ( empty( $grants[ $key ]['last_used_at'] ) || $last_used > $grants[ $key ]['last_used_at'] ) ) {
				$grants[ $key ]['last_used_at'] = $last_used;
			}
		}

		return array_values( $grants );
	}

	/**
	 * Whether the user already granted this client at least these scopes for
	 * this resource. This is what remembered consent is derived from, instead
	 * of a separate consent table.
	 *
	 * Blog scoped, so consent granted on one site of a network is never
	 * silently reused on another: the same scope names mean different things
	 * against different capability sets.
	 */
	public function has_active_grant( int $user_id, string $client_id, string $resource_uri, array $scopes ): bool {
		$rows = $this->db->get_col(
			$this->db->prepare(
				"SELECT scopes FROM $this->table_name
				WHERE user_id = %d AND client_id = %s AND resource = %s AND blog_id = %d
				AND revoked_at IS NULL AND expires_at > %s",
				$user_id,
				$client_id,
				$resource_uri,
				$this->get_blog_id(),
				current_time( 'mysql', true )
			)
		);

		foreach ( (array) $rows as $granted ) {
			$granted_scopes = array_values( array_filter( explode( ' ', (string) $granted ) ) );

			if ( empty( array_diff( $scopes, $granted_scopes ) ) ) {
				return true;
			}
		}

		return false;
	}

	public function count_active(): int {
		return (int) $this->db->get_var(
			$this->db->prepare(
				"SELECT COUNT(*) FROM $this->table_name
				WHERE blog_id = %d AND revoked_at IS NULL AND expires_at > %s",
				$this->get_blog_id(),
				current_time( 'mysql', true )
			)
		);
	}

	/**
	 * Whether any site still holds a live token for this client. Used when
	 * deciding whether a network wide client registration is still in use.
	 */
	public function has_active_for_client_on_any_site( string $client_id ): bool {
		return (bool) $this->db->get_var(
			$this->db->prepare(
				"SELECT 1 FROM $this->table_name
				WHERE client_id = %s AND revoked_at IS NULL AND expires_at > %s
				LIMIT 1",
				$client_id,
				current_time( 'mysql', true )
			)
		);
	}

	/**
	 * Remove tokens that expired long enough ago that reuse detection no
	 * longer needs them.
	 *
	 * Deliberately not blog scoped. Expiry is a property of the row, not of a
	 * site, and bounding the shared table should not depend on which site's
	 * cron happens to run.
	 */
	public function delete_expired(): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"DELETE FROM $this->table_name WHERE expires_at < %s",
				gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) )
			)
		);
	}
}
