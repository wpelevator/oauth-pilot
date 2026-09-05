<?php

namespace WPElevator\OAuth_Pilot\Authorization;

use wpdb;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * Authorization request and code storage.
 *
 * Every state change is a single conditional UPDATE, so two concurrent
 * requests can never both advance the same row. The repository reports how
 * many rows the statement actually affected, which is the atomicity contract
 * the tests assert against.
 *
 * The table is network global. Every statement carries the current blog_id, so
 * an authorization request started on one site of a network cannot be bound,
 * approved or exchanged on another.
 */
class Authorizations {

	/**
	 * How long an unapproved authorization request stays usable.
	 */
	public const REQUEST_LIFETIME = 600;

	/**
	 * How long an issued authorization code stays usable.
	 */
	public const CODE_LIFETIME = 300;

	private wpdb $db;

	private string $table_name;

	private Tokens $tokens;

	public function __construct( wpdb $wpdb, string $table_name, Tokens $tokens ) {
		$this->db = $wpdb;
		$this->table_name = $table_name;
		$this->tokens = $tokens;
	}

	public function get_table_name(): string {
		return $this->table_name;
	}

	/**
	 * The site every query below is constrained to. Resolved per call so that a
	 * switch_to_blog() during the request moves the repository with it.
	 */
	private function get_blog_id(): int {
		return get_current_blog_id();
	}

	/**
	 * Create the pending request and return the opaque request identifier that
	 * is handed to the browser. Only its hash is stored.
	 *
	 * @return array|null [ 'authorization' => Authorization, 'request_id' => string ]
	 */
	public function create( array $args ): ?array {
		$request_id = Random::credential();

		$data = [
			'blog_id' => $this->get_blog_id(),
			'request_id_hash' => Random::hash( $request_id ),
			'code_hash' => null,
			'client_id' => (string) $args['client_id'],
			'client_snapshot' => (string) wp_json_encode( (array) ( $args['client_snapshot'] ?? [] ) ),
			'user_id' => null,
			'session_token_hash' => null,
			'redirect_uri' => (string) $args['redirect_uri'],
			'scopes' => implode( ' ', (array) ( $args['scopes'] ?? [] ) ),
			'resource' => (string) $args['resource'],
			'code_challenge' => (string) $args['code_challenge'],
			'state' => (string) ( $args['state'] ?? '' ),
			'status' => Authorization::STATUS_PENDING,
			'created_at' => current_time( 'mysql', true ),
			'expires_at' => gmdate( 'Y-m-d H:i:s', time() + self::REQUEST_LIFETIME ),
		];

		if ( ! $this->db->insert( $this->table_name, $data ) ) {
			return null;
		}

		$data['id'] = (int) $this->db->insert_id;

		return [
			'authorization' => Authorization::from_row( $data ),
			'request_id' => $request_id,
		];
	}

	public function get_by_request_id( string $request_id ): ?Authorization {
		return $this->get_by_column( 'request_id_hash', Random::hash( $request_id ) );
	}

	public function get_by_code( string $code ): ?Authorization {
		return $this->get_by_column( 'code_hash', Random::hash( $code ) );
	}

	public function get_by_id( int $id ): ?Authorization {
		$row = $this->db->get_row(
			$this->db->prepare(
				"SELECT * FROM $this->table_name WHERE id = %d AND blog_id = %d",
				$id,
				$this->get_blog_id()
			),
			ARRAY_A
		);

		return empty( $row ) ? null : Authorization::from_row( $row );
	}

	/**
	 * Atomically bind an unbound pending request to the authenticated user and
	 * session, or confirm it is already bound to the same session.
	 *
	 * Returns false when the request belongs to a different user or session,
	 * which is what stops one browser from completing another browser's flow.
	 */
	public function bind_user( Authorization $authorization, int $user_id, string $session_token ): bool {
		$updated = $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET user_id = %d, session_token_hash = %s
				WHERE id = %d
				AND blog_id = %d
				AND status = %s
				AND expires_at > %s
				AND user_id IS NULL",
				$user_id,
				Random::hash( $session_token ),
				$authorization->get_id(),
				$this->get_blog_id(),
				Authorization::STATUS_PENDING,
				current_time( 'mysql', true )
			)
		);

		if ( 1 === (int) $updated ) {
			return true;
		}

		$current = $this->get_by_id( $authorization->get_id() );

		if ( ! $current || ! $current->is_pending() || $current->is_expired() ) {
			return false;
		}

		// Already bound: only the same user in the same session may continue.
		return $current->is_bound_to_session( $user_id, $session_token );
	}

	/**
	 * Atomically turn a pending request into an authorization code.
	 *
	 * @return string|null The raw code, or null when the row was no longer
	 *                     claimable.
	 */
	public function approve( Authorization $authorization, int $user_id, array $scopes ): ?string {
		$code = Random::credential();
		$now = current_time( 'mysql', true );

		/**
		 * Filter the authorization code lifetime in seconds.
		 *
		 * @param int           $lifetime      Default lifetime.
		 * @param Authorization $authorization The authorization being approved.
		 */
		$lifetime = (int) apply_filters( 'oauth_pilot__authorization_code_lifetime', self::CODE_LIFETIME, $authorization );

		$updated = $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET code_hash = %s, scopes = %s, status = %s, approved_at = %s, expires_at = %s
				WHERE id = %d
				AND blog_id = %d
				AND status = %s
				AND user_id = %d
				AND expires_at > %s",
				Random::hash( $code ),
				implode( ' ', $scopes ),
				Authorization::STATUS_APPROVED,
				$now,
				gmdate( 'Y-m-d H:i:s', time() + max( 1, $lifetime ) ),
				$authorization->get_id(),
				$this->get_blog_id(),
				Authorization::STATUS_PENDING,
				$user_id,
				$now
			)
		);

		if ( 1 !== (int) $updated ) {
			return null;
		}

		return $code;
	}

	public function deny( Authorization $authorization, int $user_id ): bool {
		$now = current_time( 'mysql', true );

		$updated = $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET status = %s, consumed_at = %s
				WHERE id = %d
				AND blog_id = %d
				AND status = %s
				AND user_id = %d",
				Authorization::STATUS_DENIED,
				$now,
				$authorization->get_id(),
				$this->get_blog_id(),
				Authorization::STATUS_PENDING,
				$user_id
			)
		);

		return 1 === (int) $updated;
	}

	/**
	 * Atomically claim an approved code so it can be exchanged exactly once.
	 */
	public function consume( Authorization $authorization ): bool {
		$now = current_time( 'mysql', true );

		$updated = $this->db->query(
			$this->db->prepare(
				"UPDATE $this->table_name
				SET status = %s, consumed_at = %s
				WHERE id = %d
				AND blog_id = %d
				AND status = %s
				AND expires_at > %s",
				Authorization::STATUS_CONSUMED,
				$now,
				$authorization->get_id(),
				$this->get_blog_id(),
				Authorization::STATUS_APPROVED,
				$now
			)
		);

		return 1 === (int) $updated;
	}

	/**
	 * A code presented twice means it leaked. Revoke everything issued from it.
	 */
	public function handle_code_reuse( Authorization $authorization ): void {
		$this->tokens->revoke_for_authorization( $authorization->get_id() );

		/**
		 * Fires when an authorization code was presented more than once and
		 * defensive revocation ran.
		 *
		 * @param Authorization $authorization The reused authorization.
		 */
		do_action( 'oauth_pilot__authorization_code_reuse_detected', $authorization );

		Security_Events::record(
			'authorization_code_reuse',
			[
				'client_id' => $authorization->get_client_id(),
				'user_id' => $authorization->get_user_id(),
			]
		);
	}

	/**
	 * Deliberately not blog scoped: expiry is a property of the row, and
	 * bounding the shared table should not depend on which site's cron runs.
	 */
	public function delete_expired(): int {
		return (int) $this->db->query(
			$this->db->prepare(
				"DELETE FROM $this->table_name WHERE expires_at < %s",
				current_time( 'mysql', true )
			)
		);
	}

	public function count_pending(): int {
		return (int) $this->db->get_var(
			$this->db->prepare(
				"SELECT COUNT(*) FROM $this->table_name
				WHERE blog_id = %d AND status = %s AND expires_at > %s",
				$this->get_blog_id(),
				Authorization::STATUS_PENDING,
				current_time( 'mysql', true )
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

	/**
	 * For deleting the client registration itself, which is network wide.
	 */
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

	/**
	 * For a user leaving the network, not for one leaving a single site.
	 */
	public function delete_for_user_on_every_site( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare( "DELETE FROM $this->table_name WHERE user_id = %d", $user_id )
		);
	}

	private function get_by_column( string $column, string $value ): ?Authorization {
		$row = $this->db->get_row(
			$this->db->prepare(
				"SELECT * FROM $this->table_name WHERE $column = %s AND blog_id = %d",
				$value,
				$this->get_blog_id()
			),
			ARRAY_A
		);

		return empty( $row ) ? null : Authorization::from_row( $row );
	}
}
