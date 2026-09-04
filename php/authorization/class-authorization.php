<?php

namespace WPElevator\OAuth_Pilot\Authorization;

use WPElevator\OAuth_Pilot\Random;

/**
 * One authorization flow: created as a pending request by the anonymous
 * authorize endpoint, bound to a user by the consent controller, and turned
 * into an authorization code on approval.
 */
class Authorization {

	public const STATUS_PENDING = 'pending';

	public const STATUS_APPROVED = 'approved';

	public const STATUS_CONSUMED = 'consumed';

	public const STATUS_DENIED = 'denied';

	private array $row;

	private function __construct( array $row ) {
		$this->row = $row;
	}

	public static function from_row( array $row ): self {
		return new self( $row );
	}

	public function get_id(): int {
		return (int) ( $this->row['id'] ?? 0 );
	}

	public function get_client_id(): string {
		return (string) ( $this->row['client_id'] ?? '' );
	}

	public function get_client_snapshot(): array {
		$snapshot = json_decode( (string) ( $this->row['client_snapshot'] ?? '{}' ), true );

		return is_array( $snapshot ) ? $snapshot : [];
	}

	public function get_client_name(): string {
		$snapshot = $this->get_client_snapshot();

		return (string) ( $snapshot['name'] ?? $this->get_client_id() );
	}

	public function get_user_id(): ?int {
		return isset( $this->row['user_id'] ) ? (int) $this->row['user_id'] : null;
	}

	public function get_redirect_uri(): string {
		return (string) ( $this->row['redirect_uri'] ?? '' );
	}

	public function get_scopes(): array {
		return array_values( array_filter( explode( ' ', (string) ( $this->row['scopes'] ?? '' ) ) ) );
	}

	public function get_resource(): string {
		return (string) ( $this->row['resource'] ?? '' );
	}

	public function get_code_challenge(): string {
		return (string) ( $this->row['code_challenge'] ?? '' );
	}

	public function get_state(): string {
		return (string) ( $this->row['state'] ?? '' );
	}

	public function get_status(): string {
		return (string) ( $this->row['status'] ?? self::STATUS_PENDING );
	}

	public function is_pending(): bool {
		return self::STATUS_PENDING === $this->get_status();
	}

	public function is_consumed(): bool {
		return self::STATUS_CONSUMED === $this->get_status();
	}

	public function get_expires_at(): string {
		return (string) ( $this->row['expires_at'] ?? '' );
	}

	public function is_expired(): bool {
		return strtotime( $this->get_expires_at() . ' UTC' ) < time();
	}

	public function is_bound_to_session( int $user_id, string $session_token ): bool {
		if ( $this->get_user_id() !== $user_id ) {
			return false;
		}

		$stored = (string) ( $this->row['session_token_hash'] ?? '' );

		return '' !== $stored && Random::hash_equals( $stored, $session_token );
	}

	public function is_unbound(): bool {
		return null === $this->get_user_id();
	}
}
