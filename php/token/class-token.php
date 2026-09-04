<?php

namespace WPElevator\OAuth_Pilot\Token;

/**
 * A stored access or refresh token. Never carries the raw credential.
 */
class Token {

	public const TYPE_ACCESS = 'access';

	public const TYPE_REFRESH = 'refresh';

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

	public function get_type(): string {
		return (string) ( $this->row['token_type'] ?? self::TYPE_ACCESS );
	}

	public function get_client_id(): string {
		return (string) ( $this->row['client_id'] ?? '' );
	}

	public function get_user_id(): int {
		return (int) ( $this->row['user_id'] ?? 0 );
	}

	public function get_scopes(): array {
		return array_values( array_filter( explode( ' ', (string) ( $this->row['scopes'] ?? '' ) ) ) );
	}

	public function get_resource(): string {
		return (string) ( $this->row['resource'] ?? '' );
	}

	public function get_family_id(): string {
		return (string) ( $this->row['family_id'] ?? '' );
	}

	public function get_authorization_id(): ?int {
		return isset( $this->row['authorization_id'] ) ? (int) $this->row['authorization_id'] : null;
	}

	public function get_created_at(): string {
		return (string) ( $this->row['created_at'] ?? '' );
	}

	public function get_expires_at(): string {
		return (string) ( $this->row['expires_at'] ?? '' );
	}

	public function get_expires_in(): int {
		return max( 0, strtotime( $this->get_expires_at() . ' UTC' ) - time() );
	}

	public function get_last_used_at(): ?string {
		return empty( $this->row['last_used_at'] ) ? null : (string) $this->row['last_used_at'];
	}

	public function is_expired(): bool {
		return strtotime( $this->get_expires_at() . ' UTC' ) <= time();
	}

	public function is_revoked(): bool {
		return ! empty( $this->row['revoked_at'] );
	}

	public function is_consumed(): bool {
		return ! empty( $this->row['consumed_at'] );
	}

	public function is_active(): bool {
		return ! $this->is_expired() && ! $this->is_revoked() && ! $this->is_consumed();
	}

	/**
	 * A redacted record safe to pass to hooks and logs.
	 */
	public function to_array(): array {
		return [
			'id' => $this->get_id(),
			'token_type' => $this->get_type(),
			'client_id' => $this->get_client_id(),
			'user_id' => $this->get_user_id(),
			'scopes' => $this->get_scopes(),
			'resource' => $this->get_resource(),
			'family_id' => $this->get_family_id(),
			'created_at' => $this->get_created_at(),
			'expires_at' => $this->get_expires_at(),
		];
	}
}
