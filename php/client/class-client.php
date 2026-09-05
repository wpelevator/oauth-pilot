<?php

namespace WPElevator\OAuth_Pilot\Client;

use WPElevator\OAuth_Pilot\Random;

/**
 * A registered OAuth client.
 *
 * Immutable except for the one-time plaintext secret, which only the instance
 * returned by Clients::create() carries and which is never persisted.
 */
class Client {

	public const TYPE_PUBLIC = 'public';

	public const TYPE_CONFIDENTIAL = 'confidential';

	public const AUTH_NONE = 'none';

	public const AUTH_BASIC = 'client_secret_basic';

	public const AUTH_POST = 'client_secret_post';

	public const SOURCE_ADMIN = 'admin';

	public const SOURCE_DYNAMIC = 'dynamic';

	public const SOURCE_CIMD = 'cimd';

	public const STATUS_ACTIVE = 'active';

	public const STATUS_REVOKED = 'revoked';

	public const GRANT_AUTHORIZATION_CODE = 'authorization_code';

	public const GRANT_REFRESH_TOKEN = 'refresh_token';

	private array $row;

	private ?string $new_secret = null;

	private function __construct( array $row ) {
		$this->row = $row;
	}

	public static function from_row( array $row ): self {
		return new self( $row );
	}

	public function with_new_secret( string $secret ): self {
		$client = new self( $this->row );
		$client->new_secret = $secret;

		return $client;
	}

	public function get_id(): int {
		return (int) ( $this->row['id'] ?? 0 );
	}

	public function get_client_id(): string {
		return (string) ( $this->row['client_id'] ?? '' );
	}

	/**
	 * The site that registered this client, or 0 when the network owns it.
	 *
	 * A registration is network wide: this records where it came from and who
	 * may revoke or delete it, never where it may be used.
	 */
	public function get_blog_id(): int {
		return (int) ( $this->row['blog_id'] ?? 0 );
	}

	/**
	 * Whether the current site may act on the registration itself, rather than
	 * only on its own tokens for it.
	 *
	 * True on single site, on the registering site, for network owned clients,
	 * and for super admins anywhere.
	 */
	public function is_managed_by_current_site(): bool {
		if ( ! is_multisite() ) {
			return true;
		}

		if ( is_super_admin() ) {
			return true;
		}

		$blog_id = $this->get_blog_id();

		return 0 === $blog_id || get_current_blog_id() === $blog_id;
	}

	public function get_name(): string {
		return (string) ( $this->row['name'] ?? '' );
	}

	public function get_type(): string {
		return (string) ( $this->row['client_type'] ?? self::TYPE_PUBLIC );
	}

	public function is_public(): bool {
		return self::TYPE_PUBLIC === $this->get_type();
	}

	public function is_confidential(): bool {
		return self::TYPE_CONFIDENTIAL === $this->get_type();
	}

	public function get_auth_method(): string {
		return (string) ( $this->row['token_endpoint_auth_method'] ?? self::AUTH_NONE );
	}

	public function get_redirect_uris(): array {
		$uris = json_decode( (string) ( $this->row['redirect_uris'] ?? '[]' ), true );

		return is_array( $uris ) ? array_values( array_map( 'strval', $uris ) ) : [];
	}

	public function get_grant_types(): array {
		return array_values( array_filter( explode( ' ', (string) ( $this->row['grant_types'] ?? '' ) ) ) );
	}

	public function allows_grant( string $grant_type ): bool {
		return in_array( $grant_type, $this->get_grant_types(), true );
	}

	/**
	 * The client scope ceiling. An empty list means the client is limited to
	 * whatever the requested resource offers.
	 */
	public function get_scopes(): array {
		return array_values( array_filter( explode( ' ', (string) ( $this->row['scopes'] ?? '' ) ) ) );
	}

	public function get_source(): string {
		return (string) ( $this->row['source'] ?? self::SOURCE_ADMIN );
	}

	public function is_dynamic(): bool {
		return self::SOURCE_DYNAMIC === $this->get_source();
	}

	public function is_cimd(): bool {
		return self::SOURCE_CIMD === $this->get_source();
	}

	/**
	 * The client ID shown to humans. For CIMD clients the trust anchor is the
	 * metadata document URL, not the generated internal identifier.
	 */
	public function get_display_client_id(): string {
		if ( $this->is_cimd() ) {
			return $this->get_metadata_url();
		}

		return $this->get_client_id();
	}

	public function get_metadata_url(): string {
		return (string) ( $this->row['metadata_url'] ?? '' );
	}

	public function get_metadata_fetched_at(): ?string {
		return isset( $this->row['metadata_fetched_at'] ) && $this->row['metadata_fetched_at']
			? (string) $this->row['metadata_fetched_at']
			: null;
	}

	public function get_metadata_expires_at(): ?string {
		return isset( $this->row['metadata_expires_at'] ) && $this->row['metadata_expires_at']
			? (string) $this->row['metadata_expires_at']
			: null;
	}

	public function get_status(): string {
		return (string) ( $this->row['status'] ?? self::STATUS_ACTIVE );
	}

	public function is_active(): bool {
		return self::STATUS_ACTIVE === $this->get_status();
	}

	public function get_owner_user_id(): ?int {
		return isset( $this->row['owner_user_id'] ) ? (int) $this->row['owner_user_id'] : null;
	}

	public function get_metadata(): array {
		$metadata = json_decode( (string) ( $this->row['metadata'] ?? '{}' ), true );

		return is_array( $metadata ) ? $metadata : [];
	}

	public function get_created_at(): string {
		return (string) ( $this->row['created_at'] ?? '' );
	}

	public function get_last_used_at(): ?string {
		return isset( $this->row['last_used_at'] ) ? (string) $this->row['last_used_at'] : null;
	}

	/**
	 * The plaintext secret, available only on the instance returned when the
	 * client was created. Show it once, then it is gone.
	 */
	public function get_new_secret(): ?string {
		return $this->new_secret;
	}

	public function has_secret(): bool {
		return ! empty( $this->row['secret_hash'] );
	}

	public function verify_secret( string $secret ): bool {
		if ( ! $this->has_secret() ) {
			return false;
		}

		return Random::hash_equals( (string) $this->row['secret_hash'], $secret );
	}

	public function has_redirect_uri( string $uri ): bool {
		return null !== Redirect_URI::match( $uri, $this->get_redirect_uris() );
	}

	/**
	 * The immutable metadata stored with an authorization so that a later
	 * client change cannot alter an in-flight flow.
	 */
	public function to_snapshot(): array {
		return [
			'client_id' => $this->get_client_id(),
			'name' => $this->get_name(),
			'client_type' => $this->get_type(),
			'token_endpoint_auth_method' => $this->get_auth_method(),
			'source' => $this->get_source(),
			'redirect_uris' => $this->get_redirect_uris(),
			'metadata_url' => $this->get_metadata_url(),
		];
	}

	/**
	 * The RFC 7591 client information response.
	 */
	public function to_registration_response(): array {
		$response = array_merge(
			$this->get_metadata(),
			[
				'client_id' => $this->get_client_id(),
				'client_id_issued_at' => strtotime( $this->get_created_at() . ' UTC' ),
				'client_name' => $this->get_name(),
				'redirect_uris' => $this->get_redirect_uris(),
				'grant_types' => $this->get_grant_types(),
				'response_types' => [ 'code' ],
				'token_endpoint_auth_method' => $this->get_auth_method(),
			]
		);

		ksort( $response );

		return $response;
	}
}
