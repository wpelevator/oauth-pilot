<?php

namespace WPElevator\OAuth_Pilot\Resources;

/**
 * One scope definition.
 *
 * A scope narrows a token. It never widens what the represented WordPress user
 * may do: capability checks still run at the point of action.
 */
class Scope {

	private string $name;

	private string $label;

	private string $description;

	private array $implies;

	private bool $requestable;

	/**
	 * @var callable|null
	 */
	private $user_can_grant;

	public function __construct( array $args ) {
		$this->name = (string) $args['name'];
		$this->label = (string) ( $args['label'] ?? $args['name'] );
		$this->description = (string) ( $args['description'] ?? '' );
		$this->implies = array_values( (array) ( $args['implies'] ?? [] ) );
		$this->requestable = (bool) ( $args['requestable'] ?? true );
		$this->user_can_grant = isset( $args['user_can_grant'] ) && is_callable( $args['user_can_grant'] )
			? $args['user_can_grant']
			: null;
	}

	/**
	 * Scope syntax from RFC 6749 section 3.3: printable ASCII without space,
	 * double quote or backslash.
	 */
	public static function is_valid_name( string $name ): bool {
		return (bool) preg_match( '/^[\x21\x23-\x5B\x5D-\x7E]+$/', $name );
	}

	public function get_name(): string {
		return $this->name;
	}

	public function get_label(): string {
		return $this->label;
	}

	public function get_description(): string {
		return $this->description;
	}

	public function get_implies(): array {
		return $this->implies;
	}

	public function is_requestable(): bool {
		return $this->requestable;
	}

	public function user_can_grant( int $user_id ): bool {
		if ( ! isset( $this->user_can_grant ) ) {
			return $user_id > 0;
		}

		return (bool) call_user_func( $this->user_can_grant, $user_id, $this );
	}
}
