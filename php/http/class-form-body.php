<?php

namespace WPElevator\OAuth_Pilot\Http;

/**
 * An exact parser for `application/x-www-form-urlencoded` request bodies.
 *
 * PHP's own parsing silently keeps the last value of a repeated parameter,
 * which is precisely the ambiguity an attacker uses against a token endpoint,
 * so the OAuth endpoints parse the raw body here instead of reading $_POST.
 */
class Form_Body {

	private array $params;

	private array $duplicates;

	private function __construct( array $params, array $duplicates ) {
		$this->params = $params;
		$this->duplicates = $duplicates;
	}

	public static function parse( string $body ): self {
		$params = [];
		$duplicates = [];

		if ( '' === trim( $body ) ) {
			return new self( $params, $duplicates );
		}

		foreach ( explode( '&', $body ) as $pair ) {
			if ( '' === $pair ) {
				continue;
			}

			$parts = explode( '=', $pair, 2 );
			$key = urldecode( $parts[0] );

			if ( '' === $key ) {
				continue;
			}

			if ( array_key_exists( $key, $params ) ) {
				$duplicates[ $key ] = true;
				continue;
			}

			$params[ $key ] = isset( $parts[1] ) ? urldecode( $parts[1] ) : '';
		}

		return new self( $params, array_keys( $duplicates ) );
	}

	public function get( string $key, string $default_value = '' ): string {
		if ( ! isset( $this->params[ $key ] ) ) {
			return $default_value;
		}

		return $this->params[ $key ];
	}

	public function has( string $key ): bool {
		return array_key_exists( $key, $this->params );
	}

	public function all(): array {
		return $this->params;
	}

	public function get_duplicates(): array {
		return $this->duplicates;
	}

	/**
	 * Reject a body that repeats any of the given security-sensitive parameters.
	 *
	 * @throws OAuth_Error When a duplicate is present.
	 */
	public function assert_no_duplicates( array $keys ): void {
		$found = array_intersect( $keys, $this->duplicates );

		if ( ! empty( $found ) ) {
			throw new OAuth_Error(
				'invalid_request',
				sprintf(
					/* translators: %s: comma separated list of request parameter names. */
					__( 'Repeated request parameters are not accepted: %s', 'wpelevator-oauth-pilot' ),
					implode( ', ', $found )
				)
			);
		}
	}
}
