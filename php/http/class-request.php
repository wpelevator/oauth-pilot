<?php

namespace WPElevator\OAuth_Pilot\Http;

/**
 * The incoming request, for the discovery documents served outside the REST
 * API.
 */
class Request {

	private string $method;

	private array $headers;

	public function __construct( ?string $method = null, array $headers = [] ) {
		$this->method = strtoupper( $method ?? 'GET' );
		$this->headers = array_change_key_case( $headers, CASE_LOWER );
	}

	public static function from_globals(): self {
		$headers = [];

		foreach ( $_SERVER as $key => $value ) {
			if ( 0 === strpos( (string) $key, 'HTTP_' ) ) {
				$name = str_replace( '_', '-', strtolower( substr( (string) $key, 5 ) ) );
				$headers[ $name ] = is_scalar( $value ) ? (string) $value : '';
			}
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
			: 'GET';

		return new self( $method, $headers );
	}

	public function get_method(): string {
		return $this->method;
	}

	public function is_method( string ...$methods ): bool {
		foreach ( $methods as $method ) {
			if ( strtoupper( $method ) === $this->method ) {
				return true;
			}
		}

		return false;
	}

	public function get_header( string $name ): ?string {
		return $this->headers[ strtolower( $name ) ] ?? null;
	}

	public function get_origin(): ?string {
		return $this->get_header( 'origin' );
	}

	public function matches_etag( string $etag ): bool {
		$if_none_match = $this->get_header( 'if-none-match' );

		if ( empty( $if_none_match ) ) {
			return false;
		}

		foreach ( explode( ',', $if_none_match ) as $candidate ) {
			if ( trim( $candidate ) === $etag ) {
				return true;
			}
		}

		return false;
	}
}
