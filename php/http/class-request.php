<?php

namespace WPElevator\OAuth_Pilot\Http;

/**
 * Incoming discovery request, using the Agent Pilot request implementation.
 */
class Request {

	private string $method;

	private array $headers;

	public function __construct( ?string $method = null, array $headers = [] ) {
		$this->method = strtoupper( trim( $method ?? 'GET' ) );
		$this->headers = [];

		foreach ( $headers as $name => $value ) {
			if ( is_scalar( $value ) ) {
				$name = self::normalize_header_name( (string) $name );

				if ( '' !== $name ) {
					$this->headers[ $name ] = trim( (string) $value );
				}
			}
		}
	}

	public static function from_globals(): self {
		$method = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
		$headers = [];
		$special_headers = [
			'CONTENT_TYPE' => 'content-type',
			'CONTENT_LENGTH' => 'content-length',
			'CONTENT_MD5' => 'content-md5',
		];

		foreach ( $_SERVER as $name => $value ) {
			if ( is_scalar( $value ) ) {
				$header_name = null;

				if ( 0 === strpos( (string) $name, 'HTTP_' ) ) {
					$header_name = substr( (string) $name, 5 );
				} elseif ( isset( $special_headers[ $name ] ) ) {
					$header_name = $special_headers[ $name ];
				}

				if ( null !== $header_name ) {
					$headers[ self::normalize_header_name( $header_name ) ] = sanitize_text_field( wp_unslash( (string) $value ) );
				}
			}
		}

		return new self( $method, $headers );
	}

	public function get_method(): string {
		return $this->method;
	}

	public function is_method( string ...$methods ): bool {
		return in_array( $this->method, array_map( 'strtoupper', $methods ), true );
	}

	public function get_headers(): array {
		return $this->headers;
	}

	public function get_header( string $name ): ?string {
		$name = self::normalize_header_name( $name );

		return $this->headers[ $name ] ?? null;
	}

	public function get_origin(): ?string {
		return $this->get_header( 'origin' );
	}

	public function matches_etag( string $etag ): bool {
		foreach ( explode( ',', $this->get_header( 'if-none-match' ) ?? '' ) as $candidate ) {
			$candidate = trim( $candidate );

			if ( '*' === $candidate ) {
				return true;
			}

			if ( 0 === stripos( $candidate, 'W/' ) ) {
				$candidate = trim( substr( $candidate, 2 ) );
			}

			if ( hash_equals( $etag, $candidate ) ) {
				return true;
			}
		}

		return false;
	}

	private static function normalize_header_name( string $name ): string {
		return strtolower( str_replace( '_', '-', trim( $name ) ) );
	}
}
