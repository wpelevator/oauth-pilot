<?php

namespace WPElevator\OAuth_Pilot\Http;

use WPElevator\OAuth_Pilot\Authorization\Authorization;

/**
 * An exact HTTP response, built outside the WordPress REST API so the
 * discovery documents are byte-for-byte what the specification requires.
 */
class Response {

	private int $status;

	private array $headers;

	private string $body;

	private function __construct( int $status, array $headers, string $body = '' ) {
		$this->status = $status;
		$this->headers = $headers;
		$this->body = $body;
	}

	/**
	 * Headers every response gets. Controller documents are public and
	 * cacheable, so CORS is opened here and nowhere else.
	 */
	private static function get_default_headers( ?string $body = null ): array {
		$headers = [
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy' => 'no-referrer',
			'Access-Control-Allow-Origin' => '*',
			'Access-Control-Allow-Methods' => 'GET, HEAD, OPTIONS',
			'Access-Control-Allow-Headers' => 'Authorization, Content-Type',
			// Without this a browser based client cannot read the challenge that starts discovery.
			'Access-Control-Expose-Headers' => 'WWW-Authenticate',
		];

		if ( isset( $body ) ) {
			$headers['Content-Length'] = (string) strlen( $body );
			$headers['ETag'] = sprintf( '"%s"', hash( 'sha256', $body ) );
		}

		return $headers;
	}

	public static function as_json( int $status, array $data, array $headers = [] ): self {
		$body = (string) wp_json_encode(
			$data,
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
		) . "\n";

		return new self(
			$status,
			array_merge(
				[ 'Content-Type' => 'application/json; charset=UTF-8' ],
				self::get_default_headers( $body ),
				$headers
			),
			$body
		);
	}

	public static function not_found(): self {
		return self::as_json(
			404,
			[ 'error' => 'not_found' ],
			[ 'Cache-Control' => 'no-store' ]
		);
	}

	public static function method_not_allowed(): self {
		return new self(
			405,
			array_merge(
				self::get_default_headers( '' ),
				[
					'Allow' => 'GET, HEAD, OPTIONS',
					'Cache-Control' => 'no-store',
				]
			),
			''
		);
	}

	public static function no_content( int $status = 204, array $headers = [] ): self {
		return new self( $status, array_merge( self::get_default_headers(), $headers ), '' );
	}

	public function with_headers( array $headers ): self {
		return new self( $this->status, array_merge( $this->headers, $headers ), $this->body );
	}

	public function as_not_modified(): self {
		$headers = array_intersect_key(
			$this->headers,
			array_flip( [ 'ETag', 'Cache-Control', 'Access-Control-Allow-Origin', 'X-Content-Type-Options' ] )
		);

		return new self( 304, $headers, '' );
	}

	public function get_status(): int {
		return $this->status;
	}

	public function get_headers(): array {
		return $this->headers;
	}

	public function get_header( string $name ): ?string {
		return $this->headers[ $name ] ?? null;
	}

	public function get_body(): string {
		return $this->body;
	}

	public function get_data(): array {
		$data = json_decode( $this->body, true );

		return is_array( $data ) ? $data : [];
	}
}
