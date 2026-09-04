<?php

namespace WPElevator\OAuth_Pilot\Http;

use Exception;

/**
 * A protocol-level failure that serializes to an exact OAuth error response.
 *
 * Endpoints throw these; the transport layer decides whether the error is
 * returned locally or redirected back to a validated client callback.
 */
class OAuth_Error extends Exception {

	private string $error_code;

	private ?string $error_uri;

	private int $status;

	private array $headers;

	public function __construct( string $error_code, string $description = '', int $status = 400, array $headers = [], ?string $error_uri = null ) {
		parent::__construct( $description );

		$this->error_code = $error_code;
		$this->status = $status;
		$this->headers = $headers;
		$this->error_uri = $error_uri;
	}

	public function get_error_code(): string {
		return $this->error_code;
	}

	public function get_description(): string {
		return $this->getMessage();
	}

	public function get_status(): int {
		return $this->status;
	}

	public function get_headers(): array {
		return $this->headers;
	}

	/**
	 * The RFC 6749 section 5.2 error body.
	 */
	public function to_array(): array {
		$body = [
			'error' => $this->error_code,
		];

		if ( '' !== $this->getMessage() ) {
			$body['error_description'] = $this->getMessage();
		}

		if ( ! empty( $this->error_uri ) ) {
			$body['error_uri'] = $this->error_uri;
		}

		return $body;
	}

	/**
	 * The subset of parameters that may be appended to a client redirect.
	 */
	public function to_redirect_params(): array {
		return array_intersect_key(
			$this->to_array(),
			array_flip( [ 'error', 'error_description', 'error_uri' ] )
		);
	}
}
