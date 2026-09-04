<?php

namespace WPElevator\OAuth_Pilot\Http;

/**
 * Emits exact HTTP response bytes outside the WordPress REST API.
 */
class Response_Emitter {

	private Request $request;

	public function __construct( Request $request ) {
		$this->request = $request;
	}

	public function send( Response $response ): void {
		$response = $this->prepare_response( $response );

		status_header( $response->get_status() );

		foreach ( $response->get_headers() as $name => $value ) {
			header( $name . ': ' . $value );
		}

		echo $this->get_body( $response ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Exact serialized response bytes.

		exit;
	}

	public function prepare_response( Response $response ): Response {
		if ( $this->request->is_method( 'OPTIONS' ) ) {
			return Response::no_content( 204, [ 'Cache-Control' => 'no-store' ] );
		}

		if ( ! $this->request->is_method( 'GET', 'HEAD' ) ) {
			return Response::method_not_allowed();
		}

		$etag = $response->get_header( 'ETag' );

		if ( 200 === $response->get_status() && $etag && $this->request->matches_etag( $etag ) ) {
			return $response->as_not_modified();
		}

		return $response;
	}

	public function get_body( Response $response ): string {
		$status = $response->get_status();

		if ( $this->request->is_method( 'HEAD' ) || $status < 200 || in_array( $status, [ 204, 304 ], true ) ) {
			return '';
		}

		return $response->get_body();
	}
}
