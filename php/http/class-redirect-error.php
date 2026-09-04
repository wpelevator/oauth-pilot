<?php

namespace WPElevator\OAuth_Pilot\Http;

/**
 * An authorization error that is safe to hand back to the client, because the
 * redirect URI it names has already been matched against stored metadata.
 */
class Redirect_Error extends OAuth_Error {

	private string $redirect_uri;

	private string $state;

	public function __construct( string $error_code, string $description, string $redirect_uri, string $state = '' ) {
		parent::__construct( $error_code, $description, 302 );

		$this->redirect_uri = $redirect_uri;
		$this->state = $state;
	}

	public function get_redirect_uri(): string {
		return $this->redirect_uri;
	}

	public function get_state(): string {
		return $this->state;
	}
}
