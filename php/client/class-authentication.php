<?php

namespace WPElevator\OAuth_Pilot\Client;

use WPElevator\OAuth_Pilot\Authorization\Authorization;
use WPElevator\OAuth_Pilot\Http\Form_Body;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Security_Events;

/**
 * OAuth client authentication for the token and revocation endpoints.
 *
 * Both client_secret_basic and client_secret_post are supported: hosted
 * connectors that take a pasted client ID and secret commonly send the
 * credentials in the request body. Clients identified by a Client ID Metadata
 * Document URL resolve from the local cache only, because these endpoints must
 * resolve to the same client row the authorization was created against.
 */
class Authentication {

	private Clients $clients;

	private Cimd $cimd;

	public function __construct( Clients $clients, Cimd $cimd ) {
		$this->clients = $clients;
		$this->cimd = $cimd;
	}

	/**
	 * @param string|null $authorization_header The raw Authorization header.
	 *
	 * @throws OAuth_Error When the client cannot be authenticated.
	 */
	public function authenticate( Form_Body $body, ?string $authorization_header = null ): Client {
		$basic = $this->parse_basic_header( $authorization_header );
		$body_id = $body->get( 'client_id' );
		$body_secret = $body->has( 'client_secret' ) ? $body->get( 'client_secret' ) : null;

		if ( isset( $basic ) && isset( $body_secret ) ) {
			throw new OAuth_Error(
				'invalid_request',
				__( 'Client credentials must be sent either in the Authorization header or in the request body, not both.', 'wpelevator-oauth-pilot' ),
				400
			);
		}

		if ( isset( $basic ) ) {
			if ( '' !== $body_id && ! hash_equals( $basic['client_id'], $body_id ) ) {
				throw new OAuth_Error(
					'invalid_request',
					__( 'The client identifier in the request body does not match the Authorization header.', 'wpelevator-oauth-pilot' ),
					400
				);
			}

			return $this->authenticate_with_secret( $basic['client_id'], $basic['client_secret'], Client::AUTH_BASIC );
		}

		if ( isset( $body_secret ) ) {
			return $this->authenticate_with_secret( $body_id, $body_secret, Client::AUTH_POST );
		}

		return $this->authenticate_public( $body_id );
	}

	/**
	 * Resolve a client without authenticating it, for endpoints that run
	 * before any credential exists.
	 *
	 * @throws OAuth_Error When the client is unknown or revoked.
	 */
	public function resolve( string $client_id ): Client {
		$client = $this->clients->get_by_client_id( $client_id );

		if ( ( ! $client || ! $client->is_active() ) && $this->cimd->is_cimd_client_id( $client_id ) ) {
			$client = $this->cimd->resolve_cached( $client_id );
		}

		if ( ! $client || ! $client->is_active() ) {
			Security_Events::record( 'client_resolution_failed', [ 'client_id' => $client_id ] );

			throw new OAuth_Error(
				'invalid_client',
				__( 'Unknown or inactive client.', 'wpelevator-oauth-pilot' ),
				401
			);
		}

		return $client;
	}

	/**
	 * @return array|null [ 'client_id' => string, 'client_secret' => string ]
	 */
	public function parse_basic_header( ?string $header ): ?array {
		if ( empty( $header ) ) {
			return null;
		}

		if ( 0 !== stripos( $header, 'basic ' ) ) {
			return null;
		}

		$decoded = base64_decode( trim( substr( $header, 6 ) ), true );

		if ( false === $decoded || false === strpos( $decoded, ':' ) ) {
			return null;
		}

		list( $client_id, $client_secret ) = explode( ':', $decoded, 2 );

		// RFC 6749 section 2.3.1 form-encodes both parts before base64.
		return [
			'client_id' => urldecode( $client_id ),
			'client_secret' => urldecode( $client_secret ),
		];
	}

	private function authenticate_with_secret( string $client_id, string $client_secret, string $method ): Client {
		$client = $this->clients->get_by_client_id( $client_id );

		if ( ! $client || ! $client->is_active() || ! $client->is_confidential() || $client->get_auth_method() !== $method ) {
			$this->fail( $client_id, $method );
		}

		if ( ! $client->verify_secret( $client_secret ) ) {
			$this->fail( $client_id, $method );
		}

		return $client;
	}

	private function authenticate_public( string $client_id ): Client {
		if ( '' === $client_id ) {
			throw new OAuth_Error(
				'invalid_client',
				__( 'A client identifier is required.', 'wpelevator-oauth-pilot' ),
				401
			);
		}

		$client = $this->clients->get_by_client_id( $client_id );

		if ( ( ! $client || ! $client->is_active() || ! $client->is_public() ) && $this->cimd->is_cimd_client_id( $client_id ) ) {
			$client = $this->cimd->resolve_cached( $client_id );
		}

		if ( ! $client || ! $client->is_active() || ! $client->is_public() ) {
			$this->fail( $client_id, Client::AUTH_NONE );
		}

		return $client;
	}

	/**
	 * @throws OAuth_Error Always.
	 */
	private function fail( string $client_id, string $method ): void {
		Security_Events::record(
			'client_authentication_failed',
			[
				'client_id' => $client_id,
				'method' => $method,
			]
		);

		$headers = Client::AUTH_BASIC === $method
			? [ 'WWW-Authenticate' => 'Basic realm="OAuth"' ]
			: [];

		throw new OAuth_Error(
			'invalid_client',
			__( 'Client authentication failed.', 'wpelevator-oauth-pilot' ),
			401,
			$headers
		);
	}
}
