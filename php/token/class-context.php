<?php

namespace WPElevator\OAuth_Pilot\Token;

use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Scopes;

/**
 * The result of a successful bearer token validation.
 *
 * Never exposes the raw credential.
 */
class Context {

	private Token $token;

	private Protected_Resource $resource;

	private Scopes $scopes;

	public function __construct( Token $token, Protected_Resource $protected_resource, Scopes $scopes ) {
		$this->token = $token;
		$this->resource = $protected_resource;
		$this->scopes = $scopes;
	}

	public function get_token_id(): int {
		return $this->token->get_id();
	}

	public function get_client_id(): string {
		return $this->token->get_client_id();
	}

	public function get_user_id(): int {
		return $this->token->get_user_id();
	}

	public function get_scopes(): array {
		return $this->token->get_scopes();
	}

	public function get_resource(): Protected_Resource {
		return $this->resource;
	}

	public function get_resource_uri(): string {
		return $this->token->get_resource();
	}

	public function get_expires_at(): string {
		return $this->token->get_expires_at();
	}

	public function get_expires_in(): int {
		return $this->token->get_expires_in();
	}

	public function has_scope( string $scope ): bool {
		return $this->scopes->satisfies( $this->get_scopes(), [ $scope ] );
	}

	public function has_scopes( array $scopes ): bool {
		return $this->scopes->satisfies( $this->get_scopes(), $scopes );
	}

	public function to_array(): array {
		return [
			'client_id' => $this->get_client_id(),
			'user_id' => $this->get_user_id(),
			'scopes' => $this->get_scopes(),
			'resource' => $this->get_resource_uri(),
			'expires_at' => $this->get_expires_at(),
		];
	}
}
