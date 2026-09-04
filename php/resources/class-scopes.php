<?php

namespace WPElevator\OAuth_Pilot\Resources;

use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;

/**
 * The scope registry.
 */
class Scopes {

	/**
	 * @var Scope[]
	 */
	private array $scopes = [];

	private bool $registered = false;

	public function register( array $args ): ?Scope {
		if ( empty( $args['name'] ) || ! Scope::is_valid_name( (string) $args['name'] ) ) {
			return null;
		}

		$scope = new Scope( $args );

		$this->scopes[ $scope->get_name() ] = $scope;

		return $scope;
	}

	/**
	 * Populate the registry once, on first use, so that registration order
	 * between plugins does not matter.
	 */
	public function boot(): void {
		if ( $this->registered ) {
			return;
		}

		$this->registered = true;

		/**
		 * Register scope definitions.
		 *
		 * @param Scopes $scopes The registry.
		 */
		do_action( 'oauth_pilot__register_scopes', $this );

		/**
		 * Filter the final scope definitions.
		 *
		 * @param Scope[] $scopes Keyed by scope name.
		 */
		$scopes = apply_filters( 'oauth_pilot__scopes', $this->scopes );

		if ( is_array( $scopes ) ) {
			$this->scopes = array_filter( $scopes, fn ( $scope ) => $scope instanceof Scope );
		}
	}

	/**
	 * Forget the registered scopes so they are collected again.
	 *
	 * Needed when the set of registering plugins changes within one request,
	 * such as switch_to_blog() or a test that registers its own scopes.
	 */
	public function reset(): void {
		$this->scopes = [];
		$this->registered = false;
	}

	public function get( string $name ): ?Scope {
		$this->boot();

		return $this->scopes[ $name ] ?? null;
	}

	public function has( string $name ): bool {
		return null !== $this->get( $name );
	}

	/**
	 * @return Scope[]
	 */
	public function all(): array {
		$this->boot();

		return $this->scopes;
	}

	public function names(): array {
		return array_keys( $this->all() );
	}

	/**
	 * Parse a space-delimited scope parameter.
	 *
	 * @throws OAuth_Error When the syntax is invalid or a scope repeats.
	 */
	public function parse( string $value ): array {
		$value = trim( $value );

		if ( '' === $value ) {
			return [];
		}

		$names = preg_split( '/\s+/', $value );
		$parsed = [];

		foreach ( (array) $names as $name ) {
			if ( ! Scope::is_valid_name( (string) $name ) ) {
				throw new OAuth_Error( 'invalid_scope', __( 'The requested scope is malformed.', 'wpelevator-oauth-pilot' ) );
			}

			if ( in_array( $name, $parsed, true ) ) {
				throw new OAuth_Error( 'invalid_scope', __( 'The requested scope contains duplicates.', 'wpelevator-oauth-pilot' ) );
			}

			$parsed[] = (string) $name;
		}

		return $parsed;
	}

	/**
	 * Add every implied scope, then sort so a granted set is always stored in
	 * the same normalized form.
	 */
	public function expand( array $names ): array {
		$expanded = [];

		foreach ( $names as $name ) {
			$expanded[] = $name;

			$scope = $this->get( (string) $name );

			if ( ! $scope ) {
				continue;
			}

			foreach ( $scope->get_implies() as $implied ) {
				$expanded[] = (string) $implied;
			}
		}

		$expanded = array_values( array_unique( $expanded ) );

		sort( $expanded );

		return $expanded;
	}

	public function normalize( array $names ): string {
		return implode( ' ', $this->expand( $names ) );
	}

	/**
	 * Whether $granted covers $required, taking implications into account.
	 */
	public function satisfies( array $granted, array $required ): bool {
		if ( empty( $required ) ) {
			return true;
		}

		$granted = $this->expand( $granted );

		foreach ( $required as $name ) {
			$satisfied = in_array( $name, $granted, true );

			/**
			 * Customize a scope implication check.
			 *
			 * @param bool   $satisfied Whether the granted set covers this scope.
			 * @param string $name      The required scope.
			 * @param array  $granted   The expanded granted scopes.
			 */
			$satisfied = (bool) apply_filters( 'oauth_pilot__scope_implies', $satisfied, $name, $granted );

			if ( ! $satisfied ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Reject unknown scopes and anything outside the client ceiling or the
	 * resource's supported set. An empty request falls back to the resource
	 * defaults, because agent clients routinely omit the scope parameter.
	 *
	 * @throws OAuth_Error When nothing can be granted.
	 */
	public function resolve_requested( array $requested, Protected_Resource $protected_resource, Client $client ): array {
		if ( empty( $requested ) ) {
			$requested = $protected_resource->get_default_scopes();
		}

		if ( empty( $requested ) ) {
			throw new OAuth_Error( 'invalid_scope', __( 'No scopes were requested and the resource has no default scopes.', 'wpelevator-oauth-pilot' ) );
		}

		$supported = $protected_resource->get_scopes();
		$ceiling = $client->get_scopes();

		foreach ( $requested as $name ) {
			if ( ! $this->has( (string) $name ) ) {
				throw new OAuth_Error(
					'invalid_scope',
					sprintf(
						/* translators: %s: the requested scope name. */
						__( 'Unknown scope: %s', 'wpelevator-oauth-pilot' ),
						$name
					)
				);
			}

			if ( ! empty( $supported ) && ! in_array( $name, $supported, true ) ) {
				throw new OAuth_Error(
					'invalid_scope',
					sprintf(
						/* translators: %s: the requested scope name. */
						__( 'The requested resource does not support the scope: %s', 'wpelevator-oauth-pilot' ),
						$name
					)
				);
			}

			if ( ! empty( $ceiling ) && ! in_array( $name, $ceiling, true ) ) {
				throw new OAuth_Error(
					'invalid_scope',
					sprintf(
						/* translators: %s: the requested scope name. */
						__( 'The client is not allowed to request the scope: %s', 'wpelevator-oauth-pilot' ),
						$name
					)
				);
			}
		}

		return $this->expand( $requested );
	}

	/**
	 * Whether the authorizing user may grant every requested scope.
	 */
	public function user_can_grant( int $user_id, array $names, Protected_Resource $protected_resource, Client $client ): bool {
		foreach ( $names as $name ) {
			$scope = $this->get( (string) $name );

			$can_grant = $scope ? $scope->user_can_grant( $user_id ) : false;

			/**
			 * Apply contextual policy after the scope's own callback.
			 *
			 * @param bool               $can_grant Whether the user may grant this scope.
			 * @param string             $name      The scope name.
			 * @param int                $user_id   The authorizing user.
			 * @param Protected_Resource $protected_resource The requested resource.
			 * @param Client             $client    The requesting client.
			 */
			$can_grant = (bool) apply_filters( 'oauth_pilot__user_can_grant_scope', $can_grant, $name, $user_id, $protected_resource, $client );

			if ( ! $can_grant ) {
				return false;
			}
		}

		return true;
	}
}
