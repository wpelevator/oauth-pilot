<?php

namespace WPElevator\OAuth_Pilot\Resources;

use WPElevator\OAuth_Pilot\Server_Urls;

/**
 * The protected resource registry.
 *
 * This is how an MCP server, the WordPress REST API or any other application
 * becomes an audience OAuth Pilot can issue tokens for, without OAuth Pilot
 * knowing anything about it.
 */
class Protected_Resources {

	/**
	 * @var Protected_Resource[] Keyed by canonical URI.
	 */
	private array $resources = [];

	private bool $registered = false;

	private Server_Urls $urls;

	public function __construct( Server_Urls $urls ) {
		$this->urls = $urls;
	}

	/**
	 * @param array $args {
	 *     @type string $uri               Canonical resource URI. Required.
	 *     @type string $name              Human readable name.
	 *     @type array  $scopes            Supported scopes.
	 *     @type array  $defaults          Scopes granted when none are requested.
	 *     @type bool   $requires_resource Whether the resource parameter is mandatory.
	 * }
	 */
	public function register( array $args ): ?Protected_Resource {
		if ( empty( $args['uri'] ) ) {
			return null;
		}

		$uri = $this->urls->normalize_url( (string) $args['uri'] );

		// Duplicate canonical URIs would make audience resolution ambiguous.
		if ( isset( $this->resources[ $uri ] ) ) {
			return null;
		}

		$args['uri'] = $uri;

		if ( empty( $args['authorization_servers'] ) ) {
			$args['authorization_servers'] = [ $this->urls->get_issuer() ];
		}

		if ( empty( $args['metadata_url'] ) ) {
			$args['metadata_url'] = $this->urls->get_protected_resource_metadata_url( $uri );
		}

		$args['metadata_path'] = $this->urls->get_resource_path( $uri );

		$resource = new Protected_Resource( $args );

		$this->resources[ $uri ] = $resource;

		return $resource;
	}

	public function boot(): void {
		if ( $this->registered ) {
			return;
		}

		$this->registered = true;

		/**
		 * Register protected resources.
		 *
		 * @param Protected_Resources $resources The registry.
		 */
		do_action( 'oauth_pilot__register_resources', $this );

		/**
		 * Filter the final protected resource list.
		 *
		 * @param Protected_Resource[] $resources Keyed by canonical URI.
		 */
		$resources = apply_filters( 'oauth_pilot__protected_resources', $this->resources );

		if ( is_array( $resources ) ) {
			$this->resources = array_filter( $resources, fn ( $item ) => $item instanceof Protected_Resource );
		}
	}

	/**
	 * Forget the registered resources so they are collected again.
	 */
	public function reset(): void {
		$this->resources = [];
		$this->registered = false;
	}

	public function get( string $uri ): ?Protected_Resource {
		$this->boot();

		return $this->resources[ $this->urls->normalize_url( $uri ) ] ?? null;
	}

	/**
	 * @return Protected_Resource[]
	 */
	public function all(): array {
		$this->boot();

		return $this->resources;
	}

	/**
	 * The resource used when a client sends no resource parameter.
	 */
	public function get_default(): ?Protected_Resource {
		$resources = $this->all();

		if ( empty( $resources ) ) {
			return null;
		}

		foreach ( $resources as $resource ) {
			if ( ! $resource->requires_resource() ) {
				return $resource;
			}
		}

		return null;
	}

	/**
	 * Resolve the resource for an incoming request URL, preferring the most
	 * specific canonical path.
	 *
	 * Without this, a token minted for an MCP endpoint nested under wp-json
	 * would be accepted by every other WordPress REST route.
	 */
	public function match_url( string $url ): ?Protected_Resource {
		$matched = null;
		$matched_length = -1;
		$path = $this->urls->get_resource_path( $url );

		foreach ( $this->all() as $resource ) {
			if ( ! $resource->matches_path( $path ) ) {
				continue;
			}

			$length = $resource->get_specificity();

			if ( $length > $matched_length ) {
				$matched = $resource;
				$matched_length = $length;
			}
		}

		return $matched;
	}

	/**
	 * Resolve a resource by its RFC 9728 metadata path.
	 */
	public function get_by_metadata_path( string $path ): ?Protected_Resource {
		$path = trim( $path, '/' );

		foreach ( $this->all() as $resource ) {
			if ( $resource->get_metadata_path() === $path ) {
				return $resource;
			}
		}

		return null;
	}

	/**
	 * Every scope offered by a registered resource, for discovery metadata.
	 */
	public function get_supported_scopes(): array {
		$scopes = [];

		foreach ( $this->all() as $resource ) {
			$scopes = array_merge( $scopes, $resource->get_scopes() );
		}

		$scopes = array_values( array_unique( $scopes ) );

		sort( $scopes );

		return $scopes;
	}
}
