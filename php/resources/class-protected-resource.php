<?php

namespace WPElevator\OAuth_Pilot\Resources;

/**
 * An immutable protected resource: the audience a token is bound to.
 */
class Protected_Resource {

	private string $uri;

	private string $name;

	private array $scopes;

	private array $default_scopes;

	private array $authorization_servers;

	private string $metadata_url;

	private bool $requires_resource;

	private string $metadata_path;

	private array $documentation;

	public function __construct( array $args ) {
		$this->uri = (string) $args['uri'];
		$this->name = (string) ( $args['name'] ?? $args['uri'] );
		$this->scopes = array_values( (array) ( $args['scopes'] ?? [] ) );
		$this->default_scopes = array_values( (array) ( $args['defaults'] ?? $this->scopes ) );
		$this->authorization_servers = array_values( (array) ( $args['authorization_servers'] ?? [] ) );
		$this->metadata_url = (string) ( $args['metadata_url'] ?? '' );
		$this->requires_resource = (bool) ( $args['requires_resource'] ?? false );
		$this->metadata_path = (string) ( $args['metadata_path'] ?? '' );
		$this->documentation = (array) ( $args['documentation'] ?? [] );
	}

	public function get_uri(): string {
		return $this->uri;
	}

	public function get_name(): string {
		return $this->name;
	}

	public function get_scopes(): array {
		return $this->scopes;
	}

	public function get_default_scopes(): array {
		return $this->default_scopes;
	}

	public function get_authorization_servers(): array {
		return $this->authorization_servers;
	}

	public function get_metadata_url(): string {
		return $this->metadata_url;
	}

	public function requires_resource(): bool {
		return $this->requires_resource;
	}

	/**
	 * The path used to route this resource's RFC 9728 metadata document.
	 *
	 * Derived once by the registry, which owns the Server_Urls instance.
	 */
	public function get_metadata_path(): string {
		return $this->metadata_path;
	}

	/**
	 * Whether a request path falls under this resource.
	 *
	 * Takes an already derived path so the registry canonicalizes the incoming
	 * URL once rather than once per registered resource.
	 */
	public function matches_path( string $path ): bool {
		if ( '' === $this->metadata_path ) {
			return true;
		}

		return $path === $this->metadata_path || 0 === strpos( $path, $this->metadata_path . '/' );
	}

	/**
	 * How specific this resource is, used to prefer the deepest match when
	 * several resources cover the same request URL.
	 */
	public function get_specificity(): int {
		return strlen( $this->metadata_path );
	}

	/**
	 * The RFC 9728 metadata document.
	 */
	public function to_metadata(): array {
		$metadata = [
			'resource' => $this->uri,
			'authorization_servers' => $this->authorization_servers,
			'scopes_supported' => $this->scopes,
			'bearer_methods_supported' => [ 'header' ],
		];

		if ( ! empty( $this->documentation['resource_documentation'] ) ) {
			$metadata['resource_documentation'] = (string) $this->documentation['resource_documentation'];
		}

		if ( ! empty( $this->documentation['resource_policy_uri'] ) ) {
			$metadata['resource_policy_uri'] = (string) $this->documentation['resource_policy_uri'];
		}

		/**
		 * Add metadata fields for one registered protected resource.
		 *
		 * @param array              $metadata The RFC 9728 document.
		 * @param Protected_Resource $resource The resource.
		 */
		return (array) apply_filters( 'oauth_pilot__protected_resource_metadata', $metadata, $this );
	}
}
