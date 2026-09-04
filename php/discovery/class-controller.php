<?php

namespace WPElevator\OAuth_Pilot\Discovery;

use WPElevator\OAuth_Pilot\Http\Response;
use WPElevator\OAuth_Pilot\Http\Response_Emitter;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Server_Urls;

/**
 * Serves the two standards mandated well-known documents.
 *
 * These are the only OAuth responses that live outside the REST API, because
 * their URLs are fixed by RFC 8414 and RFC 9728.
 */
class Controller {

	public const QUERY_METADATA = 'oauth_pilot_metadata';

	public const QUERY_RESOURCE_PATH = 'oauth_pilot_resource_path';

	public const QUERY_ISSUER_PATH = 'oauth_pilot_issuer_path';

	public const TYPE_AUTHORIZATION_SERVER = 'as';

	public const TYPE_PROTECTED_RESOURCE = 'prm';

	private Metadata $metadata;

	private Protected_Resources $resources;

	private Server_Urls $urls;

	private Response_Emitter $response_emitter;

	public function __construct( Metadata $metadata, Protected_Resources $resources, Server_Urls $urls, Response_Emitter $response_emitter ) {
		$this->metadata = $metadata;
		$this->resources = $resources;
		$this->urls = $urls;
		$this->response_emitter = $response_emitter;
	}

	public function init(): void {
		add_action( 'init', [ $this, 'action_add_rewrite_rules' ] );
		add_filter( 'query_vars', [ $this, 'filter_query_vars' ] );
		add_action( 'template_redirect', [ $this, 'action_serve_metadata' ], 0 );
	}

	public function action_add_rewrite_rules(): void {
		add_rewrite_rule(
			'^\.well-known/oauth-authorization-server/?$',
			'index.php?' . self::QUERY_METADATA . '=' . self::TYPE_AUTHORIZATION_SERVER,
			'top'
		);

		add_rewrite_rule(
			'^\.well-known/oauth-authorization-server/(.+)$',
			sprintf(
				'index.php?%s=%s&%s=$matches[1]',
				self::QUERY_METADATA,
				self::TYPE_AUTHORIZATION_SERVER,
				self::QUERY_ISSUER_PATH
			),
			'top'
		);

		add_rewrite_rule(
			'^\.well-known/oauth-protected-resource/?$',
			'index.php?' . self::QUERY_METADATA . '=' . self::TYPE_PROTECTED_RESOURCE,
			'top'
		);

		add_rewrite_rule(
			'^\.well-known/oauth-protected-resource/(.+)$',
			sprintf(
				'index.php?%s=%s&%s=$matches[1]',
				self::QUERY_METADATA,
				self::TYPE_PROTECTED_RESOURCE,
				self::QUERY_RESOURCE_PATH
			),
			'top'
		);
	}

	public function filter_query_vars( array $query_vars ): array {
		$query_vars[] = self::QUERY_METADATA;
		$query_vars[] = self::QUERY_RESOURCE_PATH;
		$query_vars[] = self::QUERY_ISSUER_PATH;

		return $query_vars;
	}

	public function action_serve_metadata(): void {
		$type = get_query_var( self::QUERY_METADATA );

		if ( empty( $type ) ) {
			return;
		}

		$this->response_emitter->send( $this->get_response( (string) $type ) );
	}

	public function get_response( string $type ): Response {
		if ( self::TYPE_AUTHORIZATION_SERVER === $type ) {
			return $this->get_authorization_server_response( (string) get_query_var( self::QUERY_ISSUER_PATH ) );
		}

		if ( self::TYPE_PROTECTED_RESOURCE === $type ) {
			return $this->get_protected_resource_response( (string) get_query_var( self::QUERY_RESOURCE_PATH ) );
		}

		return Response::not_found();
	}

	public function get_authorization_server_response( string $issuer_path = '' ): Response {
		$requested = trim( $issuer_path, '/' );
		$expected = trim( $this->urls->get_issuer_path(), '/' );

		// RFC 8414 appends the issuer path after the well-known segment. A
		// mismatch is a request for a different issuer, not for this one.
		if ( $requested !== $expected ) {
			return Response::not_found();
		}

		return Response::as_json(
			200,
			$this->metadata->get_authorization_server_metadata(),
			[ 'Cache-Control' => 'public, max-age=300' ]
		);
	}

	public function get_protected_resource_response( string $resource_path = '' ): Response {
		$resource = '' === trim( $resource_path, '/' )
			? $this->resources->get_default()
			: $this->resources->get_by_metadata_path( $resource_path );

		if ( ! $resource ) {
			return Response::not_found();
		}

		return Response::as_json(
			200,
			$this->metadata->get_protected_resource_metadata( $resource ),
			[ 'Cache-Control' => 'public, max-age=300' ]
		);
	}

	/**
	 * Whether the rewrite rules that serve the well-known documents are
	 * actually present, which the status screen reports on.
	 */
	public function has_rewrite_rules(): bool {
		$rules = get_option( 'rewrite_rules' );

		if ( ! is_array( $rules ) ) {
			return false;
		}

		return isset( $rules['^\.well-known/oauth-authorization-server/?$'] );
	}
}
