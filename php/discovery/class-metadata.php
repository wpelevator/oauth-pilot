<?php

namespace WPElevator\OAuth_Pilot\Discovery;

use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;

/**
 * Controller documents.
 *
 * Only implemented behavior is ever advertised: a client that trusts this
 * document must not be able to derive a capability we do not have.
 */
class Metadata {

	private Server_Urls $urls;

	private Protected_Resources $resources;

	private Settings $settings;

	public function __construct( Server_Urls $urls, Protected_Resources $resources, Settings $settings ) {
		$this->urls = $urls;
		$this->resources = $resources;
		$this->settings = $settings;
	}

	/**
	 * The RFC 8414 authorization server metadata document.
	 */
	public function get_authorization_server_metadata(): array {
		$metadata = [
			'issuer' => $this->urls->get_issuer(),
			'authorization_endpoint' => $this->urls->get_endpoint_url( 'authorize' ),
			'token_endpoint' => $this->urls->get_endpoint_url( 'token' ),
			'revocation_endpoint' => $this->urls->get_endpoint_url( 'revoke' ),
			'response_types_supported' => [ 'code' ],
			'response_modes_supported' => [ 'query' ],
			'grant_types_supported' => [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ],
			'code_challenge_methods_supported' => [ PKCE::METHOD ],
			'token_endpoint_auth_methods_supported' => [ Client::AUTH_NONE, Client::AUTH_BASIC, Client::AUTH_POST ],
			'revocation_endpoint_auth_methods_supported' => [ Client::AUTH_NONE, Client::AUTH_BASIC, Client::AUTH_POST ],
			'scopes_supported' => $this->resources->get_supported_scopes(),
			'authorization_response_iss_parameter_supported' => true,
			'resource_indicators_supported' => true,
		];

		if ( $this->settings->is_dynamic_registration_enabled() ) {
			$metadata['registration_endpoint'] = $this->urls->get_endpoint_url( 'register' );
		}

		if ( $this->settings->is_cimd_enabled() ) {
			$metadata['client_id_metadata_document_supported'] = true;
		}

		/**
		 * Add standards compliant authorization server metadata fields.
		 *
		 * Core security capabilities are reapplied after this filter so they
		 * cannot be falsely removed or advertised.
		 *
		 * @param array $metadata The RFC 8414 document.
		 */
		$metadata = (array) apply_filters( 'oauth_pilot__authorization_server_metadata', $metadata );

		return array_merge(
			$metadata,
			[
				'issuer' => $this->urls->get_issuer(),
				'authorization_endpoint' => $this->urls->get_endpoint_url( 'authorize' ),
				'token_endpoint' => $this->urls->get_endpoint_url( 'token' ),
				'response_types_supported' => [ 'code' ],
				'grant_types_supported' => [ Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ],
				'code_challenge_methods_supported' => [ PKCE::METHOD ],
				'authorization_response_iss_parameter_supported' => true,
			]
		);
	}

	public function get_protected_resource_metadata( Protected_Resource $protected_resource ): array {
		return $protected_resource->to_metadata();
	}
}
