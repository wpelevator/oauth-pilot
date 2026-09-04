<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Server_Urls;

class Server_Urls_Test extends \WP_UnitTestCase {

	private Server_Urls $urls;

	public function set_up() {
		parent::set_up();

		$this->urls = new Server_Urls();
	}

	public function test_normalizes_scheme_host_and_trailing_slash() {
		$this->assertSame(
			'https://example.com/wp-json',
			$this->urls->normalize_url( 'HTTPS://Example.COM/wp-json/' ),
			'Canonicalization must lowercase the scheme and host and drop the trailing slash.'
		);
	}

	public function test_drops_only_default_ports() {
		$this->assertSame(
			'https://example.com/a',
			$this->urls->normalize_url( 'https://example.com:443/a' ),
			'The default HTTPS port carries no meaning and must be removed.'
		);

		$this->assertSame(
			'https://example.com:8443/a',
			$this->urls->normalize_url( 'https://example.com:8443/a' ),
			'A non default port is part of the identity of a URL.'
		);
	}

	public function test_root_install_has_an_empty_issuer_path() {
		add_filter( 'oauth_pilot__issuer', fn (): string => 'https://example.com' );

		$this->assertSame( '', $this->urls->get_issuer_path(), 'A root install has no issuer path.' );
		$this->assertTrue( $this->urls->is_root_issuer(), 'A root install is the configuration RFC 8414 can serve directly.' );

		$this->assertSame(
			'https://example.com/.well-known/oauth-authorization-server',
			$this->urls->get_authorization_server_metadata_url(),
			'A root issuer publishes metadata at the bare well-known path.'
		);
	}

	public function test_subdirectory_install_appends_the_issuer_path_after_the_well_known_segment() {
		add_filter( 'oauth_pilot__issuer', fn (): string => 'https://example.com/blog' );

		$this->assertFalse(
			$this->urls->is_root_issuer(),
			'A subdirectory install cannot serve conforming metadata from its own rewrite rules.'
		);

		$this->assertSame(
			'https://example.com/.well-known/oauth-authorization-server/blog',
			$this->urls->get_authorization_server_metadata_url(),
			'RFC 8414 inserts the well-known segment before the issuer path, at the root of the host.'
		);
	}

	public function test_protected_resource_metadata_url_inserts_the_well_known_segment() {
		add_filter( 'oauth_pilot__issuer', fn (): string => 'https://example.com' );

		$this->assertSame(
			'https://example.com/.well-known/oauth-protected-resource/wp-json/mcp/v1/mcp',
			$this->urls->get_protected_resource_metadata_url( 'https://example.com/wp-json/mcp/v1/mcp' ),
			'RFC 9728 places the well-known segment between the host and the resource path.'
		);
	}

	public function test_endpoint_urls_are_rest_routes() {
		$this->assertSame(
			rest_url( 'oauth-pilot/v1/token' ),
			$this->urls->get_endpoint_url( 'token' ),
			'Protocol endpoints live on the versioned REST API so they work with any permalink setting.'
		);

		$this->assertSame(
			'',
			$this->urls->get_endpoint_url( 'introspect' ),
			'An endpoint that is not implemented must not produce a URL that could be advertised.'
		);
	}

	public function test_endpoint_urls_are_filterable() {
		add_filter(
			'oauth_pilot__endpoint_url',
			fn ( string $url, string $endpoint ): string => 'token' === $endpoint ? 'https://auth.example.com/token' : $url,
			10,
			2
		);

		$this->assertSame(
			'https://auth.example.com/token',
			$this->urls->get_endpoint_url( 'token' ),
			'A dedicated authorization host must be able to override a generated endpoint.'
		);
	}
}
