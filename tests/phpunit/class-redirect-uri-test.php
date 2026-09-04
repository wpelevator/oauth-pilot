<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Client\Redirect_URI;

class Redirect_URI_Test extends \WP_UnitTestCase {

	/**
	 * @dataProvider data_allowed_uris
	 */
	public function test_allows_supported_callbacks( string $uri, string $reason ) {
		$this->assertTrue( Redirect_URI::is_valid( $uri ), $reason );
	}

	public function data_allowed_uris(): array {
		return [
			[ 'https://claude.ai/api/mcp/auth_callback', 'A hosted connector callback over HTTPS is the primary supported case.' ],
			[ 'https://chatgpt.com/connector_platform_oauth_redirect', 'A second hosted connector callback must be allowed the same way.' ],
			[ 'http://127.0.0.1:8765/callback', 'RFC 8252 allows a loopback IPv4 callback for native clients.' ],
			[ 'http://[::1]:9000/callback', 'RFC 8252 allows a loopback IPv6 callback.' ],
			[ 'http://localhost:1455/oauth/callback', 'The localhost hostname is an accepted loopback form.' ],
			[ 'https://example.com/callback?flow=mcp', 'A query string is part of the exact registered value.' ],
		];
	}

	/**
	 * @dataProvider data_rejected_uris
	 */
	public function test_rejects_unsafe_callbacks( string $uri, string $reason ) {
		$this->assertFalse( Redirect_URI::is_valid( $uri ), $reason );
	}

	public function data_rejected_uris(): array {
		return [
			[ '', 'An empty redirect URI cannot be matched against anything.' ],
			[ 'http://example.com/callback', 'Plain HTTP is only allowed for loopback addresses.' ],
			[ 'https://example.com/callback#fragment', 'A fragment must never be part of a redirect URI.' ],
			[ 'https://user:pass@example.com/callback', 'Userinfo in a redirect URI is a credential leak.' ],
			[ 'https://*.example.com/callback', 'Wildcards would defeat exact matching.' ],
			[ '/callback', 'A schemeless URI is not absolute.' ],
			[ 'javascript:alert(1)', 'Script schemes must be denied outright.' ],
			[ 'data:text/html,hello', 'Data URIs must be denied outright.' ],
			[ 'com.example.app:/callback', 'A private use scheme is denied unless a filter approves it.' ],
			[ "https://example.com/call\nback", 'Control characters must be rejected.' ],
		];
	}

	public function test_private_use_scheme_can_be_approved_by_filter() {
		add_filter(
			'oauth_pilot__redirect_uri_allowed',
			fn ( bool $allowed, string $uri ): bool => 'com.example.app:/callback' === $uri ? true : $allowed,
			10,
			2
		);

		$this->assertTrue(
			Redirect_URI::is_valid( 'com.example.app:/callback' ),
			'A native client scheme must become registrable once a site opts into it.'
		);
	}

	public function test_comparison_is_exact_for_https() {
		$this->assertTrue(
			Redirect_URI::equals( 'https://example.com/callback', 'https://example.com/callback' ),
			'An identical HTTPS URI must match.'
		);

		$this->assertFalse(
			Redirect_URI::equals( 'https://example.com/callback/extra', 'https://example.com/callback' ),
			'A longer path must not match: comparison is exact, never prefix based.'
		);

		$this->assertFalse(
			Redirect_URI::equals( 'https://example.com:8443/callback', 'https://example.com/callback' ),
			'A different port on a non loopback URI is a different callback.'
		);
	}

	public function test_loopback_ports_are_the_only_flexible_part() {
		$this->assertTrue(
			Redirect_URI::equals( 'http://127.0.0.1:54321/callback', 'http://127.0.0.1:8765/callback' ),
			'RFC 8252 requires ignoring the loopback port because native clients bind an ephemeral one.'
		);

		$this->assertFalse(
			Redirect_URI::equals( 'http://127.0.0.1:54321/evil', 'http://127.0.0.1:8765/callback' ),
			'Loopback port flexibility must not extend to the path.'
		);

		$this->assertFalse(
			Redirect_URI::equals( 'http://localhost:54321/callback', 'http://127.0.0.1:8765/callback' ),
			'Loopback host forms are distinct registered values.'
		);
	}

	public function test_matches_against_a_registered_list() {
		$registered = [ 'https://a.example.com/cb', 'http://127.0.0.1:1/cb' ];

		$this->assertSame(
			'http://127.0.0.1:1/cb',
			Redirect_URI::match( 'http://127.0.0.1:6000/cb', $registered ),
			'Matching must return the registered value that the request corresponds to.'
		);

		$this->assertNull(
			Redirect_URI::match( 'https://b.example.com/cb', $registered ),
			'An unregistered callback must not match anything.'
		);
	}
}
