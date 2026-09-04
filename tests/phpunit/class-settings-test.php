<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Settings;

require_once __DIR__ . '/class-test-case.php';

/**
 * Settings are the only stored configuration, so their sanitization is what
 * stands between a form post - or a REST write - and the protocol behavior.
 * Each one is its own registered option, which is what gives WordPress the
 * type, default and REST schema to enforce per setting.
 */
class Settings_Test extends Test_Case {

	public function test_parse_host_list_accepts_spaces_commas_semicolons_and_new_lines() {
		$this->assertSame(
			[ 'claude.ai', 'chatgpt.com', 'chat.openai.com' ],
			Settings::parse_host_list( "claude.ai, chatgpt.com; chat.openai.com\nclaude.ai" ),
			'Administrators paste host lists in any separator style, and duplicates collapse.'
		);
	}

	public function test_parse_host_list_accepts_pasted_urls_and_ports() {
		$this->assertSame(
			[ 'claude.ai', 'chatgpt.com' ],
			Settings::parse_host_list( "https://claude.ai/api/mcp/auth_callback\nchatgpt.com:443" ),
			'Pasting a full callback URL or a host with a port still yields the bare hostname.'
		);
	}

	public function test_parse_host_list_is_case_insensitive_and_drops_junk() {
		$this->assertSame(
			[ 'claude.ai' ],
			Settings::parse_host_list( 'CLAude.AI  *.claude.ai  not_a_host  ' ),
			'Hosts are lowercased, and anything that is not a plain hostname is dropped rather than stored.'
		);
	}

	public function test_update_stores_a_normalized_line_separated_string() {
		$settings = $this->plugin->get_settings();
		$settings->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai, chatgpt.com' ] );

		$this->assertSame(
			"claude.ai\nchatgpt.com",
			$settings->get( 'dynamic_registration_allowed_redirect_hosts' ),
			'The stored value is a canonical line separated list, one host per line like the redirect URI fields.'
		);
	}

	public function test_updating_one_setting_leaves_the_others_alone() {
		$settings = $this->plugin->get_settings();
		$settings->update( [ 'dynamic_registration_allowed_redirect_hosts' => 'claude.ai' ] );

		$settings->update( [ 'dynamic_registration_enabled' => true ] );

		$this->assertSame(
			'claude.ai',
			$settings->get( 'dynamic_registration_allowed_redirect_hosts' ),
			'Each setting is its own option, so writing one must not wipe the allow-list.'
		);
	}

	/**
	 * One option per setting is what lets WordPress own the type, the default
	 * and the REST schema for each of them individually.
	 */
	public function test_every_setting_is_its_own_registered_option() {
		$settings = $this->plugin->get_settings();

		$this->assertNotFalse(
			has_action( 'init', [ $settings, 'register' ] ),
			'Registration runs on init, not admin_init, so the settings reach REST requests too.'
		);

		$registered = get_registered_settings();

		foreach ( $settings->get_schema() as $key => $definition ) {
			$option = $settings->get_option_name( $key );

			$this->assertArrayHasKey(
				$option,
				$registered,
				sprintf( 'The %s setting must be registered under its own option name.', $key )
			);

			$this->assertSame(
				$definition['type'],
				$registered[ $option ]['type'],
				sprintf( 'The %s setting must register with its declared type.', $key )
			);

			$this->assertNotEmpty(
				$registered[ $option ]['show_in_rest'],
				sprintf( 'The %s setting must be exposed on the REST settings endpoint.', $key )
			);
		}
	}

	public function test_defaults_apply_before_anything_is_stored() {
		$settings = $this->plugin->get_settings();

		$this->assertFalse( $settings->get( 'dynamic_registration_enabled' ), 'Dynamic registration ships off.' );
		$this->assertTrue( $settings->get( 'cimd_enabled' ), 'CIMD is the recommended replacement and ships on.' );
		$this->assertFalse( $settings->get( 'rest_authentication_enabled' ), 'REST bearer authentication ships off.' );
	}

	public function test_token_lifetimes_are_clamped_to_their_bounds() {
		$settings = $this->plugin->get_settings();

		$settings->update(
			[
				'access_token_lifetime' => 1,
				'refresh_token_lifetime' => PHP_INT_MAX,
			]
		);

		$this->assertSame(
			Settings::MIN_ACCESS_TOKEN_LIFETIME,
			$settings->get( 'access_token_lifetime' ),
			'A lifetime below the floor is raised rather than stored verbatim.'
		);

		$this->assertSame(
			Settings::MAX_REFRESH_TOKEN_LIFETIME,
			$settings->get( 'refresh_token_lifetime' ),
			'A lifetime above the ceiling is capped rather than stored verbatim.'
		);
	}

	public function test_getter_returns_an_empty_array_when_no_list_is_stored() {
		$this->assertSame(
			[],
			$this->plugin->get_settings()->get_dynamic_registration_allowed_redirect_hosts(),
			'An empty setting means any host may register.'
		);
	}

	public function test_getter_applies_its_filter() {
		add_filter(
			'oauth_pilot__dynamic_registration_allowed_redirect_hosts',
			fn () => [ 'ChatGPT.com', 'chatgpt.com' ]
		);

		$this->assertSame(
			[ 'chatgpt.com' ],
			$this->plugin->get_settings()->get_dynamic_registration_allowed_redirect_hosts(),
			'The filtered list is lowercased, trimmed and deduplicated like the stored one.'
		);
	}
}
