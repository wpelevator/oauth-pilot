<?php
/**
 * Plugin Name: OAuth Pilot
 * Description: OAuth 2.1 authorization server for WordPress. Lets agent MCP clients and other applications authenticate against this site.
 * Author: WP Elevator
 * Author URI: https://wpelevator.com
 * Version: 0.7.0
 * Plugin URI: https://wpelevator.com/plugins/oauth-pilot
 * Update URI: https://updates.wpelevator.com/wp-json/update-pilot/v1/plugins
 * Requires at least: 6.6
 * Requires PHP: 7.4
 * Text Domain: wpelevator-oauth-pilot
 */

namespace WPElevator\OAuth_Pilot;

// Ensure WP core is loaded.
if ( ! function_exists( 'add_action' ) ) {
	return;
}

if ( is_readable( __DIR__ . '/vendor-isolated/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor-isolated/vendor/autoload.php';
}

// Only if there is no project autoloader that knows about us.
if ( ! class_exists( Plugin::class ) && file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
}

// Configure the Update Pilot integration for this plugin.
require_once __DIR__ . '/update-pilot.php';

function plugin(): Plugin {
	static $plugin;

	if ( ! isset( $plugin ) ) {
		$plugin = new Plugin( __FILE__ );
	}

	return $plugin;
}

add_action( 'plugins_loaded', [ plugin(), 'init' ] );

register_activation_hook( __FILE__, [ Plugin::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ Plugin::class, 'deactivate' ] );
register_uninstall_hook( __FILE__, [ Plugin::class, 'uninstall' ] );
