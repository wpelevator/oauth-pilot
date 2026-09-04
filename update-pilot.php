<?php
/**
 * Integrate with Update Pilot even when OAuth Pilot is not enabled on the main
 * site of the WP multisite where the update checks are performed.
 */

namespace WPElevator\OAuth_Pilot;

use WPElevator\OAuth_Pilot_Vendor\WPElevator\Update_Client\Plugin_Require;

if ( ! function_exists( 'add_filter' ) ) {
	return; // Ensure WP core is loaded.
}

if ( is_readable( __DIR__ . '/vendor-isolated/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor-isolated/vendor/autoload.php';
}

add_action(
	'init',
	function () {
		if ( ! class_exists( Plugin_Require::class ) ) {
			return;
		}

		$require = new Plugin_Require(
			[
				'notice' => __( 'OAuth Pilot requires the Update Pilot plugin for automatic updates.', 'wpelevator-oauth-pilot' ),
			]
		);

		$require->init();
	}
);

add_filter(
	'update_pilot__plugins',
	function ( array $plugins ): array {
		$plugins[] = [
			'file' => plugin_basename( __DIR__ . '/oauth-pilot.php' ),
			'license_key' => null,
			'signing_key' => null, // TODO: populate this once we sign the releases.
		];

		return $plugins;
	}
);
