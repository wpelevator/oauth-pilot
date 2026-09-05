<?php

namespace WPElevator\OAuth_Pilot\Cli;

use WP_CLI;
use WP_CLI\Utils;
use WPElevator\OAuth_Pilot\Cleanup;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Server_Urls;

/**
 * Manage the OAuth Pilot authorization server.
 *
 * This is the debugging surface for a failing client handshake: it shows what
 * is registered, what is advertised, and what tokens exist.
 */
class Command {

	private Plugin $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}


	/**
	 * Show the issuer, endpoints and any configuration warnings.
	 *
	 * ## EXAMPLES
	 *
	 *     wp oauth-pilot status
	 *
	 * @subcommand status
	 */
	public function status(): void {
		$urls = $this->plugin->get_urls();

		$rows = [
			[
				'setting' => 'issuer',
				'value' => $urls->get_issuer(),
			],
			[
				'setting' => 'authorization_server_metadata',
				'value' => $urls->get_authorization_server_metadata_url(),
			],
		];

		foreach ( Server_Urls::ENDPOINTS as $endpoint ) {
			$rows[] = [
				'setting' => $endpoint . '_endpoint',
				'value' => $urls->get_endpoint_url( $endpoint ),
			];
		}

		foreach ( $this->plugin->get_resources()->all() as $resource ) {
			$rows[] = [
				'setting' => 'resource',
				'value' => $resource->get_uri(),
			];
		}

		Utils\format_items( 'table', $rows, [ 'setting', 'value' ] );

		foreach ( $this->plugin->get_admin()->get_status_warnings() as $warning ) {
			WP_CLI::warning( wp_strip_all_tags( (string) $warning ) );
		}
	}

	/**
	 * List registered clients.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * @subcommand client-list
	 */
	public function client_list( array $args, array $assoc_args ): void {
		$rows = [];

		foreach ( $this->plugin->get_clients()->find( [ 'limit' => 500 ] ) as $client ) {
			$rows[] = [
				'client_id' => $client->get_client_id(),
				'name' => $client->get_name(),
				'type' => $client->get_type(),
				'source' => $client->get_source(),
				'blog_id' => $client->get_blog_id(),
				'status' => $client->get_status(),
				'redirect_uris' => implode( ' ', $client->get_redirect_uris() ),
				'last_used_at' => (string) $client->get_last_used_at(),
			];
		}

		$fields = [ 'client_id', 'name', 'type', 'source', 'status', 'redirect_uris', 'last_used_at' ];

		// Registrations are shared by the network, so which site owns one is
		// only worth a column when there is more than one site.
		if ( is_multisite() ) {
			array_splice( $fields, 4, 0, 'blog_id' );
		}

		Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, $fields );
	}

	/**
	 * Create a client.
	 *
	 * ## OPTIONS
	 *
	 * <name>
	 * : Display name.
	 *
	 * --redirect-uri=<uri>
	 * : A redirect URI. Repeat by separating with a comma.
	 *
	 * [--confidential]
	 * : Issue a client secret and require client authentication.
	 *
	 * [--auth-method=<method>]
	 * : Client authentication method for confidential clients.
	 * ---
	 * default: client_secret_basic
	 * options:
	 *   - client_secret_basic
	 *   - client_secret_post
	 * ---
	 *
	 * @subcommand client-create
	 */
	public function client_create( array $args, array $assoc_args ): void {
		$is_confidential = ! empty( $assoc_args['confidential'] );

		try {
			$client = $this->plugin->get_client_registration()->register_admin(
				[
					'client_name' => (string) $args[0],
					'redirect_uris' => array_map( 'trim', explode( ',', (string) ( $assoc_args['redirect-uri'] ?? '' ) ) ),
					'client_type' => $is_confidential ? Client::TYPE_CONFIDENTIAL : Client::TYPE_PUBLIC,
					'token_endpoint_auth_method' => $is_confidential
						? (string) ( $assoc_args['auth-method'] ?? Client::AUTH_BASIC )
						: Client::AUTH_NONE,
				],
				get_current_user_id()
			);
		} catch ( OAuth_Error $error ) {
			WP_CLI::error( $error->get_description() );

			return;
		}

		WP_CLI::log( 'client_id: ' . $client->get_client_id() );

		$secret = $client->get_new_secret();

		if ( isset( $secret ) ) {
			WP_CLI::log( 'client_secret: ' . $secret );
			WP_CLI::warning( 'The secret is shown only once.' );
		}

		WP_CLI::success( 'Client created.' );
	}

	/**
	 * Revoke a client and every token issued to it.
	 *
	 * On multisite the registration is shared by the network, so this revokes
	 * the client and its tokens on every site.
	 *
	 * ## OPTIONS
	 *
	 * <client-id>
	 * : The client identifier.
	 *
	 * @subcommand client-revoke
	 */
	public function client_revoke( array $args ): void {
		$client = $this->plugin->get_clients()->get_by_client_id( (string) $args[0] );

		if ( ! $client ) {
			WP_CLI::error( 'Unknown client.' );

			return;
		}

		$this->plugin->get_clients()->revoke( $client );

		WP_CLI::success( 'Client revoked.' );
	}

	/**
	 * Delete a client permanently.
	 *
	 * On multisite the registration is shared by the network, so this deletes
	 * it for every site.
	 *
	 * ## OPTIONS
	 *
	 * <client-id>
	 * : The client identifier.
	 *
	 * @subcommand client-delete
	 */
	public function client_delete( array $args ): void {
		$client = $this->plugin->get_clients()->get_by_client_id( (string) $args[0] );

		if ( ! $client ) {
			WP_CLI::error( 'Unknown client.' );

			return;
		}

		$this->plugin->get_clients()->delete( $client );

		WP_CLI::success( 'Client deleted.' );
	}

	/**
	 * Revoke every token a user granted, or every token of one client.
	 *
	 * ## OPTIONS
	 *
	 * [--user=<user-id>]
	 * : Revoke all tokens for this user.
	 *
	 * [--client=<client-id>]
	 * : Revoke all tokens for this client.
	 *
	 * [--all-sites]
	 * : On multisite, revoke across the whole network instead of only the
	 * current site. Without it, and without --url, the current site is the
	 * network's main site.
	 *
	 * @subcommand token-revoke
	 */
	public function token_revoke( array $args, array $assoc_args ): void {
		$revoked = 0;
		$tokens = $this->plugin->get_tokens();
		$network_wide = ! empty( $assoc_args['all-sites'] );

		if ( empty( $assoc_args['user'] ) && empty( $assoc_args['client'] ) ) {
			WP_CLI::error( 'Pass --user or --client.' );

			return;
		}

		if ( ! empty( $assoc_args['user'] ) ) {
			$user_id = (int) $assoc_args['user'];

			$revoked += $network_wide
				? $tokens->revoke_for_user_on_every_site( $user_id )
				: $tokens->revoke_for_user( $user_id );
		}

		if ( ! empty( $assoc_args['client'] ) ) {
			$client_id = (string) $assoc_args['client'];

			$revoked += $network_wide
				? $tokens->revoke_for_client_on_every_site( $client_id )
				: $tokens->revoke_for_client( $client_id );
		}

		WP_CLI::success(
			sprintf(
				'Revoked %d tokens%s.',
				$revoked,
				is_multisite() ? ( $network_wide ? ' across the network' : ' on this site' ) : ''
			)
		);
	}

	/**
	 * Run the scheduled cleanup immediately.
	 *
	 * @subcommand cleanup
	 */
	public function cleanup(): void {
		$results = $this->plugin->get_cleanup()->run_all();

		foreach ( $results as $key => $count ) {
			WP_CLI::log( sprintf( '%s: %d', $key, $count ) );
		}

		WP_CLI::success( 'Cleanup finished.' );
	}
}
