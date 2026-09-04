<?php

namespace WPElevator\OAuth_Pilot\Admin;

use WPElevator\OAuth_Pilot\Authorization\Authorization;
use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;
use WPElevator\OAuth_Pilot\Plugin;
use WPElevator\OAuth_Pilot\Server_Urls;
use WPElevator\OAuth_Pilot\Settings;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * Settings screen with a tab each for the server status, the configuration and the clients.
 */
class Screen {

	public const SLUG = 'oauth-pilot';

	public const TAB_SETTINGS = 'settings';

	public const TAB_CLIENTS = 'clients';

	public const TAB_STATUS = 'status';

	public const TAB_DEFAULT = self::TAB_SETTINGS;

	private const ACTION_CREATE_CLIENT = 'oauth_pilot_create_client';

	private const ACTION_CLIENT = 'oauth_pilot_client_action';

	private Plugin $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'action_register_settings_page' ] );
		add_action( 'admin_post_' . self::ACTION_CREATE_CLIENT, [ $this, 'action_create_client' ] );
		add_action( 'admin_post_' . self::ACTION_CLIENT, [ $this, 'action_client_action' ] );
		add_filter( 'option_page_capability_oauth_pilot', [ $this, 'filter_settings_capability' ] );
	}

	public function filter_settings_capability(): string {
		return $this->plugin->get_admin_capability();
	}

	public function get_settings_url( string $tab = '' ): string {
		$url = admin_url( 'options-general.php?page=' . self::SLUG );

		if ( ! empty( $tab ) && self::TAB_DEFAULT !== $tab ) {
			$url = add_query_arg( 'tab', $tab, $url );
		}

		return $url;
	}

	/**
	 * @return array<string, string> Tab slugs and their labels, in display order.
	 */
	public function get_tabs(): array {
		return [
			self::TAB_SETTINGS => __( 'Settings', 'wpelevator-oauth-pilot' ),
			self::TAB_CLIENTS => __( 'Clients', 'wpelevator-oauth-pilot' ),
			self::TAB_STATUS => __( 'Status', 'wpelevator-oauth-pilot' ),
		];
	}

	public function get_current_tab(): string {
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';

		return isset( $this->get_tabs()[ $tab ] ) ? $tab : self::TAB_DEFAULT;
	}

	public function get_client_action_url( string $action, Client $client ): string {
		return wp_nonce_url(
			add_query_arg(
				[
					'action' => self::ACTION_CLIENT,
					'client_action' => $action,
					'client' => $client->get_id(),
				],
				admin_url( 'admin-post.php' )
			),
			self::ACTION_CLIENT . '_' . $client->get_id()
		);
	}

	public function action_register_settings_page(): void {
		add_options_page(
			__( 'OAuth Pilot', 'wpelevator-oauth-pilot' ),
			__( 'OAuth Pilot', 'wpelevator-oauth-pilot' ),
			$this->plugin->get_admin_capability(),
			self::SLUG,
			[ $this, 'render_settings_page' ]
		);
	}

	/**
	 * Configuration problems that would break a real client handshake.
	 */
	public function get_status_warnings(): array {
		$warnings = [];
		$urls = $this->plugin->get_urls();

		if ( $urls->is_https_required() && ! $urls->is_https_issuer() ) {
			$warnings[] = sprintf(
				/* translators: %s: link to the General Settings screen. */
				__( 'The site address is not HTTPS. OAuth clients will refuse to connect. Update it on the <a href="%s">General Settings</a> screen.', 'wpelevator-oauth-pilot' ),
				esc_url( admin_url( 'options-general.php#home' ) )
			);
		}

		$is_subdirectory_multisite = is_multisite() && ! is_subdomain_install();

		if ( $is_subdirectory_multisite && ! $urls->is_root_issuer() ) {
			$warnings[] = sprintf(
				/* translators: %s: the metadata URL that has to work. */
				__( 'This site is a subdirectory site on a multisite network. RFC 8414 places the authorization server metadata at <code>%s</code>, which is at the root of the host, where the request resolves to the main site of the network and cannot serve this site. Use the main site as the issuer, or give this site its own subdomain.', 'wpelevator-oauth-pilot' ),
				esc_url( $urls->get_authorization_server_metadata_url() )
			);
		} elseif ( ! $urls->is_root_issuer() ) {
			$warnings[] = sprintf(
				/* translators: %s: the metadata URL that has to work. */
				__( 'WordPress is installed in a subdirectory. RFC 8414 places the authorization server metadata at <code>%s</code>, which is at the root of the host and outside the paths WordPress rewrite rules can reach from a subdirectory install. Add a server-level rewrite or proxy rule for that path, or run the authorization server on a root install.', 'wpelevator-oauth-pilot' ),
				esc_url( $urls->get_authorization_server_metadata_url() )
			);
		}

		if ( ! $this->plugin->get_discovery()->has_rewrite_rules() ) {
			$warnings[] = sprintf(
				/* translators: %s: link to the Permalinks settings screen. */
				__( 'The well-known discovery rewrite rules are missing. Visit <a href="%s">Settings then Permalinks</a> and save to flush the rewrite rules.', 'wpelevator-oauth-pilot' ),
				esc_url( admin_url( 'options-permalink.php' ) )
			);
		}

		if ( ! $this->plugin->get_cleanup()->get_next_run() ) {
			$warnings[] = __( 'The cleanup schedule is not registered, so expired authorizations and tokens will not be removed.', 'wpelevator-oauth-pilot' );
		}

		return $warnings;
	}

	/**
	 * Basic inline HTML elements allowed in warning and notice messages.
	 *
	 * @return array<string, array<string, bool>> Allowed HTML tags with their allowed attributes.
	 */
	public function get_notice_allowed_html(): array {
		return [
			'a' => [
				'href' => true,
				'target' => true,
			],
			'abbr' => [ 'title' => true ],
			'br' => [],
			'code' => [],
			'em' => [],
			'span' => [],
			'strong' => [],
		];
	}

	public function render_settings_page(): void {
		if ( ! current_user_can( $this->plugin->get_admin_capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to manage OAuth Pilot.', 'wpelevator-oauth-pilot' ) );
		}

		$current_tab = $this->get_current_tab();

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'OAuth Pilot', 'wpelevator-oauth-pilot' ); ?></h1>

			<?php foreach ( $this->get_status_warnings() as $warning ) : ?>
				<div class="notice notice-warning"><p><?php echo wp_kses( (string) $warning, $this->get_notice_allowed_html() ); ?></p></div>
			<?php endforeach; ?>

			<h2 class="nav-tab-wrapper wp-clearfix">
				<?php foreach ( $this->get_tabs() as $tab => $label ) : ?>
					<?php $is_current = ( $tab === $current_tab ); ?>
					<a href="<?php echo esc_url( $this->get_settings_url( $tab ) ); ?>" class="<?php echo esc_attr( $is_current ? 'nav-tab nav-tab-active' : 'nav-tab' ); ?>"<?php echo $is_current ? ' aria-current="page"' : ''; ?>><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</h2>

			<?php
			switch ( $current_tab ) {
				case self::TAB_CLIENTS:
					$this->render_clients_tab();
					break;

				case self::TAB_STATUS:
					$this->render_status_tab();
					break;

				default:
					$this->render_settings_tab();
			}
			?>
		</div>
		<?php
	}

	/**
	 * The Settings tab: the configuration form.
	 */
	private function render_settings_tab(): void {
		$settings = $this->plugin->get_settings();

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
			<?php settings_fields( Settings::GROUP ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Dynamic client registration', 'wpelevator-oauth-pilot' ); ?></th>
					<td>
						<label>
							<input type="hidden" name="<?php echo esc_attr( $settings->get_option_name( 'dynamic_registration_enabled' ) ); ?>" value="0" />
							<input type="checkbox" name="<?php echo esc_attr( $settings->get_option_name( 'dynamic_registration_enabled' ) ); ?>" value="1" <?php checked( (bool) $settings->get( 'dynamic_registration_enabled' ) ); ?> />
							<?php esc_html_e( 'Enable dynamic client registration', 'wpelevator-oauth-pilot' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="oauth-pilot-allowed-hosts"><?php esc_html_e( 'Limit dynamic client domains', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td>
						<textarea name="<?php echo esc_attr( $settings->get_option_name( 'dynamic_registration_allowed_redirect_hosts' ) ); ?>" id="oauth-pilot-allowed-hosts" rows="3" class="large-text"><?php echo esc_textarea( (string) $settings->get( 'dynamic_registration_allowed_redirect_hosts' ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Limit the dynamic client registration only to these hosts (one domain per line). Listed domain names are matched against the client redirect_url hostname. Loopback callbacks such as localhost or 127.0.0.1 used by native and CLI clients are always allowed. Leave empty to allow any host.', 'wpelevator-oauth-pilot' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Client ID Metadata Documents (CIMD) registration', 'wpelevator-oauth-pilot' ); ?></th>
					<td>
						<label>
							<input type="hidden" name="<?php echo esc_attr( $settings->get_option_name( 'cimd_enabled' ) ); ?>" value="0" />
							<input type="checkbox" name="<?php echo esc_attr( $settings->get_option_name( 'cimd_enabled' ) ); ?>" value="1" <?php checked( (bool) $settings->get( 'cimd_enabled' ) ); ?> />
							<?php esc_html_e( 'Accept HTTPS URL client identifiers backed by a client metadata document', 'wpelevator-oauth-pilot' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Recommended for MCP clients instead of dynamic client registration. WordPress fetches and validates the client\'s self-published metadata document at the client_id URL. The document host must be publicly reachable.', 'wpelevator-oauth-pilot' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'REST API authentication', 'wpelevator-oauth-pilot' ); ?></th>
					<td>
						<label>
							<input type="hidden" name="<?php echo esc_attr( $settings->get_option_name( 'rest_authentication_enabled' ) ); ?>" value="0" />
							<input type="checkbox" name="<?php echo esc_attr( $settings->get_option_name( 'rest_authentication_enabled' ) ); ?>" value="1" <?php checked( (bool) $settings->get( 'rest_authentication_enabled' ) ); ?> />
							<?php esc_html_e( 'Accept OAuth bearer tokens for the WordPress REST API. Endpoint capability checks still apply.', 'wpelevator-oauth-pilot' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="oauth-pilot-access-lifetime"><?php esc_html_e( 'Access token lifetime', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td>
							<input type="number" name="<?php echo esc_attr( $settings->get_option_name( 'access_token_lifetime' ) ); ?>" id="oauth-pilot-access-lifetime" value="<?php echo esc_attr( (string) $settings->get( 'access_token_lifetime' ) ); ?>" min="<?php echo esc_attr( (string) Settings::MIN_ACCESS_TOKEN_LIFETIME ); ?>" max="<?php echo esc_attr( (string) Settings::MAX_ACCESS_TOKEN_LIFETIME ); ?>" />
						<?php esc_html_e( 'seconds', 'wpelevator-oauth-pilot' ); ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="oauth-pilot-refresh-lifetime"><?php esc_html_e( 'Refresh token lifetime', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td>
							<input type="number" name="<?php echo esc_attr( $settings->get_option_name( 'refresh_token_lifetime' ) ); ?>" id="oauth-pilot-refresh-lifetime" value="<?php echo esc_attr( (string) $settings->get( 'refresh_token_lifetime' ) ); ?>" min="<?php echo esc_attr( (string) Settings::MIN_REFRESH_TOKEN_LIFETIME ); ?>" max="<?php echo esc_attr( (string) Settings::MAX_REFRESH_TOKEN_LIFETIME ); ?>" />
						<?php esc_html_e( 'seconds', 'wpelevator-oauth-pilot' ); ?>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>
		<?php
	}

	/**
	 * The Clients tab: the registered clients table and the form that adds one.
	 */
	private function render_clients_tab(): void {
		$table = new Clients_Table( $this->plugin->get_clients(), $this );
		$table->prepare_items();
		$table->display();

		?>
		<h2><?php esc_html_e( 'Add a client', 'wpelevator-oauth-pilot' ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_CREATE_CLIENT ); ?>" />
			<?php wp_nonce_field( self::ACTION_CREATE_CLIENT ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="oauth-pilot-name"><?php esc_html_e( 'Name', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td><input name="client_name" id="oauth-pilot-name" type="text" class="regular-text" required /></td>
				</tr>
				<tr>
					<th scope="row"><label for="oauth-pilot-redirects"><?php esc_html_e( 'Redirect URIs', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td>
						<textarea name="redirect_uris" id="oauth-pilot-redirects" rows="3" class="large-text" required></textarea>
						<p class="description"><?php esc_html_e( 'List of allowed redirect URIs, one per line. Must be HTTPS, or HTTP for loopback address.', 'wpelevator-oauth-pilot' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Type', 'wpelevator-oauth-pilot' ); ?></th>
					<td>
						<label><input type="radio" name="client_type" value="<?php echo esc_attr( Client::TYPE_PUBLIC ); ?>" checked /> <?php esc_html_e( 'Public, authenticates with PKCE only', 'wpelevator-oauth-pilot' ); ?></label><br />
						<label><input type="radio" name="client_type" value="<?php echo esc_attr( Client::TYPE_CONFIDENTIAL ); ?>" /> <?php esc_html_e( 'Confidential, receives a client secret', 'wpelevator-oauth-pilot' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="oauth-pilot-auth-method"><?php esc_html_e( 'Client authentication', 'wpelevator-oauth-pilot' ); ?></label></th>
					<td>
						<select name="token_endpoint_auth_method" id="oauth-pilot-auth-method">
							<option value="<?php echo esc_attr( Client::AUTH_BASIC ); ?>"><?php echo esc_html( Client::AUTH_BASIC ); ?></option>
							<option value="<?php echo esc_attr( Client::AUTH_POST ); ?>"><?php echo esc_html( Client::AUTH_POST ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'Only used by confidential clients.', 'wpelevator-oauth-pilot' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Add client', 'wpelevator-oauth-pilot' ) ); ?>
		</form>
		<?php
	}

	/**
	 * The Status tab: what the server is currently advertising and serving.
	 */
	private function render_status_tab(): void {
		$urls = $this->plugin->get_urls();

		?>
		<table class="widefat striped">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Issuer', 'wpelevator-oauth-pilot' ); ?></th>
					<td><code><?php echo esc_html( $urls->get_issuer() ); ?></code></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Authorization server metadata', 'wpelevator-oauth-pilot' ); ?></th>
					<td><code><?php echo esc_html( $urls->get_authorization_server_metadata_url() ); ?></code></td>
				</tr>
				<?php foreach ( Server_Urls::ENDPOINTS as $endpoint ) : ?>
					<tr>
						<th scope="row"><?php echo esc_html( ucfirst( $endpoint ) ); ?></th>
						<td><code><?php echo esc_html( $urls->get_endpoint_url( $endpoint ) ); ?></code></td>
					</tr>
				<?php endforeach; ?>
				<tr>
					<th scope="row"><?php esc_html_e( 'Registered resources', 'wpelevator-oauth-pilot' ); ?></th>
					<td>
						<?php foreach ( $this->plugin->get_resources()->all() as $resource ) : ?>
							<code><?php echo esc_html( $resource->get_uri() ); ?></code>
							&mdash; <?php echo esc_html( $resource->get_name() ); ?><br />
							<code><?php echo esc_html( $resource->get_metadata_url() ); ?></code><br />
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Active tokens', 'wpelevator-oauth-pilot' ); ?></th>
					<td><?php echo esc_html( (string) $this->plugin->get_tokens()->count_active() ); ?></td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	public function action_create_client(): void {
		$this->assert_can_manage();
		check_admin_referer( self::ACTION_CREATE_CLIENT );

		$uris = isset( $_POST['redirect_uris'] )
			? preg_split( '/\R+/', sanitize_textarea_field( wp_unslash( $_POST['redirect_uris'] ) ) )
			: [];

		$metadata = [
			'client_name' => isset( $_POST['client_name'] ) ? sanitize_text_field( wp_unslash( $_POST['client_name'] ) ) : '',
			'redirect_uris' => array_values( array_filter( array_map( 'trim', (array) $uris ) ) ),
			'client_type' => isset( $_POST['client_type'] ) ? sanitize_key( wp_unslash( $_POST['client_type'] ) ) : Client::TYPE_PUBLIC,
			'token_endpoint_auth_method' => isset( $_POST['token_endpoint_auth_method'] ) ? sanitize_text_field( wp_unslash( $_POST['token_endpoint_auth_method'] ) ) : Client::AUTH_NONE,
		];

		if ( Client::TYPE_CONFIDENTIAL !== $metadata['client_type'] ) {
			$metadata['token_endpoint_auth_method'] = Client::AUTH_NONE;
		}

		try {
			$client = $this->plugin->get_client_registration()->register_admin( $metadata, get_current_user_id() );
		} catch ( OAuth_Error $error ) {
			$this->redirect_back( [ 'message' => rawurlencode( $error->get_description() ) ], self::TAB_CLIENTS );
		}

		$secret = $client->get_new_secret();

		if ( isset( $secret ) ) {
			wp_die(
				sprintf(
					'<p>%s</p><p><code>%s</code></p><p><a href="%s">%s</a></p>',
					esc_html__( 'The client secret is shown only once. Copy it now.', 'wpelevator-oauth-pilot' ),
					esc_html( $secret ),
					esc_url( $this->get_settings_url( self::TAB_CLIENTS ) ),
					esc_html__( 'Return to the OAuth Pilot clients', 'wpelevator-oauth-pilot' )
				),
				esc_html__( 'Client created', 'wpelevator-oauth-pilot' ),
				[ 'response' => 200 ]
			);
		}

		$this->redirect_back( [ 'created' => 1 ], self::TAB_CLIENTS );
	}

	public function action_client_action(): void {
		$this->assert_can_manage();

		$client_id = isset( $_GET['client'] ) ? (int) $_GET['client'] : 0;

		check_admin_referer( self::ACTION_CLIENT . '_' . $client_id );

		$client = $this->plugin->get_clients()->get_by_id( $client_id );

		if ( ! $client ) {
			$this->redirect_back( [ 'message' => rawurlencode( __( 'That client no longer exists.', 'wpelevator-oauth-pilot' ) ) ], self::TAB_CLIENTS );
		}

		$action = isset( $_GET['client_action'] ) ? sanitize_key( wp_unslash( $_GET['client_action'] ) ) : '';

		if ( 'revoke' === $action ) {
			$this->plugin->get_clients()->revoke( $client );
		} elseif ( 'delete' === $action ) {
			$this->plugin->get_clients()->delete( $client );
		}

		$this->redirect_back( [], self::TAB_CLIENTS );
	}

	private function assert_can_manage(): void {
		if ( ! current_user_can( $this->plugin->get_admin_capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to manage OAuth Pilot.', 'wpelevator-oauth-pilot' ) );
		}
	}

	private function redirect_back( array $args = [], string $tab = self::TAB_DEFAULT ): void {
		wp_safe_redirect( add_query_arg( $args, $this->get_settings_url( $tab ) ) );

		exit;
	}
}
