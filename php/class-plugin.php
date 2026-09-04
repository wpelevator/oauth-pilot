<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Service composition and WordPress wiring.
 */
class Plugin {
	public const SCOPE_REST = 'wp:rest';

	private string $plugin_file;

	private Schema $schema;

	private Settings $settings;

	private Server_Urls $urls;

	private Resources\Scopes $scopes;

	private Resources\Protected_Resources $resources;

	private Token\Tokens $tokens;

	private Authorization\Authorizations $authorizations;

	private Client\Clients $clients;

	private Client\Authentication $client_authentication;

	private Client\Registration $registration;

	private Client\Cimd $cimd;

	private Authorization\Service $authorization_service;

	private Token\Service $token_service;

	private Token\Bearer_Validator $validator;

	private Discovery\Metadata $metadata;

	private Discovery\Controller $discovery;

	private Rest\Controller $rest_controller;

	private Rest\Authentication $rest_authentication;

	private Integrations\MCP_Adapter $mcp_adapter_integration;

	private Authorization\Consent $consent_controller;

	private Cleanup $cleanup;

	private Admin\Screen $admin;

	private Admin\Profile $profile;

	public function __construct( string $plugin_file ) {
		global $wpdb;

		$this->plugin_file = $plugin_file;

		$this->schema = new Schema( $wpdb );
		$this->settings = new Settings();
		$this->urls = new Server_Urls();
		$this->scopes = new Resources\Scopes();
		$this->resources = new Resources\Protected_Resources( $this->urls );

		$this->tokens = new Token\Tokens( $wpdb, $this->schema->get_table_name( Schema::TABLE_TOKENS ) );
		$this->authorizations = new Authorization\Authorizations( $wpdb, $this->schema->get_table_name( Schema::TABLE_AUTHORIZATIONS ), $this->tokens );
		$this->clients = new Client\Clients( $wpdb, $this->schema->get_table_name( Schema::TABLE_CLIENTS ), $this->tokens, $this->authorizations );

		$rate_limiter = new Rate_Limiter();

		$this->registration = new Client\Registration( $this->clients, $this->settings, $rate_limiter );
		$this->cimd = new Client\Cimd( $this->clients, $this->registration, $this->settings, $rate_limiter );
		$this->client_authentication = new Client\Authentication( $this->clients, $this->cimd );

		$this->authorization_service = new Authorization\Service(
			$this->clients,
			$this->authorizations,
			$this->scopes,
			$this->resources,
			$this->urls,
			$this->tokens,
			$this->cimd,
			$this->settings,
			$rate_limiter
		);

		$this->token_service = new Token\Service(
			$this->clients,
			$this->authorizations,
			$this->tokens,
			$this->scopes,
			$this->resources,
			$this->settings,
			$this->urls,
			$this->client_authentication,
			$rate_limiter
		);

		$this->validator = new Token\Bearer_Validator( $this->tokens, $this->clients, $this->scopes, $this->resources );
		$this->metadata = new Discovery\Metadata( $this->urls, $this->resources, $this->settings );

		$this->discovery = new Discovery\Controller(
			$this->metadata,
			$this->resources,
			$this->urls,
			new Http\Response_Emitter( Http\Request::from_globals() )
		);

		$this->rest_controller = new Rest\Controller(
			$this->authorization_service,
			$this->token_service,
			$this->registration,
			$this->urls,
			$this->settings
		);

		$this->rest_authentication = new Rest\Authentication( $this->validator, $this->resources, $this->settings );
		$this->mcp_adapter_integration = new Integrations\MCP_Adapter( $this->settings );

		$this->consent_controller = new Authorization\Consent(
			$this->authorizations,
			$this->authorization_service,
			$this->clients,
			$this->scopes,
			$this->resources,
			$this->urls,
			new Asset_Meta( $this->get_path_to( 'css/consent.css' ) )
		);

		$this->cleanup = new Cleanup( $this->authorizations, $this->tokens, $this->clients );
		$this->admin = new Admin\Screen( $this );
		$this->profile = new Admin\Profile( $this->clients, $this->tokens );
	}

	public function init(): void {
		// Activation hooks do not run in every environment that loads this plugin.
		$this->schema->install_if_needed();

		// Settings register on init, not admin_init, so they reach the REST
		// settings endpoint and carry their defaults on front end requests too.
		add_action( 'init', [ $this->settings, 'register' ] );

		add_action( 'oauth_pilot__register_scopes', [ $this, 'action_register_default_scopes' ], 5 );
		add_action( 'oauth_pilot__register_resources', [ $this, 'action_register_default_resources' ], 5 );
		add_action( 'wp_initialize_site', [ $this, 'action_initialize_site' ], 100 );
		add_filter( 'plugin_action_links_' . $this->get_basename(), [ $this, 'filter_plugin_action_links' ] );

		$this->discovery->init();
		$this->rest_controller->init();
		$this->rest_authentication->init();
		$this->mcp_adapter_integration->init();
		$this->consent_controller->init();
		$this->cleanup->init();
		$this->admin->init();
		$this->profile->init();

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'oauth-pilot', new Cli\Command( $this ) );
		}
	}

	/**
	 * The WordPress REST API as a protected resource.
	 *
	 * Registered always, so it can be discovered and tokens can be scoped to
	 * it, but bearer authentication for it stays off until a site opts in.
	 */
	public function action_register_default_resources( Resources\Protected_Resources $resources ): void {
		$resources->register(
			[
				'uri' => rest_url(),
				'name' => __( 'WordPress REST API', 'wpelevator-oauth-pilot' ),
				'scopes' => [ self::SCOPE_REST ],
				'defaults' => [ self::SCOPE_REST ],
			]
		);
	}

	public function action_register_default_scopes( Resources\Scopes $scopes ): void {
		$scopes->register(
			[
				'name' => self::SCOPE_REST,
				'label' => __( 'Use the WordPress REST API', 'wpelevator-oauth-pilot' ),
				'description' => __( 'Use REST endpoints with the same permissions as your WordPress account.', 'wpelevator-oauth-pilot' ),
				'user_can_grant' => fn ( int $user_id ): bool => user_can( $user_id, 'read' ),
			]
		);
	}

	/**
	 * Install the tables for a new site on multisite.
	 *
	 * @param mixed $site The new site object.
	 */
	public function action_initialize_site( $site ): void {
		if ( ! is_multisite() || ! isset( $site->blog_id ) ) {
			return;
		}

		switch_to_blog( (int) $site->blog_id );

		( new Schema( $GLOBALS['wpdb'] ) )->install();

		restore_current_blog();
	}

	public function filter_plugin_action_links( array $actions ): array {
		$actions['settings'] = sprintf(
			'<a href="%s">%s</a>',
			esc_url( $this->admin->get_settings_url() ),
			esc_html__( 'Settings', 'wpelevator-oauth-pilot' )
		);

		return $actions;
	}

	public function get_basename(): string {
		return plugin_basename( $this->plugin_file );
	}

	public function get_path_to( string $relative_path ): string {
		return plugin_dir_path( $this->plugin_file ) . ltrim( $relative_path, '/\\' );
	}

	public function get_schema(): Schema {
		return $this->schema;
	}

	public function get_settings(): Settings {
		return $this->settings;
	}

	public function get_urls(): Server_Urls {
		return $this->urls;
	}

	public function get_scopes(): Resources\Scopes {
		return $this->scopes;
	}

	public function get_resources(): Resources\Protected_Resources {
		return $this->resources;
	}

	public function get_clients(): Client\Clients {
		return $this->clients;
	}

	public function get_authorizations(): Authorization\Authorizations {
		return $this->authorizations;
	}

	public function get_tokens(): Token\Tokens {
		return $this->tokens;
	}

	public function get_client_registration(): Client\Registration {
		return $this->registration;
	}

	public function get_cimd(): Client\Cimd {
		return $this->cimd;
	}

	public function get_authorization_service(): Authorization\Service {
		return $this->authorization_service;
	}

	public function get_token_service(): Token\Service {
		return $this->token_service;
	}

	public function get_validator(): Token\Bearer_Validator {
		return $this->validator;
	}

	public function get_metadata(): Discovery\Metadata {
		return $this->metadata;
	}

	public function get_discovery(): Discovery\Controller {
		return $this->discovery;
	}

	public function get_rest_authentication(): Rest\Authentication {
		return $this->rest_authentication;
	}

	public function get_consent_controller(): Authorization\Consent {
		return $this->consent_controller;
	}

	public function get_cleanup(): Cleanup {
		return $this->cleanup;
	}

	public function get_admin(): Admin\Screen {
		return $this->admin;
	}

	public function get_admin_capability(): string {
		/**
		 * The capability required to manage the authorization server.
		 *
		 * @param string $capability The required capability.
		 */
		return (string) apply_filters( 'oauth_pilot__admin_capability', 'manage_options' );
	}

	public static function activate(): void {
		global $wpdb;

		( new Schema( $wpdb ) )->install();

		flush_rewrite_rules();
	}

	public static function deactivate(): void {
		plugin()->get_cleanup()->unschedule_events();

		flush_rewrite_rules();
	}

	public static function uninstall(): void {
		global $wpdb;

		( new Schema( $wpdb ) )->uninstall();

		$settings = new Settings();

		foreach ( array_keys( $settings->get_schema() ) as $key ) {
			delete_option( $settings->get_option_name( $key ) );
		}
	}
}
