<?php

namespace WPElevator\OAuth_Pilot\Authorization;

use WP_User;
use WPElevator\OAuth_Pilot\Asset_Meta;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Client\Redirect_URI;
use WPElevator\OAuth_Pilot\Random;
use WPElevator\OAuth_Pilot\Resources\Protected_Resource;
use WPElevator\OAuth_Pilot\Resources\Protected_Resources;
use WPElevator\OAuth_Pilot\Resources\Scopes;
use WPElevator\OAuth_Pilot\Server_Urls;

/**
 * The internal login and consent screen.
 *
 * This lives on wp-login.php rather than in the REST API on purpose: it is the
 * only step of the flow that reads a WordPress login cookie, and rendering it
 * here gives it the native login look through login_header() and
 * login_footer().
 */
class Consent {

	private Authorizations $authorizations;

	private Service $authorization_service;

	private Clients $clients;

	private Scopes $scopes;

	private Protected_Resources $resources;

	private Server_Urls $urls;

	private Asset_Meta $stylesheet;

	public function __construct(
		Authorizations $authorizations,
		Service $authorization_service,
		Clients $clients,
		Scopes $scopes,
		Protected_Resources $resources,
		Server_Urls $urls,
		Asset_Meta $stylesheet
	) {
		$this->authorizations = $authorizations;
		$this->authorization_service = $authorization_service;
		$this->clients = $clients;
		$this->scopes = $scopes;
		$this->resources = $resources;
		$this->urls = $urls;
		$this->stylesheet = $stylesheet;
	}

	public function init(): void {
		add_action( 'login_form_' . Server_Urls::CONSENT_ACTION, [ $this, 'action_handle_request' ] );
	}

	public function get_nonce_action( string $request_id ): string {
		return 'oauth_pilot_consent_' . Random::hash( $request_id );
	}

	public function action_handle_request(): void {
		$this->send_headers();

		$request_id = $this->get_request_id();

		if ( '' === $request_id ) {
			$this->render_error( __( 'This authorization request is missing its identifier.', 'wpelevator-oauth-pilot' ) );
		}

		$authorization = $this->authorizations->get_by_request_id( $request_id );

		if ( ! $authorization || $authorization->is_expired() || ! $authorization->is_pending() ) {
			$this->render_error( __( 'This authorization request has expired or was already used. Start the connection again from your application.', 'wpelevator-oauth-pilot' ) );
		}

		if ( ! is_user_logged_in() ) {
			// Same host, so the safe redirect is the correct one here.
			wp_safe_redirect( wp_login_url( $this->urls->get_consent_url( $request_id ) ) );
			exit;
		}

		$user_id = get_current_user_id();

		if ( ! $this->authorizations->bind_user( $authorization, $user_id, (string) wp_get_session_token() ) ) {
			$this->render_error( __( 'This authorization request belongs to a different sign-in session.', 'wpelevator-oauth-pilot' ) );
		}

		$authorization = $this->authorizations->get_by_id( $authorization->get_id() );

		if ( ! $authorization ) {
			$this->render_error( __( 'This authorization request is no longer available.', 'wpelevator-oauth-pilot' ) );
		}

		$client = $this->clients->get_by_client_id( $authorization->get_client_id() );
		$resource = $this->resources->get( $authorization->get_resource() );

		if ( ! $client || ! $client->is_active() || ! $resource ) {
			$this->render_error( __( 'The application that started this request is no longer available.', 'wpelevator-oauth-pilot' ) );
		}

		if ( ! $this->scopes->user_can_grant( $user_id, $authorization->get_scopes(), $resource, $client ) ) {
			$this->render_error( __( 'Your account is not allowed to grant the requested permissions.', 'wpelevator-oauth-pilot' ) );
		}

		if ( $this->is_post_request() ) {
			$this->handle_decision( $authorization, $user_id, $request_id );
		}

		if ( $this->authorization_service->has_remembered_consent( $authorization, $user_id ) ) {
			$this->complete_approval( $authorization, $user_id );
		}

		$this->render_consent_form( $authorization, $client, $resource, $request_id );
	}

	private function handle_decision( Authorization $authorization, int $user_id, string $request_id ): void {
		check_admin_referer( $this->get_nonce_action( $request_id ), 'oauth_pilot_nonce' );

		$decision = isset( $_POST['oauth_pilot_decision'] )
			? sanitize_key( wp_unslash( $_POST['oauth_pilot_decision'] ) )
			: '';

		if ( 'approve' === $decision ) {
			$this->complete_approval( $authorization, $user_id );
		}

		$redirect = $this->authorization_service->deny( $authorization, $user_id );

		$this->redirect_to_client( $redirect );
	}

	private function complete_approval( Authorization $authorization, int $user_id ): void {
		$redirect = $this->authorization_service->approve( $authorization, $user_id );

		if ( ! isset( $redirect ) ) {
			$this->render_error( __( 'This authorization request was already completed.', 'wpelevator-oauth-pilot' ) );
		}

		$this->redirect_to_client( $redirect );
	}

	/**
	 * The callback is an external URL that was matched byte for byte against
	 * the client's registered list, so wp_safe_redirect() - which would drop
	 * every external host - must not be used here.
	 */
	private function redirect_to_client( string $url ): void {
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Validated against the registered redirect URIs.

		exit;
	}

	private function get_request_id(): string {
		$raw = '';

		if ( isset( $_REQUEST['request_id'] ) ) {
			$raw = sanitize_text_field( wp_unslash( $_REQUEST['request_id'] ) );
		}

		return preg_match( '/^[A-Za-z0-9\-_]{16,128}$/', $raw ) ? $raw : '';
	}

	private function is_post_request(): bool {
		return isset( $_SERVER['REQUEST_METHOD'] )
			&& 'POST' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
	}

	private function send_headers(): void {
		if ( headers_sent() ) {
			return;
		}

		nocache_headers();

		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		header( 'Pragma: no-cache' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: DENY' );
		header( 'Referrer-Policy: no-referrer' );
		header( "Content-Security-Policy: frame-ancestors 'none'" );
	}

	private function render_error( string $message ): void {
		login_header(
			__( 'Authorization', 'wpelevator-oauth-pilot' ),
			'<p class="message">' . esc_html( $message ) . '</p>'
		);

		printf(
			'<p id="backtoblog"><a href="%s">%s</a></p>',
			esc_url( home_url( '/' ) ),
			esc_html__( 'Back to site', 'wpelevator-oauth-pilot' )
		);

		login_footer();

		exit;
	}

	/**
	 * The display name of the role this grant would be made with. A user with
	 * no role on this site - possible on multisite - has nothing to show.
	 */
	private function get_user_role_name( WP_User $user ): string {
		$names = array_intersect_key( wp_roles()->get_names(), array_flip( $user->roles ) );

		if ( empty( $names ) ) {
			return '';
		}

		return translate_user_role( (string) reset( $names ) );
	}

	public function action_enqueue_styles(): void {
		if ( ! $this->stylesheet->exists() ) {
			return;
		}

		wp_enqueue_style(
			'oauth-pilot-consent',
			$this->stylesheet->get_url(),
			$this->stylesheet->get_dependencies(),
			$this->stylesheet->get_version()
		);
	}

	private function render_consent_form( Authorization $authorization, Client $client, Protected_Resource $protected_resource, string $request_id ): void {
		$user = wp_get_current_user();
		$role_name = $this->get_user_role_name( $user );
		$redirect_host = Redirect_URI::get_display_host( $authorization->get_redirect_uri() );

		/**
		 * Add display context to the consent screen.
		 *
		 * @param array              $context       Safe, escapable display values.
		 * @param Authorization      $authorization The pending authorization.
		 * @param Client             $client        The requesting client.
		 * @param Protected_Resource $protected_resource The requested resource.
		 */
		$context = (array) apply_filters(
			'oauth_pilot__consent_context',
			[ 'notice' => '' ],
			$authorization,
			$client,
			$protected_resource
		);

		add_action( 'login_enqueue_scripts', [ $this, 'action_enqueue_styles' ] );

		login_header( __( 'Authorize application', 'wpelevator-oauth-pilot' ) );
		?>
		<form name="oauth-pilot-consent" id="oauth-pilot-consent" action="<?php echo esc_url( $this->urls->get_consent_url( $request_id ) ); ?>" method="post">
			<?php wp_nonce_field( $this->get_nonce_action( $request_id ), 'oauth_pilot_nonce' ); ?>
			<input type="hidden" name="request_id" value="<?php echo esc_attr( $request_id ); ?>" />

			<p>
				<?php
				if ( '' !== $role_name ) {
					printf(
						/* translators: 1: application name, 2: WordPress user login, 3: user role name. */
						esc_html__( 'Application named %1$s wants to access this site as you (%2$s with role %3$s).', 'wpelevator-oauth-pilot' ),
						'<strong>&#8220;' . esc_html( $client->get_name() ) . '&#8221;</strong>',
						'<strong>' . esc_html( $user->user_login ) . '</strong>',
						esc_html( $role_name )
					);
				} else {
					printf(
						/* translators: 1: application name, 2: WordPress user login. */
						esc_html__( 'Application named %1$s wants to access this site as you (%2$s).', 'wpelevator-oauth-pilot' ),
						'<strong>&#8220;' . esc_html( $client->get_name() ) . '&#8221;</strong>',
						'<strong>' . esc_html( $user->user_login ) . '</strong>'
					);
				}
				?>
			</p>

			<?php if ( $client->is_dynamic() ) : ?>
				<p class="notice notice-error">
					<?php esc_html_e( 'This application registered itself automatically and has not been reviewed by an administrator.', 'wpelevator-oauth-pilot' ); ?>
				</p>
			<?php endif; ?>

			<?php if ( ! empty( $context['notice'] ) ) : ?>
				<p class="message"><?php echo esc_html( (string) $context['notice'] ); ?></p>
			<?php endif; ?>

			<h2 class="oauth-pilot-consent__heading"><?php esc_html_e( 'Permissions requested', 'wpelevator-oauth-pilot' ); ?></h2>
			<ul class="oauth-pilot-consent__permissions">
				<?php foreach ( $authorization->get_scopes() as $scope_name ) : ?>
					<?php $scope = $this->scopes->get( $scope_name ); ?>
					<li>
						<strong><?php echo esc_html( $scope ? $scope->get_label() : $scope_name ); ?></strong>
						<?php if ( $scope && '' !== $scope->get_description() ) : ?>
							&mdash; <?php echo esc_html( $scope->get_description() ); ?>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ul>

			<dl class="oauth-pilot-consent__details">
				<dt><?php esc_html_e( 'Resource:', 'wpelevator-oauth-pilot' ); ?></dt>
				<dd><code><?php echo esc_html( $protected_resource->get_name() ); ?></code></dd>
				<dt><?php esc_html_e( 'Redirects to:', 'wpelevator-oauth-pilot' ); ?></dt>
				<dd><code><?php echo esc_html( $redirect_host ); ?></code></dd>
				<dt><?php esc_html_e( 'Client ID:', 'wpelevator-oauth-pilot' ); ?></dt>
				<dd><code><?php echo esc_html( $client->get_display_client_id() ); ?></code></dd>
			</dl>

			<p class="submit">
				<button type="submit" name="oauth_pilot_decision" value="approve" class="button button-primary button-large">
					<?php esc_html_e( 'Approve', 'wpelevator-oauth-pilot' ); ?>
				</button>
				<button type="submit" name="oauth_pilot_decision" value="deny" class="button button-large">
					<?php esc_html_e( 'Deny', 'wpelevator-oauth-pilot' ); ?>
				</button>
			</p>
		</form>

		<p id="nav">
			<a href="<?php echo esc_url( wp_logout_url( $this->urls->get_consent_url( $request_id ) ) ); ?>">
				<?php esc_html_e( 'Sign in as a different user', 'wpelevator-oauth-pilot' ); ?>
			</a>
		</p>
		<?php
		login_footer();

		exit;
	}
}
