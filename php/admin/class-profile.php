<?php

namespace WPElevator\OAuth_Pilot\Admin;

use WP_User;
use WPElevator\OAuth_Pilot\Authorization\Authorizations;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Token\Token;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * The OAuth Applications section on the profile screen.
 */
class Profile {

	private const ACTION_REVOKE = 'oauth_pilot_revoke_grant';

	/**
	 * The query argument that swaps the token list for its full history.
	 */
	private const ARG_HISTORY = 'oauth_pilot_tokens';

	/**
	 * How many token rows the history is willing to render.
	 *
	 * An hourly refresh mints two rows an hour and delete_expired() keeps them
	 * for a week past expiry, so an unbounded history runs to hundreds of rows
	 * that all say the same thing. The cap is a readability bound, not a
	 * security one: wp oauth-pilot token-list has no such limit.
	 */
	private const HISTORY_LIMIT = 200;

	private Clients $clients;

	private Tokens $tokens;

	private Authorizations $authorizations;

	private Screen $admin;

	/**
	 * Client names already resolved during this request, keyed by client id.
	 */
	private array $client_names = [];

	public function __construct( Clients $clients, Tokens $tokens, Authorizations $authorizations, Screen $admin ) {
		$this->clients = $clients;
		$this->tokens = $tokens;
		$this->authorizations = $authorizations;
		$this->admin = $admin;
	}

	public function init(): void {
		add_action( 'show_user_profile', [ $this, 'action_render_section' ] );
		add_action( 'edit_user_profile', [ $this, 'action_render_section' ] );
		add_action( 'admin_post_' . self::ACTION_REVOKE, [ $this, 'action_revoke_grant' ] );
		add_action( 'deleted_user', [ $this, 'action_delete_user_data' ] );
		add_action( 'remove_user_from_blog', [ $this, 'action_remove_user_from_blog' ], 10, 2 );
	}

	public function get_revoke_url( int $user_id, string $client_id, string $resource_uri ): string {
		return wp_nonce_url(
			add_query_arg(
				[
					'action' => self::ACTION_REVOKE,
					'user_id' => $user_id,
					'client_id' => rawurlencode( $client_id ),
					'resource' => rawurlencode( $resource_uri ),
				],
				admin_url( 'admin-post.php' )
			),
			self::ACTION_REVOKE . '_' . $user_id
		);
	}

	/**
	 * The OAuth Applications area of the profile screen.
	 *
	 * One heading over two tables, because they are two views of one thing:
	 * the connections this account has approved, and the credentials those
	 * connections are made of.
	 */
	public function action_render_section( WP_User $user ): void {
		?>
		<h2 id="oauth-pilot-applications">
			<?php esc_html_e( 'OAuth Applications', 'wpelevator-oauth-pilot' ); ?>

			<?php if ( current_user_can( $this->admin->get_capability() ) ) : ?>
				<a class="page-title-action" href="<?php echo esc_url( $this->admin->get_settings_url() ); ?>">
					<?php esc_html_e( 'Configure', 'wpelevator-oauth-pilot' ); ?>
				</a>
			<?php endif; ?>
		</h2>

		<p class="description">
			<?php esc_html_e( 'The applications this account has approved to access the site on its behalf, and the credentials they use to do it. Revoking a connection disconnects the application immediately.', 'wpelevator-oauth-pilot' ); ?>

			<?php if ( is_multisite() ) : ?>
				<?php esc_html_e( 'Both lists cover this site only, because a connection approved on one site of the network does not carry to another.', 'wpelevator-oauth-pilot' ); ?>
			<?php endif; ?>
		</p>

		<h3><?php esc_html_e( 'Connected Applications', 'wpelevator-oauth-pilot' ); ?></h3>

		<?php $this->render_connections( $user ); ?>

		<h3 id="oauth-pilot-tokens"><?php esc_html_e( 'Connection Tokens', 'wpelevator-oauth-pilot' ); ?></h3>

		<?php $this->render_tokens( $user ); ?>
		<?php
	}

	/**
	 * One row per application and resource this account approved, which is the
	 * unit revocation acts on.
	 */
	private function render_connections( WP_User $user ): void {
		$grants = $this->tokens->get_grants_for_user( $user->ID );

		if ( empty( $grants ) ) {
			?>
			<p><?php esc_html_e( 'No applications have been approved for this account.', 'wpelevator-oauth-pilot' ); ?></p>
			<?php

			return;
		}
		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Application', 'wpelevator-oauth-pilot' ); ?></th>
					<th><?php esc_html_e( 'Resource', 'wpelevator-oauth-pilot' ); ?></th>
					<th><?php esc_html_e( 'Permissions', 'wpelevator-oauth-pilot' ); ?></th>
					<th><?php esc_html_e( 'Last used', 'wpelevator-oauth-pilot' ); ?></th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $grants as $grant ) : ?>
					<tr>
						<td><?php echo esc_html( $this->get_client_name( $grant['client_id'] ) ); ?></td>
						<td><code><?php echo esc_html( $grant['resource'] ); ?></code></td>
						<td><?php echo esc_html( implode( ', ', $grant['scopes'] ) ); ?></td>
						<td><?php echo wp_kses( $this->render_datetime( $grant['last_used_at'], __( 'Never', 'wpelevator-oauth-pilot' ) ), $this->get_datetime_allowed_html() ); ?></td>
						<td>
							<?php
							// row-actions is core's inline action styling, and
							// span.delete is what makes it read as destructive.
							// The visible modifier is required because the base
							// class parks the element off screen until its row
							// is hovered, which would hide the only action here
							// from anyone not using a mouse.
							?>
							<div class="row-actions visible">
								<span class="delete">
									<a
										href="<?php echo esc_url( $this->get_revoke_url( $user->ID, $grant['client_id'], $grant['resource'] ) ); ?>"
										onclick="return confirm( '<?php echo esc_js( __( 'Revoke this connection? The application is disconnected immediately and has to be approved again before it can be used.', 'wpelevator-oauth-pilot' ) ); ?>' );"
									>
										<?php esc_html_e( 'Revoke', 'wpelevator-oauth-pilot' ); ?>
									</a>
								</span>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * The credentials behind the connections above.
	 *
	 * Diagnostic rather than actionable. Revocation stays on the connection,
	 * which is the unit that means something: ending a single access token
	 * achieves nothing when the client mints another from its refresh token on
	 * the very next call.
	 */
	private function render_tokens( WP_User $user ): void {
		$show_history = $this->is_showing_history();

		$active_count = $this->tokens->count_for_user( $user->ID, [ 'active_only' => true ] );
		$total_count = $this->tokens->count_for_user( $user->ID );

		if ( 0 === $total_count ) {
			?>
			<p><?php esc_html_e( 'No tokens have been issued to this account.', 'wpelevator-oauth-pilot' ); ?></p>
			<?php

			return;
		}

		$tokens = $this->tokens->find_for_user(
			$user->ID,
			[
				'active_only' => ! $show_history,
				'limit' => self::HISTORY_LIMIT,
			]
		);
		?>
		<p class="description">
			<?php esc_html_e( 'Approving an application issues it a short lived access token and a refresh token that renews it. Rotated, expired and revoked tokens are kept for a while so that a replayed credential can still be recognised.', 'wpelevator-oauth-pilot' ); ?>
		</p>

		<ul class="subsubsub">
			<li>
				<a href="<?php echo esc_url( $this->get_view_url( false ) ); ?>"<?php echo $show_history ? '' : ' class="current" aria-current="page"'; ?>>
					<?php esc_html_e( 'Active', 'wpelevator-oauth-pilot' ); ?>
					<span class="count">(<?php echo esc_html( number_format_i18n( $active_count ) ); ?>)</span>
				</a> |
			</li>
			<li>
				<a href="<?php echo esc_url( $this->get_view_url( true ) ); ?>"<?php echo $show_history ? ' class="current" aria-current="page"' : ''; ?>>
					<?php esc_html_e( 'All', 'wpelevator-oauth-pilot' ); ?>
					<span class="count">(<?php echo esc_html( number_format_i18n( $total_count ) ); ?>)</span>
				</a>
			</li>
		</ul>

		<div class="clear"></div>

		<?php if ( empty( $tokens ) ) : ?>
			<p><?php esc_html_e( 'No active tokens. This account has approved applications that are not connected right now.', 'wpelevator-oauth-pilot' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Application', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Type', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Resource', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Permissions', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Family', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Created', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'wpelevator-oauth-pilot' ); ?></th>
						<th><?php esc_html_e( 'State', 'wpelevator-oauth-pilot' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $tokens as $token ) : ?>
						<tr>
							<td><?php echo esc_html( $this->get_client_name( $token->get_client_id() ) ); ?></td>
							<td><?php echo esc_html( $this->get_type_label( $token->get_type() ) ); ?></td>
							<td><code><?php echo esc_html( $token->get_resource() ); ?></code></td>
							<td><?php echo esc_html( implode( ', ', $token->get_scopes() ) ); ?></td>
							<td><code title="<?php echo esc_attr( $token->get_family_id() ); ?>"><?php echo esc_html( substr( $token->get_family_id(), 0, 8 ) ); ?></code></td>
							<td><?php echo wp_kses( $this->render_datetime( $token->get_created_at() ), $this->get_datetime_allowed_html() ); ?></td>
							<td><?php echo wp_kses( $this->render_datetime( $token->get_expires_at() ), $this->get_datetime_allowed_html() ); ?></td>
							<td><?php echo wp_kses( $this->render_datetime( $token->get_last_used_at(), __( 'Never', 'wpelevator-oauth-pilot' ) ), $this->get_datetime_allowed_html() ); ?></td>
							<td><?php echo esc_html( $this->get_state_label( $token->get_state() ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $show_history && $total_count > count( $tokens ) ) : ?>
				<p class="description">
					<?php
					printf(
						/* translators: 1: number of token rows shown, 2: number of token rows held in total. */
						esc_html__( 'Showing the %1$d most recent of %2$d tokens. Use wp oauth-pilot token-list for the rest.', 'wpelevator-oauth-pilot' ),
						(int) count( $tokens ),
						(int) $total_count
					);
					?>
				</p>
			<?php endif; ?>
		<?php endif; ?>
		<?php
	}

	/**
	 * Whether the request asked for the full history rather than active rows.
	 */
	private function is_showing_history(): bool {
		// A read only display toggle on a screen the viewer already reads.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$value = isset( $_GET[ self::ARG_HISTORY ] ) ? sanitize_key( wp_unslash( $_GET[ self::ARG_HISTORY ] ) ) : '';

		return 'all' === $value;
	}

	/**
	 * The same profile screen showing one of the two token views.
	 *
	 * Built from the current URL rather than from admin_url(), because this
	 * section renders on both profile.php and user-edit.php and the second one
	 * carries a user_id that must survive the round trip.
	 */
	private function get_view_url( bool $show_history ): string {
		$url = $show_history
			? add_query_arg( self::ARG_HISTORY, 'all' )
			: remove_query_arg( self::ARG_HISTORY );

		return $url . '#oauth-pilot-tokens';
	}

	/**
	 * Resolve a client id to its display name once per request.
	 *
	 * The history can run to a couple of hundred rows spanning a handful of
	 * clients, so the lookup is memoized rather than repeated per row.
	 */
	private function get_client_name( string $client_id ): string {
		if ( ! isset( $this->client_names[ $client_id ] ) ) {
			$client = $this->clients->get_by_client_id( $client_id );

			// A deleted registration leaves its tokens behind. Showing the raw
			// id is better than an empty cell: it is what the CLI reports too.
			$this->client_names[ $client_id ] = $client ? $client->get_name() : $client_id;
		}

		return $this->client_names[ $client_id ];
	}

	private function get_type_label( string $type ): string {
		return Token::TYPE_REFRESH === $type
			? __( 'Refresh', 'wpelevator-oauth-pilot' )
			: __( 'Access', 'wpelevator-oauth-pilot' );
	}

	private function get_state_label( string $state ): string {
		switch ( $state ) {
			case Token::STATE_REVOKED:
				return __( 'Revoked', 'wpelevator-oauth-pilot' );

			case Token::STATE_CONSUMED:
				return __( 'Consumed', 'wpelevator-oauth-pilot' );

			case Token::STATE_EXPIRED:
				return __( 'Expired', 'wpelevator-oauth-pilot' );
		}

		return __( 'Active', 'wpelevator-oauth-pilot' );
	}

	/**
	 * A stored UTC timestamp as relative time, keeping the exact value in the
	 * title attribute.
	 *
	 * Every datetime the two tables show goes through this, because two date
	 * formats on one screen read as a bug rather than as a distinction.
	 */
	private function render_datetime( ?string $mysql_utc, string $empty_label = '&mdash;' ): string {
		if ( empty( $mysql_utc ) ) {
			return $empty_label;
		}

		$timestamp = strtotime( $mysql_utc . ' UTC' );

		if ( empty( $timestamp ) ) {
			return $empty_label;
		}

		$now = time();

		$label = $timestamp <= $now
			/* translators: %s: a human readable time difference, such as "5 mins". */
			? sprintf( __( '%s ago', 'wpelevator-oauth-pilot' ), human_time_diff( $timestamp, $now ) )
			/* translators: %s: a human readable time difference, such as "5 mins". */
			: sprintf( __( 'in %s', 'wpelevator-oauth-pilot' ), human_time_diff( $now, $timestamp ) );

		return sprintf(
			'<span title="%s">%s</span>',
			esc_attr( $mysql_utc . ' UTC' ),
			esc_html( $label )
		);
	}

	/**
	 * The markup render_datetime() is allowed to emit.
	 */
	private function get_datetime_allowed_html(): array {
		return [
			'span' => [ 'title' => true ],
		];
	}

	public function action_revoke_grant(): void {
		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0;

		check_admin_referer( self::ACTION_REVOKE . '_' . $user_id );

		// Users may revoke their own grants; administrators may revoke anyone's.
		if ( get_current_user_id() !== $user_id && ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to revoke this authorization.', 'wpelevator-oauth-pilot' ) );
		}

		$client_id = isset( $_GET['client_id'] ) ? sanitize_text_field( wp_unslash( $_GET['client_id'] ) ) : '';
		$resource_uri = isset( $_GET['resource'] ) ? sanitize_url( wp_unslash( $_GET['resource'] ) ) : '';

		$this->tokens->revoke_grant( $user_id, $client_id, $resource_uri );

		Security_Events::record(
			'grant_revoked_by_user',
			[
				'client_id' => $client_id,
				'user_id' => $user_id,
			]
		);

		wp_safe_redirect( add_query_arg( [ 'user_id' => $user_id ], admin_url( 'user-edit.php' ) ) . '#oauth-pilot-applications' );

		exit;
	}

	/**
	 * A deleted user keeps no grants behind, on any site of the network.
	 *
	 * This hook fires when the account itself is gone, so the cleanup is not
	 * scoped to the site that happened to run the deletion.
	 */
	public function action_delete_user_data( int $user_id ): void {
		$this->tokens->revoke_for_user_on_every_site( $user_id );
		$this->tokens->delete_for_user_on_every_site( $user_id );
		$this->authorizations->delete_for_user_on_every_site( $user_id );
	}

	/**
	 * Losing membership of a site ends that site's grants and nothing else.
	 *
	 * The account and its grants on other sites survive; the tokens that were
	 * issued against capabilities this user no longer has do not.
	 */
	public function action_remove_user_from_blog( int $user_id, int $blog_id ): void {
		if ( ! is_multisite() ) {
			return;
		}

		switch_to_blog( $blog_id );

		$this->tokens->revoke_for_user( $user_id );
		$this->tokens->delete_for_user( $user_id );
		$this->authorizations->delete_for_user( $user_id );

		restore_current_blog();
	}
}
