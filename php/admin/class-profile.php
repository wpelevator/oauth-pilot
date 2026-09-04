<?php

namespace WPElevator\OAuth_Pilot\Admin;

use WP_User;
use WPElevator\OAuth_Pilot\Client\Clients;
use WPElevator\OAuth_Pilot\Security_Events;
use WPElevator\OAuth_Pilot\Token\Tokens;

/**
 * The Authorized Applications section on the profile screen.
 */
class Profile {

	private const ACTION_REVOKE = 'oauth_pilot_revoke_grant';

	private Clients $clients;

	private Tokens $tokens;

	public function __construct( Clients $clients, Tokens $tokens ) {
		$this->clients = $clients;
		$this->tokens = $tokens;
	}

	public function init(): void {
		add_action( 'show_user_profile', [ $this, 'action_render_grants' ] );
		add_action( 'edit_user_profile', [ $this, 'action_render_grants' ] );
		add_action( 'admin_post_' . self::ACTION_REVOKE, [ $this, 'action_revoke_grant' ] );
		add_action( 'deleted_user', [ $this, 'action_delete_user_data' ] );
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

	public function action_render_grants( WP_User $user ): void {
		$grants = $this->tokens->get_grants_for_user( $user->ID );
		?>
		<h2 id="oauth-pilot-applications"><?php esc_html_e( 'Authorized Applications', 'wpelevator-oauth-pilot' ); ?></h2>

		<?php if ( empty( $grants ) ) : ?>
			<p><?php esc_html_e( 'No applications have been authorized for this account.', 'wpelevator-oauth-pilot' ); ?></p>
		<?php else : ?>
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
						<?php $client = $this->clients->get_by_client_id( $grant['client_id'] ); ?>
						<tr>
							<td><?php echo esc_html( $client ? $client->get_name() : $grant['client_id'] ); ?></td>
							<td><code><?php echo esc_html( $grant['resource'] ); ?></code></td>
							<td><?php echo esc_html( implode( ', ', $grant['scopes'] ) ); ?></td>
							<td><?php echo esc_html( empty( $grant['last_used_at'] ) ? __( 'Never', 'wpelevator-oauth-pilot' ) : $grant['last_used_at'] ); ?></td>
							<td>
								<a class="button" href="<?php echo esc_url( $this->get_revoke_url( $user->ID, $grant['client_id'], $grant['resource'] ) ); ?>">
									<?php esc_html_e( 'Revoke', 'wpelevator-oauth-pilot' ); ?>
								</a>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
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
	 * A deleted user keeps no grants behind.
	 */
	public function action_delete_user_data( int $user_id ): void {
		$this->tokens->revoke_for_user( $user_id );
		$this->tokens->delete_for_user( $user_id );
	}
}
