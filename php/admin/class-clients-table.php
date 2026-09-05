<?php

namespace WPElevator\OAuth_Pilot\Admin;

use WP_List_Table;
use WPElevator\OAuth_Pilot\Client\Client;
use WPElevator\OAuth_Pilot\Client\Clients;

/**
 * The registered clients list on the settings screen.
 */
class Clients_Table extends WP_List_Table {

	private const PER_PAGE = 20;

	private Clients $clients;

	private Screen $admin;

	public function __construct( Clients $clients, Screen $admin ) {
		$this->clients = $clients;
		$this->admin = $admin;

		parent::__construct(
			[
				'singular' => 'oauth_pilot_client',
				'plural' => 'oauth_pilot_clients',
				'ajax' => false,
			]
		);
	}

	public function get_columns(): array {
		$columns = [
			'name' => __( 'Name', 'wpelevator-oauth-pilot' ),
			'client_id' => __( 'Client ID', 'wpelevator-oauth-pilot' ),
			'type' => __( 'Type', 'wpelevator-oauth-pilot' ),
			'source' => __( 'Registered', 'wpelevator-oauth-pilot' ),
			'redirect_uris' => __( 'Redirects to', 'wpelevator-oauth-pilot' ),
			'status' => __( 'Status', 'wpelevator-oauth-pilot' ),
			'last_used_at' => __( 'Last used', 'wpelevator-oauth-pilot' ),
		];

		// Registrations are shared across the network, so which site owns one
		// decides who may revoke it and is worth showing.
		if ( is_multisite() ) {
			$columns = array_slice( $columns, 0, 4, true )
				+ [ 'blog' => __( 'Registered on', 'wpelevator-oauth-pilot' ) ]
				+ array_slice( $columns, 4, null, true );
		}

		return $columns;
	}

	public function prepare_items(): void {
		$paged = max( 1, (int) $this->get_pagenum() );

		$args = [
			'limit' => self::PER_PAGE,
			'offset' => ( $paged - 1 ) * self::PER_PAGE,
		];

		$this->items = $this->clients->find( $args );

		$this->set_pagination_args(
			[
				'total_items' => $this->clients->count(),
				'per_page' => self::PER_PAGE,
			]
		);

		$this->_column_headers = [ $this->get_columns(), [], [] ];
	}

	public function no_items(): void {
		esc_html_e( 'No clients have been registered yet.', 'wpelevator-oauth-pilot' );
	}

	/**
	 * @param Client $item
	 */
	public function column_name( $item ): string {
		$actions = [];

		// A client another site registered is shared: this site may stop
		// trusting it, but may not take it away from the rest of the network.
		if ( ! $item->is_managed_by_current_site() ) {
			$actions['revoke_local'] = sprintf(
				'<a href="%s" onclick="return confirm(\'%s\');">%s</a>',
				esc_url( $this->admin->get_client_action_url( 'revoke_local', $item ) ),
				esc_js( __( 'Revoke this site\'s tokens for this client? Other sites on the network keep working.', 'wpelevator-oauth-pilot' ) ),
				esc_html__( 'Revoke access on this site', 'wpelevator-oauth-pilot' )
			);

			return sprintf(
				'<strong>%s</strong>%s',
				esc_html( $item->get_name() ),
				$this->row_actions( $actions )
			);
		}

		if ( $item->is_active() ) {
			$actions['revoke'] = sprintf(
				'<a href="%s" onclick="return confirm(\'%s\');">%s</a>',
				esc_url( $this->admin->get_client_action_url( 'revoke', $item ) ),
				esc_js(
					is_multisite()
						? __( 'Revoke this client and all of its tokens on every site of the network?', 'wpelevator-oauth-pilot' )
						: __( 'Revoke this client and all of its tokens?', 'wpelevator-oauth-pilot' )
				),
				esc_html__( 'Revoke', 'wpelevator-oauth-pilot' )
			);
		}

		$actions['delete'] = sprintf(
			'<a href="%s" onclick="return confirm(\'%s\');">%s</a>',
			esc_url( $this->admin->get_client_action_url( 'delete', $item ) ),
			esc_js(
				is_multisite()
					? __( 'Permanently delete this client from the whole network?', 'wpelevator-oauth-pilot' )
					: __( 'Permanently delete this client?', 'wpelevator-oauth-pilot' )
			),
			esc_html__( 'Delete', 'wpelevator-oauth-pilot' )
		);

		return sprintf(
			'<strong>%s</strong>%s',
			esc_html( $item->get_name() ),
			$this->row_actions( $actions )
		);
	}

	/**
	 * @param Client $item
	 * @param string $column_name
	 */
	public function column_default( $item, $column_name ): string {
		switch ( $column_name ) {
			case 'client_id':
				return sprintf( '<code>%s</code>', esc_html( $item->get_display_client_id() ) );

			case 'type':
				return $item->is_confidential()
					? esc_html__( 'Confidential', 'wpelevator-oauth-pilot' )
					: esc_html__( 'Public', 'wpelevator-oauth-pilot' );

			case 'source':
				if ( $item->is_cimd() ) {
					return esc_html__( 'Self-published (metadata document)', 'wpelevator-oauth-pilot' );
				}

				return $item->is_dynamic()
					? esc_html__( 'Dynamically', 'wpelevator-oauth-pilot' )
					: $this->get_owner_label( $item );

			case 'blog':
				$blog_id = $item->get_blog_id();

				if ( 0 === $blog_id ) {
					return esc_html__( 'The network', 'wpelevator-oauth-pilot' );
				}

				if ( get_current_blog_id() === $blog_id ) {
					return esc_html__( 'This site', 'wpelevator-oauth-pilot' );
				}

				$name = get_blog_option( $blog_id, 'blogname' );

				if ( empty( $name ) ) {
					/* translators: %d: the numeric site id on the network. */
					$name = sprintf( __( 'Site %d', 'wpelevator-oauth-pilot' ), $blog_id );
				}

				return esc_html( $name );

			case 'redirect_uris':
				return implode(
					'<br />',
					array_map(
						fn ( string $uri ): string => sprintf( '<code>%s</code>', esc_html( $uri ) ),
						$item->get_redirect_uris()
					)
				);

			case 'status':
				return $item->is_active()
					? esc_html__( 'Active', 'wpelevator-oauth-pilot' )
					: esc_html__( 'Revoked', 'wpelevator-oauth-pilot' );

			case 'last_used_at':
				$last_used = $item->get_last_used_at();

				return empty( $last_used )
					? esc_html__( 'Never', 'wpelevator-oauth-pilot' )
					: esc_html( $last_used );
		}

		return '';
	}

	/**
	 * Who registered a client an administrator created by hand.
	 *
	 * Only this source records an owner: a dynamic registration has no user
	 * behind it, and a metadata document publishes itself. The owner can also
	 * be missing here, when the account has since been deleted or when the
	 * registration came from WP-CLI without --user, so the anonymous label
	 * remains the fallback rather than an error.
	 */
	private function get_owner_label( Client $item ): string {
		$owner_id = $item->get_owner_user_id();
		$owner = empty( $owner_id ) ? null : get_userdata( $owner_id );

		if ( empty( $owner ) ) {
			return esc_html__( 'By an administrator', 'wpelevator-oauth-pilot' );
		}

		// Returns an empty string when the viewer may not edit that account,
		// which on a network is how a client registered elsewhere stops
		// offering a link into another site's user.
		$edit_url = get_edit_user_link( $owner->ID );

		$name = empty( $edit_url )
			? esc_html( $owner->display_name )
			: sprintf( '<a href="%s">%s</a>', esc_url( $edit_url ), esc_html( $owner->display_name ) );

		return sprintf(
			/* translators: %s: the display name of the administrator who registered the client. */
			esc_html__( 'By %s', 'wpelevator-oauth-pilot' ),
			$name
		);
	}
}
