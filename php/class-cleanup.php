<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Scheduled cleanup. Every table this plugin owns is bounded here.
 */
class Cleanup {

	public const HOOK_HOURLY = 'oauth_pilot_cleanup_hourly';

	public const HOOK_DAILY = 'oauth_pilot_cleanup_daily';

	/**
	 * Dynamic and CIMD clients that never completed an authorization.
	 */
	private const UNUSED_DYNAMIC_CLIENT_TTL = DAY_IN_SECONDS;

	/**
	 * Dynamic and CIMD clients that have not been used and hold no live tokens.
	 */
	private const INACTIVE_DYNAMIC_CLIENT_TTL = 90 * DAY_IN_SECONDS;

	private Authorization\Authorizations $authorizations;

	private Token\Tokens $tokens;

	private Client\Clients $clients;

	public function __construct( Authorization\Authorizations $authorizations, Token\Tokens $tokens, Client\Clients $clients ) {
		$this->authorizations = $authorizations;
		$this->tokens = $tokens;
		$this->clients = $clients;
	}

	public function init(): void {
		add_action( self::HOOK_HOURLY, [ $this, 'run_hourly' ] );
		add_action( self::HOOK_DAILY, [ $this, 'run_daily' ] );
		add_action( 'init', [ $this, 'action_schedule_events' ] );
	}

	public function action_schedule_events(): void {
		if ( ! wp_next_scheduled( self::HOOK_HOURLY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::HOOK_HOURLY );
		}

		if ( ! wp_next_scheduled( self::HOOK_DAILY ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', self::HOOK_DAILY );
		}
	}

	public function unschedule_events(): void {
		wp_clear_scheduled_hook( self::HOOK_HOURLY );
		wp_clear_scheduled_hook( self::HOOK_DAILY );
	}

	public function run_hourly(): array {
		return [
			'authorizations' => $this->authorizations->delete_expired(),
		];
	}

	public function run_daily(): array {
		return [
			'tokens' => $this->tokens->delete_expired(),
			'clients' => $this->clients->delete_stale_ephemeral(
				self::UNUSED_DYNAMIC_CLIENT_TTL,
				self::INACTIVE_DYNAMIC_CLIENT_TTL
			),
		];
	}

	public function run_all(): array {
		return array_merge( $this->run_hourly(), $this->run_daily() );
	}

	public function get_next_run(): ?int {
		$next = wp_next_scheduled( self::HOOK_HOURLY );

		return empty( $next ) ? null : (int) $next;
	}
}
