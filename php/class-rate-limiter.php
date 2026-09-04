<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Fixed window counters.
 *
 * The window is anchored at the first attempt and never extended, so a client
 * that keeps hammering a limit cannot hold itself - or, because token limits
 * are keyed by the public client_id, some other client - locked out forever.
 *
 * With a persistent object cache the counter is an atomic increment, which is
 * what makes the count correct under concurrency. Without one the fallback is
 * a read-increment-write against a transient: it undercounts when requests
 * race, which is why the limits that actually bound storage - the active
 * client quotas, the pending authorization quota and request size limits - are
 * enforced with exact queries and request validation instead.
 */
class Rate_Limiter {

	private const PREFIX = 'oauth_pilot_rl_';

	private const GROUP = 'oauth_pilot_rate_limit';

	/**
	 * Record an attempt and report whether it is within the limit.
	 */
	public function attempt( string $key, int $limit, int $window ): bool {
		if ( $limit <= 0 ) {
			return true;
		}

		$window = max( 1, $window );
		$cache_key = md5( $key . '|' . $window );

		$allowed = $this->has_atomic_counter()
			? $this->attempt_atomic( $cache_key, $limit, $window )
			: $this->attempt_transient( self::PREFIX . $cache_key, $limit, $window );

		/**
		 * Override a rate limit decision.
		 *
		 * @param bool   $allowed Whether the attempt is within the limit.
		 * @param string $key     The limit key, already scoped and hashed where needed.
		 * @param int    $limit   Attempts allowed per window.
		 * @param int    $window  Window length in seconds.
		 */
		return (bool) apply_filters( 'oauth_pilot__rate_limit_allowed', $allowed, $key, $limit, $window );
	}

	public function reset( string $key, int $window ): void {
		$cache_key = md5( $key . '|' . max( 1, $window ) );

		if ( $this->has_atomic_counter() ) {
			wp_cache_delete( $cache_key, self::GROUP );

			return;
		}

		delete_transient( self::PREFIX . $cache_key );
	}

	/**
	 * Whether the object cache can carry the counter itself.
	 *
	 * A non-persistent cache is per-request, so it would reset the window on
	 * every request rather than enforcing anything.
	 */
	private function has_atomic_counter(): bool {
		return function_exists( 'wp_using_ext_object_cache' )
			&& wp_using_ext_object_cache()
			&& function_exists( 'wp_cache_incr' );
	}

	/**
	 * wp_cache_add() only sets the expiry when it creates the entry, so the
	 * window start is fixed at the first attempt and later attempts increment
	 * without extending it.
	 */
	private function attempt_atomic( string $cache_key, int $limit, int $window ): bool {
		if ( wp_cache_add( $cache_key, 1, self::GROUP, $window ) ) {
			return true; // First attempt in a fresh window.
		}

		$count = wp_cache_incr( $cache_key, 1, self::GROUP );

		if ( false === $count ) {
			// The entry expired between the add and the incr, or the backend
			// refused to increment a value it did not store as an integer.
			wp_cache_set( $cache_key, 1, self::GROUP, $window );

			return true;
		}

		return (int) $count <= $limit;
	}

	/**
	 * The transient fallback. The stored window start is authoritative: the
	 * remaining lifetime is recomputed on every write so the expiration is
	 * never pushed forward.
	 */
	private function attempt_transient( string $transient_key, int $limit, int $window ): bool {
		$now = time();
		$state = get_transient( $transient_key );

		if ( ! is_array( $state ) || empty( $state['expires_at'] ) || (int) $state['expires_at'] <= $now ) {
			$state = [
				'count' => 0,
				'expires_at' => $now + $window,
			];
		}

		$allowed = (int) $state['count'] < $limit;
		++$state['count'];

		set_transient( $transient_key, $state, max( 1, (int) $state['expires_at'] - $now ) );

		return $allowed;
	}
}
