<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Normalized, redacted security events.
 *
 * Version 1 emits the action only; nothing is persisted. Logging plugins can
 * subscribe today and the storage table stays an additive change.
 *
 * Static by design: the observable contract is the `oauth_pilot__security_event`
 * action, which is what both integrations and tests hook, so there is nothing
 * an injected instance would make substitutable. Revisit this if v2 adds
 * persistence, because a storage backed recorder does need to be injectable.
 */
class Security_Events {

	/**
	 * Context keys that must never reach a log, whatever the caller passed.
	 */
	private const REDACTED_KEYS = [
		'authorization',
		'access_token',
		'refresh_token',
		'client_secret',
		'code',
		'code_verifier',
		'token',
		'password',
	];

	public static function record( string $event, array $context = [] ): void {
		$context = self::redact( $context );

		if ( ! isset( $context['ip_hash'] ) ) {
			$context['ip_hash'] = self::get_ip_hash();
		}

		/**
		 * Fires for every recorded security event.
		 *
		 * @param string $event   Stable event name.
		 * @param array  $context Redacted context. Never contains a credential.
		 */
		do_action( 'oauth_pilot__security_event', $event, $context );
	}

	/**
	 * IP addresses are only ever stored as a keyed hash.
	 */
	public static function get_ip_hash(): string {
		$address = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		if ( '' === $address ) {
			return '';
		}

		return substr( hash_hmac( 'sha256', $address, wp_salt( 'nonce' ) ), 0, 32 );
	}

	private static function redact( array $context ): array {
		foreach ( $context as $key => $value ) {
			if ( in_array( strtolower( (string) $key ), self::REDACTED_KEYS, true ) ) {
				$context[ $key ] = '[redacted]';
				continue;
			}

			if ( is_array( $value ) ) {
				$context[ $key ] = self::redact( $value );
			}
		}

		return $context;
	}
}
