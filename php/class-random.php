<?php

namespace WPElevator\OAuth_Pilot;

/**
 * Credential generation and hashing primitives.
 *
 * Every credential this plugin hands out is generated here, and only its
 * SHA-256 hash is ever persisted.
 *
 * Static by design: these are pure functions over PHP builtins with no state
 * and nothing to configure, the same shape as agent-pilot's Markdown helper.
 * Injecting them would thread a dependency through every service that mints a
 * credential to buy test seams no test needs.
 */
class Random {

	/**
	 * Bytes of entropy for opaque credentials. 32 bytes is 256 bits.
	 */
	public const CREDENTIAL_BYTES = 32;

	/**
	 * Generate an opaque credential as unpadded base64url.
	 */
	public static function credential(): string {
		return self::base64url_encode( random_bytes( self::CREDENTIAL_BYTES ) );
	}

	/**
	 * Generate a lowercase hexadecimal identifier of the given byte length.
	 */
	public static function hex( int $bytes ): string {
		return bin2hex( random_bytes( $bytes ) );
	}

	/**
	 * The only hash used for stored credentials.
	 */
	public static function hash( string $value ): string {
		return hash( 'sha256', $value );
	}

	/**
	 * Constant-time comparison of a presented credential against a stored hash.
	 */
	public static function hash_equals( string $stored_hash, string $presented_value ): bool {
		return hash_equals( $stored_hash, self::hash( $presented_value ) );
	}

	public static function base64url_encode( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	public static function base64url_decode( string $value ): string {
		return (string) base64_decode( strtr( $value, '-_', '+/' ), true );
	}
}
