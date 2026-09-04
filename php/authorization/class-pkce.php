<?php

namespace WPElevator\OAuth_Pilot\Authorization;

use WPElevator\OAuth_Pilot\Random;

/**
 * RFC 7636 PKCE with the S256 challenge method.
 *
 * The `plain` method is never advertised nor accepted.
 *
 * Static by design: pure functions with no state, like Random.
 */
class PKCE {

	public const METHOD = 'S256';

	private const MIN_LENGTH = 43;

	private const MAX_LENGTH = 128;

	/**
	 * The RFC 7636 code verifier syntax: 43-128 unreserved characters.
	 */
	public static function is_valid_verifier( string $verifier ): bool {
		return (bool) preg_match(
			sprintf( '/^[A-Za-z0-9\-._~]{%d,%d}$/', self::MIN_LENGTH, self::MAX_LENGTH ),
			$verifier
		);
	}

	/**
	 * A challenge is a base64url-encoded SHA-256 digest, so it uses the same
	 * character set and length bounds as a verifier.
	 */
	public static function is_valid_challenge( string $challenge ): bool {
		return self::is_valid_verifier( $challenge );
	}

	public static function challenge_for( string $verifier ): string {
		return Random::base64url_encode( hash( 'sha256', $verifier, true ) );
	}

	public static function verify( string $verifier, string $challenge ): bool {
		if ( ! self::is_valid_verifier( $verifier ) ) {
			return false;
		}

		return hash_equals( $challenge, self::challenge_for( $verifier ) );
	}
}
