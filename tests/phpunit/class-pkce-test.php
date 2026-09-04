<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Authorization\PKCE;
use WPElevator\OAuth_Pilot\Random;

class PKCE_Test extends \WP_UnitTestCase {

	public function test_generates_the_rfc_7636_s256_challenge() {
		$verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

		$this->assertSame(
			'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			PKCE::challenge_for( $verifier ),
			'The S256 challenge must match the worked example from RFC 7636 appendix B.'
		);
	}

	public function test_accepts_a_valid_verifier() {
		$this->assertTrue(
			PKCE::is_valid_verifier( str_repeat( 'a', 43 ) ),
			'A 43 character unreserved string is the shortest verifier RFC 7636 allows.'
		);

		$this->assertTrue(
			PKCE::is_valid_verifier( str_repeat( 'a', 128 ) ),
			'A 128 character verifier is the longest RFC 7636 allows.'
		);
	}

	public function test_rejects_verifiers_outside_the_allowed_syntax() {
		$this->assertFalse(
			PKCE::is_valid_verifier( str_repeat( 'a', 42 ) ),
			'A verifier shorter than 43 characters carries too little entropy and must be rejected.'
		);

		$this->assertFalse(
			PKCE::is_valid_verifier( str_repeat( 'a', 129 ) ),
			'A verifier longer than 128 characters is outside the RFC 7636 syntax.'
		);

		$this->assertFalse(
			PKCE::is_valid_verifier( str_repeat( 'a', 42 ) . '/' ),
			'A verifier containing a character outside the unreserved set must be rejected.'
		);
	}

	public function test_verifies_only_the_matching_verifier() {
		$verifier = Random::credential();
		$challenge = PKCE::challenge_for( $verifier );

		$this->assertTrue(
			PKCE::verify( $verifier, $challenge ),
			'The verifier that produced the challenge must verify against it.'
		);

		$this->assertFalse(
			PKCE::verify( Random::credential(), $challenge ),
			'A different verifier must never satisfy the stored challenge.'
		);
	}

	public function test_rejects_a_malformed_verifier_before_hashing() {
		$this->assertFalse(
			PKCE::verify( 'short', PKCE::challenge_for( 'short' ) ),
			'A verifier that fails the syntax check must be rejected even when its own hash would match.'
		);
	}

	public function test_generated_credentials_are_base64url_without_padding() {
		$credential = Random::credential();

		$this->assertMatchesRegularExpression(
			'/^[A-Za-z0-9\-_]{43}$/',
			$credential,
			'A 32 byte credential must encode as 43 unpadded base64url characters.'
		);
	}
}
