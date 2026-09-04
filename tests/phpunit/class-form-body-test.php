<?php

namespace WPElevator\OAuth_Pilot_Tests;

use WPElevator\OAuth_Pilot\Http\Form_Body;
use WPElevator\OAuth_Pilot\Http\OAuth_Error;

class Form_Body_Test extends \WP_UnitTestCase {

	public function test_parses_form_encoded_values() {
		$body = Form_Body::parse( 'grant_type=authorization_code&code=abc%20def&client_id=op_1' );

		$this->assertSame(
			'authorization_code',
			$body->get( 'grant_type' ),
			'A plain parameter must be readable.'
		);

		$this->assertSame(
			'abc def',
			$body->get( 'code' ),
			'Percent encoded values must be decoded exactly once.'
		);
	}

	public function test_distinguishes_an_absent_parameter_from_an_empty_one() {
		$body = Form_Body::parse( 'client_secret=' );

		$this->assertTrue(
			$body->has( 'client_secret' ),
			'A present but empty parameter must be reported as present, because it changes client authentication.'
		);

		$this->assertFalse(
			$body->has( 'client_id' ),
			'A parameter that was never sent must not be reported as present.'
		);
	}

	public function test_keeps_the_first_value_and_records_the_duplicate() {
		$body = Form_Body::parse( 'code=first&code=second' );

		$this->assertSame(
			'first',
			$body->get( 'code' ),
			'The parser must not silently adopt the last value the way PHP does.'
		);

		$this->assertSame(
			[ 'code' ],
			$body->get_duplicates(),
			'The repeated parameter must be recorded so the endpoint can reject it.'
		);
	}

	public function test_rejects_repeated_security_parameters() {
		$body = Form_Body::parse( 'code=first&code=second' );

		$this->expectException( OAuth_Error::class );

		$body->assert_no_duplicates( [ 'code' ] );
	}

	public function test_ignores_duplicates_of_parameters_that_do_not_matter() {
		$body = Form_Body::parse( 'code=first&irrelevant=a&irrelevant=b' );

		$body->assert_no_duplicates( [ 'code' ] );

		$this->assertSame(
			'first',
			$body->get( 'code' ),
			'Only the listed security sensitive parameters cause a rejection.'
		);
	}

	public function test_handles_an_empty_body() {
		$body = Form_Body::parse( '' );

		$this->assertSame(
			[],
			$body->all(),
			'An empty request body must parse to no parameters rather than failing.'
		);
	}
}
