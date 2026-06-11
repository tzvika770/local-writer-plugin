<?php
/**
 * Standalone signing known-answer test (no WordPress required).
 *
 *   php tests/test_signing.php
 *
 * Loads the committed golden vectors (vectors.json) — the SAME file the Python CI test
 * (tests/test_wp_plugin_contract.py) pins — and asserts the PHP signing functions reproduce the
 * exact signature and that verify accepts the vector and rejects a tampered body / stale timestamp.
 * Exits 0 on pass, 1 on any failure (so it can gate a deploy script).
 */

define( 'LW_SIGNING_STANDALONE', 1 );
require __DIR__ . '/../includes/signing.php';

$vectors = json_decode( file_get_contents( __DIR__ . '/vectors.json' ), true );
if ( ! is_array( $vectors ) ) {
	fwrite( STDERR, "could not load vectors.json\n" );
	exit( 1 );
}

$failures = 0;

function lw_check( $label, $condition, &$failures ) {
	if ( $condition ) {
		echo "ok   - $label\n";
	} else {
		echo "FAIL - $label\n";
		$failures++;
	}
}

$secret    = $vectors['secret'];
$timestamp = $vectors['timestamp'];
$nonce     = $vectors['nonce'];
$body      = $vectors['body'];
$now       = (int) $timestamp;

lw_check(
	'canonical matches the pinned vector',
	lw_canonical( $timestamp, $nonce, $body ) === $vectors['canonical'],
	$failures
);

$signature = lw_sign( $secret, $timestamp, $nonce, $body );
lw_check(
	'sign reproduces the pinned signature',
	$signature === $vectors['signature'],
	$failures
);

lw_check(
	'verify accepts the pinned vector',
	lw_verify( $secret, $timestamp, $nonce, $body, $vectors['signature'], $now, 300 ),
	$failures
);

lw_check(
	'verify rejects a tampered body',
	! lw_verify( $secret, $timestamp, $nonce, $body . ' tampered', $vectors['signature'], $now, 300 ),
	$failures
);

lw_check(
	'verify rejects a stale timestamp',
	! lw_verify( $secret, $timestamp, $nonce, $body, $vectors['signature'], $now + 301, 300 ),
	$failures
);

// READ-route vectors (h-wp-site-inventory-and-audit): inventory/page ride the SAME signing.
foreach ( array( 'inventory', 'page' ) as $route ) {
	if ( ! isset( $vectors['read_routes'][ $route ] ) ) {
		lw_check( "read-route vector present: $route", false, $failures );
		continue;
	}
	$rv = $vectors['read_routes'][ $route ];
	lw_check(
		"$route canonical matches the pinned vector",
		lw_canonical( $rv['timestamp'], $rv['nonce'], $rv['body'] ) === $rv['canonical'],
		$failures
	);
	lw_check(
		"$route sign reproduces the pinned signature",
		lw_sign( $secret, $rv['timestamp'], $rv['nonce'], $rv['body'] ) === $rv['signature'],
		$failures
	);
	lw_check(
		"$route verify accepts the pinned vector",
		lw_verify( $secret, $rv['timestamp'], $rv['nonce'], $rv['body'], $rv['signature'], (int) $rv['timestamp'], 300 ),
		$failures
	);
}

if ( $failures > 0 ) {
	fwrite( STDERR, "$failures check(s) failed\n" );
	exit( 1 );
}
echo "all signing checks passed\n";
exit( 0 );
