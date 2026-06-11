<?php
/**
 * HMAC request signing — the PHP mirror of src/local_writer/publisher.py (_canonical/sign/verify).
 *
 * The canonical string and signature MUST be byte-identical to the Python reference; the committed
 * golden vectors (tests/vectors.json) + tests/test_signing.php pin this.
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'LW_SIGNING_STANDALONE' ) ) {
	exit;
}

/**
 * The exact string that is HMAC-signed: "{timestamp}\n{nonce}\n{sha256_hex(body)}".
 *
 * @param string $timestamp Unix seconds as a string.
 * @param string $nonce     Single-use hex nonce.
 * @param string $body      The raw request body bytes.
 * @return string
 */
function lw_canonical( $timestamp, $nonce, $body ) {
	return $timestamp . "\n" . $nonce . "\n" . hash( 'sha256', $body );
}

/**
 * HMAC-SHA256 hex signature over the canonical string.
 *
 * @param string $secret    Shared signing key.
 * @param string $timestamp Unix seconds as a string.
 * @param string $nonce     Single-use hex nonce.
 * @param string $body      The raw request body bytes.
 * @return string Hex digest.
 */
function lw_sign( $secret, $timestamp, $nonce, $body ) {
	return hash_hmac( 'sha256', lw_canonical( $timestamp, $nonce, $body ), $secret );
}

/**
 * True iff the signature matches AND the timestamp is within $allowed_skew of $now.
 *
 * Constant-time compare via hash_equals; mirrors publisher.verify.
 *
 * @param string $secret       Shared signing key.
 * @param string $timestamp    Unix seconds as a string.
 * @param string $nonce        Single-use hex nonce.
 * @param string $body         The raw request body bytes.
 * @param string $signature    The provided hex signature.
 * @param int    $now          Current unix time.
 * @param int    $allowed_skew Max |now - timestamp| in seconds.
 * @return bool
 */
function lw_verify( $secret, $timestamp, $nonce, $body, $signature, $now, $allowed_skew ) {
	// Require a plain non-negative integer string (the client always sends str(int(time()))).
	// Stricter than is_numeric on purpose: reject floats / scientific notation / signs / spaces so
	// this stays equivalent to the Python reference's int() path (publisher.verify).
	if ( ! ctype_digit( (string) $timestamp ) ) {
		return false;
	}
	if ( abs( $now - (int) $timestamp ) > $allowed_skew ) {
		return false;
	}
	$expected = lw_sign( $secret, $timestamp, $nonce, $body );
	return hash_equals( $expected, (string) $signature );
}
