<?php
/**
 * Configuration helpers (m-wp-plugin-normal-ux): the NORMAL path is the settings screen
 * (values in wp_options, like any plugin); wp-config.php constants remain supported as a
 * HARDENING OVERRIDE and ALWAYS WIN — an existing constant-based install keeps working
 * unchanged, and a host that wants secrets out of the DB still can.
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Whether a config value is locked by a wp-config.php constant (the settings screen shows a
 * lock notice and ignores the form value for that field).
 *
 * @param string $constant The constant name.
 * @return bool
 */
function lw_config_is_constant( $constant ) {
	return defined( $constant );
}

/**
 * The shared HMAC signing secret, or '' when unconfigured (the routes then refuse).
 *
 * @return string
 */
function lw_hmac_secret() {
	if ( defined( 'LOCAL_WRITER_HMAC_SECRET' ) ) {
		return (string) LOCAL_WRITER_HMAC_SECRET;
	}
	return (string) get_option( 'local_writer_hmac_secret', '' );
}

/**
 * The IP allowlist as an array of trimmed strings. Empty array = not configured (IP check skipped;
 * the HMAC signature is still required). When non-empty, only listed IPs may reach the endpoint.
 *
 * @return string[]
 */
function lw_ip_allowlist() {
	if ( defined( 'LOCAL_WRITER_IP_ALLOWLIST' ) ) {
		$raw = (string) LOCAL_WRITER_IP_ALLOWLIST;
	} else {
		$raw = (string) get_option( 'local_writer_ip_allowlist', '' );
	}
	$parts = array_map( 'trim', explode( ',', $raw ) );
	return array_values( array_filter( $parts, 'strlen' ) );
}

/**
 * The author id for created posts, or 0 to let WordPress use the default.
 *
 * @return int
 */
function lw_author_id() {
	if ( defined( 'LOCAL_WRITER_AUTHOR_ID' ) ) {
		return (int) LOCAL_WRITER_AUTHOR_ID;
	}
	return (int) get_option( 'local_writer_author_id', 0 );
}

/**
 * The accepted timestamp skew in seconds (mirrors the Python client's default allowed_skew).
 *
 * @return int
 */
function lw_skew_seconds() {
	if ( defined( 'LOCAL_WRITER_SKEW_SECONDS' ) ) {
		return (int) LOCAL_WRITER_SKEW_SECONDS;
	}
	$option = (int) get_option( 'local_writer_skew_seconds', 300 );
	return $option > 0 ? $option : 300;
}
