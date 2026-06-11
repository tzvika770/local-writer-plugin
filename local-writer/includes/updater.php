<?php
/**
 * Standard plugin updates via WordPress's NATIVE Update URI mechanism (WP >= 5.8) —
 * no vendored update library (m-wp-plugin-normal-ux).
 *
 * The plugin header declares `Update URI: https://github.com/tzvika770/local-writer-plugin`;
 * core then runs the `update_plugins_github.com` filter during its regular update checks.
 * We fetch a tiny version manifest (update.json) from that PUBLIC repo, and when it carries a
 * newer version WordPress shows the standard "update available" row on the Plugins page and
 * installs the release zip with one click.
 *
 * Security: the manifest lives in a PUBLIC repo that contains ONLY the plugin (never a key,
 * never business data), and the package URL is accepted ONLY when it points back at that same
 * repo (a compromised/MITM'd manifest cannot redirect the install elsewhere over plain data).
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const LW_UPDATE_MANIFEST_URL = 'https://raw.githubusercontent.com/tzvika770/local-writer-plugin/main/update.json';
const LW_UPDATE_REPO_PREFIX  = 'https://github.com/tzvika770/local-writer-plugin/';
const LW_UPDATE_CACHE_KEY    = 'local_writer_update_manifest';

/**
 * Fetch (and cache) the update manifest. Returns null on any failure — updates simply don't
 * show; the plugin keeps working.
 *
 * @return array|null {version: string, package: string}
 */
function lw_fetch_update_manifest() {
	$cached = get_transient( LW_UPDATE_CACHE_KEY );
	if ( is_array( $cached ) ) {
		return $cached;
	}
	$response = wp_remote_get( LW_UPDATE_MANIFEST_URL, array( 'timeout' => 5 ) );
	if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
		return null;
	}
	$manifest = json_decode( wp_remote_retrieve_body( $response ), true );
	if ( ! is_array( $manifest ) || empty( $manifest['version'] ) || empty( $manifest['package'] ) ) {
		return null;
	}
	// The package may ONLY come from the plugin's own public repo (releases assets).
	if ( 0 !== strpos( (string) $manifest['package'], LW_UPDATE_REPO_PREFIX ) ) {
		return null;
	}
	$manifest = array(
		'version' => (string) $manifest['version'],
		'package' => (string) $manifest['package'],
	);
	set_transient( LW_UPDATE_CACHE_KEY, $manifest, 6 * HOUR_IN_SECONDS );
	return $manifest;
}

/**
 * The `update_plugins_github.com` filter: hand core this plugin's latest release info.
 * Core compares versions and renders the standard update UI.
 *
 * @param array|false $update      The update info for this plugin (false = none yet).
 * @param array       $plugin_data The plugin's header data.
 * @param string      $plugin_file The plugin file path relative to the plugins dir.
 * @param array       $locales     Installed locales.
 * @return array|false
 */
function lw_update_check( $update, $plugin_data, $plugin_file, $locales ) {
	if ( 'local-writer/local-writer.php' !== $plugin_file ) {
		return $update;
	}
	$manifest = lw_fetch_update_manifest();
	if ( null === $manifest ) {
		return $update;
	}
	// Offer the update only when the manifest is strictly newer than the installed version.
	if ( version_compare( $manifest['version'], LOCAL_WRITER_VERSION, '<=' ) ) {
		return $update;
	}
	return array(
		'id'      => 'local-writer/local-writer.php',
		'slug'    => 'local-writer',
		'version' => $manifest['version'],
		'url'     => rtrim( LW_UPDATE_REPO_PREFIX, '/' ),
		'package' => $manifest['package'],
	);
}
