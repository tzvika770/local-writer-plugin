<?php
/**
 * Plugin Name:       Local Writer Receiver
 * Description:       Receives signed draft posts from the Local Writer client, serves the signed read routes (site inventory + page), and prints stored JSON-LD. Configure under Settings → Local Writer.
 * Version:           0.2.1
 * Requires PHP:      7.4
 * Requires at least: 5.8
 * Author:            Local Writer
 * License:           MIT
 * Update URI:        https://github.com/tzvika770/local-writer-plugin
 *
 * The full wire contract this implements is documented in the Python side,
 * src/local_writer/publisher.py + src/local_writer/wp_client.py (module docstrings).
 * Authenticated REST routes (auth IS the HMAC token — no WordPress application-password):
 *
 *   POST {site}/wp-json/local-writer/v1/receive-draft   (write: creates a DRAFT)
 *   POST {site}/wp-json/local-writer/v1/inventory       (read)
 *   POST {site}/wp-json/local-writer/v1/page            (read)
 *
 * Configuration (m-wp-plugin-normal-ux): the normal path is the SETTINGS SCREEN
 * (Settings → Local Writer — values stored in wp_options like any plugin). wp-config.php
 * constants remain supported as a HARDENING OVERRIDE and always win over the options:
 *
 *   define( 'LOCAL_WRITER_HMAC_SECRET', '....' );           // shared signing key
 *   define( 'LOCAL_WRITER_IP_ALLOWLIST', '203.0.113.7' );   // optional — comma-separated
 *   define( 'LOCAL_WRITER_AUTHOR_ID', 1 );                  // optional — author for created posts
 *   define( 'LOCAL_WRITER_SKEW_SECONDS', 300 );             // optional — signature time window
 *
 * Updates: standard one-click updates on the Plugins page, served from the PUBLIC release
 * channel https://github.com/tzvika770/local-writer-plugin via WordPress's native
 * Update URI mechanism (includes/updater.php). No secret ever lives in that repo.
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

define( 'LOCAL_WRITER_VERSION', '0.2.1' );
define( 'LOCAL_WRITER_DIR', plugin_dir_path( __FILE__ ) );

require_once LOCAL_WRITER_DIR . 'includes/config.php';
require_once LOCAL_WRITER_DIR . 'includes/signing.php';
require_once LOCAL_WRITER_DIR . 'includes/rest.php';
require_once LOCAL_WRITER_DIR . 'includes/schema.php';
require_once LOCAL_WRITER_DIR . 'includes/updater.php';

add_action( 'rest_api_init', 'lw_register_routes' );
add_action( 'wp_head', 'lw_print_jsonld' );
add_filter( 'update_plugins_github.com', 'lw_update_check', 10, 4 );

if ( is_admin() ) {
	require_once LOCAL_WRITER_DIR . 'includes/admin.php';
	add_action( 'admin_menu', 'lw_admin_menu' );
	add_action( 'admin_init', 'lw_admin_init' );
}
