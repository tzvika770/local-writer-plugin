<?php
/**
 * JSON-LD injection — print the stored schema into the post's <head> (the AIO value).
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * On a singular Local-Writer post, print its stored JSON-LD as a <script> in <head>.
 * Hooked to wp_head.
 */
function lw_print_jsonld() {
	if ( ! is_singular() ) {
		return;
	}
	$post_id = get_queried_object_id();
	if ( ! $post_id ) {
		return;
	}
	$raw = get_post_meta( $post_id, 'lw_jsonld', true );
	if ( ! $raw ) {
		return;
	}
	$data = json_decode( $raw, true );
	if ( ! is_array( $data ) ) {
		return;
	}
	// Re-encode so the output is canonical JSON; JSON_UNESCAPED_SLASHES is intentionally OFF so a
	// "</script>" inside any string is emitted as "<\/script>" and cannot break out of the tag.
	echo '<script type="application/ld+json">' . wp_json_encode( $data ) . '</script>' . "\n";
}
