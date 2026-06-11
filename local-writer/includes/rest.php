<?php
/**
 * The REST routes: the write route (receive-draft) plus the two READ routes
 * (inventory / page — h-wp-site-inventory-and-audit). All POST-with-body on the SAME
 * lw_permission_check (HMAC + skew + single-use nonce + IP allowlist) — POST by design so
 * the read requests ride the exact existing canonical-string signing.
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Register the routes. Everything else on this namespace is absent (404).
 */
function lw_register_routes() {
	register_rest_route(
		'local-writer/v1',
		'/receive-draft',
		array(
			'methods'             => 'POST',
			'callback'            => 'lw_handle_receive_draft',
			'permission_callback' => 'lw_permission_check',
		)
	);
	register_rest_route(
		'local-writer/v1',
		'/inventory',
		array(
			'methods'             => 'POST',
			'callback'            => 'lw_handle_inventory',
			'permission_callback' => 'lw_permission_check',
		)
	);
	register_rest_route(
		'local-writer/v1',
		'/page',
		array(
			'methods'             => 'POST',
			'callback'            => 'lw_handle_page',
			'permission_callback' => 'lw_permission_check',
		)
	);
}

/**
 * The auth gate: IP allowlist -> HMAC signature -> timestamp skew -> single-use nonce.
 * Any failure returns a WP_Error (401/403) and the post callback never runs.
 *
 * @param WP_REST_Request $request The request.
 * @return true|WP_Error
 */
function lw_permission_check( $request ) {
	$secret = lw_hmac_secret();
	if ( '' === $secret ) {
		return new WP_Error( 'lw_unconfigured', 'Plugin is not configured (LOCAL_WRITER_HMAC_SECRET missing).', array( 'status' => 403 ) );
	}

	// IP allowlist — enforced only when configured (the HMAC signature is always required).
	$allowlist = lw_ip_allowlist();
	if ( ! empty( $allowlist ) ) {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( ! in_array( $remote, $allowlist, true ) ) {
			return new WP_Error( 'lw_forbidden_ip', 'Source IP is not on the allowlist.', array( 'status' => 403 ) );
		}
	}

	$timestamp = $request->get_header( 'X-LW-Timestamp' );
	$nonce     = $request->get_header( 'X-LW-Nonce' );
	$signature = $request->get_header( 'X-LW-Signature' );
	if ( ! $timestamp || ! $nonce || ! $signature ) {
		return new WP_Error( 'lw_missing_auth', 'Missing authentication headers.', array( 'status' => 401 ) );
	}

	$body = $request->get_body();
	if ( ! lw_verify( $secret, $timestamp, $nonce, $body, $signature, time(), lw_skew_seconds() ) ) {
		return new WP_Error( 'lw_bad_signature', 'Invalid signature or stale timestamp.', array( 'status' => 401 ) );
	}

	// Single-use nonce (replay defense). The transient TTL = the skew window: a nonce cannot be
	// reused while its timestamp is still fresh, and after the window the skew check rejects it.
	// NOTE: this get-then-set is best-effort, not atomic. The Python client is synchronous (one
	// request at a time, a fresh nonce per call), so legitimate use never races; a narrow TOCTOU
	// window exists only if an attacker replays a captured valid request CONCURRENTLY, and the worst
	// case is a few duplicate DRAFT posts behind the human review gate. A persistent object cache
	// (Redis/Memcached) tightens this; see README "Deploy-time notes".
	$nonce_key = 'lw_nonce_' . $nonce;
	if ( get_transient( $nonce_key ) ) {
		return new WP_Error( 'lw_replayed_nonce', 'Nonce has already been used.', array( 'status' => 401 ) );
	}
	set_transient( $nonce_key, 1, lw_skew_seconds() );

	return true;
}

/**
 * Create the draft/pending post (or return the idempotent first one). Auth already passed.
 *
 * @param WP_REST_Request $request The request.
 * @return WP_REST_Response|WP_Error
 */
function lw_handle_receive_draft( $request ) {
	// Idempotency: a repeated key returns the first post, never a second one.
	$idem_key = $request->get_header( 'Idempotency-Key' );
	if ( $idem_key ) {
		$existing = get_transient( 'lw_idem_' . $idem_key );
		if ( $existing ) {
			$post = get_post( (int) $existing );
			if ( $post ) {
				return new WP_REST_Response( array( 'id' => (int) $existing, 'status' => $post->post_status ), 200 );
			}
		}
	}

	$params = json_decode( $request->get_body(), true );
	if ( ! is_array( $params ) ) {
		return new WP_Error( 'lw_bad_body', 'Request body is not a JSON object.', array( 'status' => 400 ) );
	}

	$status = isset( $params['status'] ) ? (string) $params['status'] : 'draft';
	if ( ! in_array( $status, array( 'draft', 'pending' ), true ) ) {
		$status = 'draft';
	}
	$title   = isset( $params['title'] ) ? (string) $params['title'] : '';
	$content = isset( $params['content'] ) ? (string) $params['content'] : '';
	if ( '' === trim( $title ) && '' === trim( wp_strip_all_tags( $content ) ) ) {
		return new WP_Error( 'lw_empty', 'Both title and content are empty.', array( 'status' => 400 ) );
	}

	$postarr = array(
		'post_title'   => wp_strip_all_tags( $title ),
		'post_content' => $content, // trusted, profile-grounded HTML from the client.
		'post_status'  => $status,
		'post_type'    => 'post',
	);
	$author = lw_author_id();
	if ( $author > 0 ) {
		$postarr['post_author'] = $author;
	}

	$post_id = wp_insert_post( $postarr, true );
	if ( is_wp_error( $post_id ) ) {
		return new WP_Error( 'lw_insert_failed', $post_id->get_error_message(), array( 'status' => 500 ) );
	}

	if ( isset( $params['page_type'] ) ) {
		update_post_meta( $post_id, 'lw_page_type', sanitize_text_field( (string) $params['page_type'] ) );
	}
	if ( isset( $params['focus_keyword'] ) ) {
		update_post_meta( $post_id, 'lw_focus_keyword', sanitize_text_field( (string) $params['focus_keyword'] ) );
	}
	if ( isset( $params['jsonld'] ) && is_array( $params['jsonld'] ) ) {
		// Store as a JSON string; re-encoded + escaped at output time (schema.php).
		update_post_meta( $post_id, 'lw_jsonld', wp_json_encode( $params['jsonld'] ) );
	}

	if ( $idem_key ) {
		// Same best-effort caveat as the nonce: the lookup above + this set are not atomic. A
		// sequential client retry (the real case — the CLI is synchronous) hits the stored mapping
		// correctly; only truly concurrent duplicates could slip a second post past it.
		set_transient( 'lw_idem_' . $idem_key, $post_id, 30 * DAY_IN_SECONDS );
	}

	return new WP_REST_Response( array( 'id' => (int) $post_id, 'status' => $status ), 201 );
}

/**
 * Walk an Elementor element tree collecting widget entries.
 *
 * @param array $elements Elementor element list.
 * @param array $out      Accumulator of widget rows (by reference).
 */
function lw_collect_widgets( $elements, &$out ) {
	foreach ( $elements as $el ) {
		if ( ! is_array( $el ) ) {
			continue;
		}
		if ( isset( $el['elType'] ) && 'widget' === $el['elType'] ) {
			$type   = isset( $el['widgetType'] ) ? (string) $el['widgetType'] : '';
			$source = 'local';
			if ( 'global' === $type || ! empty( $el['templateID'] ) ) {
				// A global-widget placeholder: its content lives in a SEPARATE elementor_library
				// post — editing it in-page is a silent no-op (HR6).
				$source = 'global';
			} elseif ( ! empty( $el['settings']['__dynamic__'] ) ) {
				$source = 'dynamic';
			}
			$out[] = array(
				'widget_id'     => isset( $el['id'] ) ? (string) $el['id'] : '',
				'widget_type'   => $type,
				'widget_source' => $source,
			);
		}
		if ( isset( $el['elements'] ) && is_array( $el['elements'] ) ) {
			lw_collect_widgets( $el['elements'], $out );
		}
	}
}

/**
 * The post's Elementor widget index: [{widget_id, widget_type, widget_source}] (HR6 prep —
 * task 2's refresh.py refuses to edit any widget whose source is not 'local').
 * Non-Elementor posts return an empty array.
 *
 * @param int $post_id The post id.
 * @return array
 */
function lw_widget_index( $post_id ) {
	$raw = get_post_meta( $post_id, '_elementor_data', true );
	if ( ! is_string( $raw ) || '' === $raw ) {
		return array();
	}
	$data = json_decode( $raw, true );
	if ( ! is_array( $data ) ) {
		return array();
	}
	$out = array();
	lw_collect_widgets( $data, $out );
	return $out;
}

/**
 * Unicode-aware word count. str_word_count is ASCII-letter-based — a Hebrew page would count
 * near zero, and the inventory column feeds the "what's on the site" judgment.
 *
 * @param string $html The post content (HTML).
 * @return int
 */
function lw_word_count( $html ) {
	$text  = wp_strip_all_tags( $html );
	$count = preg_match_all( '/\p{L}[\p{L}\p{Mn}\p{Pd}\'\x{2019}\x{05F3}\x{05F4}]*/u', $text, $matches );
	return false === $count ? 0 : (int) $count;
}

/**
 * READ: list pages/posts (id, title, slug, status, modified, word count, lw_* meta, widget
 * index). Auth already passed. Returns a JSON ARRAY of rows (the wire contract is documented
 * in src/local_writer/wp_client.py).
 *
 * @param WP_REST_Request $request The request.
 * @return WP_REST_Response|WP_Error
 */
function lw_handle_inventory( $request ) {
	$params = json_decode( $request->get_body(), true );
	if ( ! is_array( $params ) ) {
		return new WP_Error( 'lw_bad_body', 'Request body is not a JSON object.', array( 'status' => 400 ) );
	}
	$post_type = isset( $params['post_type'] ) ? sanitize_key( (string) $params['post_type'] ) : '';
	$status    = isset( $params['status'] ) ? sanitize_key( (string) $params['status'] ) : '';
	$page      = isset( $params['page'] ) ? max( 1, (int) $params['page'] ) : 1;
	$per_page  = isset( $params['per_page'] ) ? max( 1, min( 100, (int) $params['per_page'] ) ) : 100;
	// LIGHT mode (m-site-inventory-filters): titles-only rows — no widget walk, no word count,
	// no lw_* meta. Keeps listing a 500+ blog-post flood cheap (the MVP "know they exist" index).
	$light = isset( $params['fields'] ) && 'light' === (string) $params['fields'];

	$query = new WP_Query(
		array(
			'post_type'      => $post_type ? $post_type : array( 'post', 'page' ),
			'post_status'    => $status ? $status : 'any',
			'posts_per_page' => $per_page,
			'paged'          => $page,
			'orderby'        => 'ID',
			'order'          => 'ASC',
		)
	);

	$rows = array();
	foreach ( $query->posts as $post ) {
		$row = array(
			'id'       => (int) $post->ID,
			'title'    => $post->post_title,
			'slug'     => $post->post_name,
			'status'   => $post->post_status,
			'modified' => $post->post_modified,
		);
		if ( ! $light ) {
			$row['word_count']       = lw_word_count( $post->post_content );
			$row['lw_page_type']     = (string) get_post_meta( $post->ID, 'lw_page_type', true );
			$row['lw_focus_keyword'] = (string) get_post_meta( $post->ID, 'lw_focus_keyword', true );
			$row['widgets']          = lw_widget_index( $post->ID );
		}
		$rows[] = $row;
	}
	return new WP_REST_Response( $rows, 200 );
}

/**
 * READ: one post's full content + meta. Auth already passed. `elementor_data` rides along
 * because an Elementor page's post_content is EMPTY (the page's real text lives in the
 * _elementor_data postmeta) — without it the Python-side audit would read nothing.
 *
 * @param WP_REST_Request $request The request.
 * @return WP_REST_Response|WP_Error
 */
function lw_handle_page( $request ) {
	$params = json_decode( $request->get_body(), true );
	if ( ! is_array( $params ) || empty( $params['id'] ) ) {
		return new WP_Error( 'lw_bad_body', 'Request body must be a JSON object with a post id.', array( 'status' => 400 ) );
	}
	$post = get_post( (int) $params['id'] );
	if ( ! $post ) {
		return new WP_Error( 'lw_not_found', 'No post with that id.', array( 'status' => 404 ) );
	}
	$elementor_raw = get_post_meta( $post->ID, '_elementor_data', true );
	return new WP_REST_Response(
		array(
			'id'               => (int) $post->ID,
			'title'            => $post->post_title,
			'slug'             => $post->post_name,
			'status'           => $post->post_status,
			'modified'         => $post->post_modified,
			'content'          => $post->post_content,
			'lw_page_type'     => (string) get_post_meta( $post->ID, 'lw_page_type', true ),
			'lw_focus_keyword' => (string) get_post_meta( $post->ID, 'lw_focus_keyword', true ),
			'widgets'          => lw_widget_index( $post->ID ),
			'elementor_data'   => is_string( $elementor_raw ) ? $elementor_raw : '',
		),
		200
	);
}
