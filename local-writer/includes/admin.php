<?php
/**
 * The Settings → Local Writer screen (m-wp-plugin-normal-ux): the "normal plugin" config path.
 *
 * Security posture:
 * - The stored HMAC secret is NEVER echoed back into the page (status shows set/unset only;
 *   an empty submit keeps the existing value).
 * - A field locked by a wp-config.php constant is shown disabled with a lock notice — the
 *   constant always wins (see includes/config.php).
 * - manage_options capability + the Settings API's built-in nonce protect the form.
 *
 * @package LocalWriter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Register the options page.
 */
function lw_admin_menu() {
	add_options_page(
		'Local Writer',
		'Local Writer',
		'manage_options',
		'local-writer',
		'lw_render_settings_page'
	);
}

/**
 * Register the settings (one group; sanitize callbacks below).
 */
function lw_admin_init() {
	register_setting( 'local_writer', 'local_writer_hmac_secret', array(
		'type'              => 'string',
		'sanitize_callback' => 'lw_sanitize_secret',
		'default'           => '',
	) );
	register_setting( 'local_writer', 'local_writer_ip_allowlist', array(
		'type'              => 'string',
		'sanitize_callback' => 'lw_sanitize_allowlist',
		'default'           => '',
	) );
	register_setting( 'local_writer', 'local_writer_author_id', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 0,
	) );
	register_setting( 'local_writer', 'local_writer_skew_seconds', array(
		'type'              => 'integer',
		'sanitize_callback' => 'lw_sanitize_skew',
		'default'           => 300,
	) );
}

/**
 * Secret sanitizer: an EMPTY submit keeps the existing stored value (so saving the page never
 * silently wipes the key); whitespace is trimmed; the value itself is opaque.
 *
 * @param string $value Submitted value.
 * @return string
 */
function lw_sanitize_secret( $value ) {
	$value = trim( (string) $value );
	if ( '' === $value ) {
		return (string) get_option( 'local_writer_hmac_secret', '' );
	}
	return $value;
}

/**
 * Allowlist sanitizer: keep a normalized comma-separated list of non-empty trimmed entries.
 *
 * @param string $value Submitted value.
 * @return string
 */
function lw_sanitize_allowlist( $value ) {
	$parts = array_map( 'trim', explode( ',', (string) $value ) );
	return implode( ',', array_values( array_filter( $parts, 'strlen' ) ) );
}

/**
 * Skew sanitizer: a positive integer, defaulting back to 300.
 *
 * @param mixed $value Submitted value.
 * @return int
 */
function lw_sanitize_skew( $value ) {
	$value = absint( $value );
	return $value > 0 ? $value : 300;
}

/**
 * Render the settings screen.
 */
function lw_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$secret_set      = '' !== lw_hmac_secret();
	$secret_locked   = lw_config_is_constant( 'LOCAL_WRITER_HMAC_SECRET' );
	$allow_locked    = lw_config_is_constant( 'LOCAL_WRITER_IP_ALLOWLIST' );
	$author_locked   = lw_config_is_constant( 'LOCAL_WRITER_AUTHOR_ID' );
	$skew_locked     = lw_config_is_constant( 'LOCAL_WRITER_SKEW_SECONDS' );
	$allowlist_value = implode( ',', lw_ip_allowlist() );
	?>
	<div class="wrap">
		<h1>Local Writer</h1>
		<p>
			Connects this site to the Local Writer content tool: signed draft delivery + the
			read-only site inventory/audit routes. The same secret must be set on BOTH sides —
			here and in the tool's local <code>.env</code> as <code>WP_HMAC_SECRET</code>.
		</p>

		<h2 class="title">Status</h2>
		<table class="widefat striped" style="max-width: 680px;">
			<tbody>
				<tr>
					<td>Plugin version</td>
					<td><code><?php echo esc_html( LOCAL_WRITER_VERSION ); ?></code></td>
				</tr>
				<tr>
					<td>Signing secret</td>
					<td>
						<?php if ( $secret_set ) : ?>
							<span style="color: #1e7e34;">&#10004; configured<?php echo $secret_locked ? ' (locked by wp-config.php)' : ''; ?></span>
						<?php else : ?>
							<span style="color: #b32d2e;">&#10008; not configured — every API call is refused until a secret is set</span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td>Endpoint base</td>
					<td><code><?php echo esc_html( rest_url( 'local-writer/v1/' ) ); ?></code></td>
				</tr>
			</tbody>
		</table>

		<form method="post" action="options.php">
			<?php settings_fields( 'local_writer' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="lw-secret">Signing secret (HMAC)</label></th>
					<td>
						<?php if ( $secret_locked ) : ?>
							<input type="password" id="lw-secret" class="regular-text" disabled
								placeholder="defined in wp-config.php (LOCAL_WRITER_HMAC_SECRET)">
							<p class="description">Locked by a wp-config.php constant — remove the constant to manage it here.</p>
						<?php else : ?>
							<input type="password" id="lw-secret" name="local_writer_hmac_secret"
								class="regular-text" value="" autocomplete="new-password"
								placeholder="<?php echo $secret_set ? 'leave empty to keep the current secret' : 'paste or generate a secret'; ?>">
							<button type="button" class="button" id="lw-generate">Generate</button>
							<p class="description">
								The stored value is never displayed. After generating, COPY it into the
								tool's local <code>.env</code> (<code>WP_HMAC_SECRET=...</code>) before saving.
							</p>
							<p id="lw-generated" style="display:none;">
								New secret (copy it now — it will not be shown again):
								<code id="lw-generated-value" style="user-select: all;"></code>
							</p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="lw-allowlist">IP allowlist (optional)</label></th>
					<td>
						<input type="text" id="lw-allowlist" name="local_writer_ip_allowlist"
							class="regular-text" value="<?php echo esc_attr( $allow_locked ? '' : $allowlist_value ); ?>"
							<?php disabled( $allow_locked ); ?>
							placeholder="<?php echo $allow_locked ? 'defined in wp-config.php' : 'e.g. 203.0.113.7, 203.0.113.8'; ?>">
						<p class="description">Comma-separated. Empty = allow any source IP (the signature is always required).</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="lw-author">Author id for created drafts (optional)</label></th>
					<td>
						<input type="number" id="lw-author" name="local_writer_author_id" min="0"
							value="<?php echo esc_attr( $author_locked ? '' : lw_author_id() ); ?>"
							<?php disabled( $author_locked ); ?>>
						<p class="description">0 = the WordPress default author.</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="lw-skew">Signature time window (seconds)</label></th>
					<td>
						<input type="number" id="lw-skew" name="local_writer_skew_seconds" min="30"
							value="<?php echo esc_attr( $skew_locked ? '' : lw_skew_seconds() ); ?>"
							<?php disabled( $skew_locked ); ?>>
						<p class="description">How old a signed request may be (replay window). Default 300.</p>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>
	</div>
	<script>
	(function () {
		var btn = document.getElementById('lw-generate');
		if (!btn) { return; }
		btn.addEventListener('click', function () {
			var bytes = new Uint8Array(32);
			crypto.getRandomValues(bytes);
			var hex = Array.prototype.map.call(bytes, function (b) {
				return ('0' + b.toString(16)).slice(-2);
			}).join('');
			document.getElementById('lw-secret').value = hex;
			document.getElementById('lw-generated-value').textContent = hex;
			document.getElementById('lw-generated').style.display = '';
		});
	}());
	</script>
	<?php
}
