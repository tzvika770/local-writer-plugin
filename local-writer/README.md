# Local Writer Receiver (WordPress plugin)

The WordPress side of the Local Writer content tool: receives signed **draft** posts from the
Python client (`src/local_writer/publisher.py`), serves the signed **read** routes (site
inventory + page content for the grounding audit, `src/local_writer/wp_client.py`), and prints
stored JSON-LD. The wire contracts are the source of truth in those two Python module
docstrings; this plugin is the PHP side that mirrors them.

## Install (the normal way)

1. In wp-admin: **Plugins → Add New → Upload Plugin** → choose `local-writer.zip` → Install →
   **Activate**. (Or copy the `local-writer/` folder into `wp-content/plugins/`.)
2. Go to **Settings → Local Writer**, paste or **Generate** a signing secret, and Save.
3. Put the SAME secret in the tool's local `.env` as `WP_HMAC_SECRET`, and the site URL as
   `LW_WP_BASE_URL`. That's it.

If no secret is configured, every API call is refused (403) and nothing is written.

Note: from the settings screen the secret can be REPLACED but never read back or cleared
(deliberate — an accidental save can't wipe or leak it). To remove it entirely, delete the
`local_writer_hmac_secret` option or define the constant instead.

## Updates

Standard one-click updates on the **Plugins** page. Releases are served from the public
channel <https://github.com/tzvika770/local-writer-plugin> via WordPress's native
`Update URI` mechanism (WP ≥ 5.8) — no third-party updater library. That repo carries ONLY
the plugin source + release zips; never a key, never business data. A new release = a new
`update.json` version + zip asset there (see `wordpress-plugin/build_release.py`).

## Configuration

The settings screen stores values in `wp_options` like any plugin. For hardened setups,
`wp-config.php` constants are still supported and **always win** (the settings screen shows a
lock notice for an overridden field):

```php
define( 'LOCAL_WRITER_HMAC_SECRET', '...' );            // the shared signing key
define( 'LOCAL_WRITER_IP_ALLOWLIST', '203.0.113.7' );   // optional — comma-separated
define( 'LOCAL_WRITER_AUTHOR_ID', 1 );                  // optional — author for created posts
define( 'LOCAL_WRITER_SKEW_SECONDS', 300 );             // optional — signature time window
```

## The routes

```
POST {site}/wp-json/local-writer/v1/receive-draft   # write: creates a draft/pending post
POST {site}/wp-json/local-writer/v1/inventory       # read: list pages/posts + Elementor widget index
POST {site}/wp-json/local-writer/v1/page            # read: one post's content + meta (+ _elementor_data)
```

All three use the SAME permission gate. Headers (all required):

| Header            | Meaning                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `Content-Type`    | `application/json`                                                       |
| `X-LW-Timestamp`  | unix seconds when the request was signed                                |
| `X-LW-Nonce`      | single-use random hex (rejected on reuse within the skew window)        |
| `X-LW-Signature`  | `HMAC_SHA256(secret, "{timestamp}\n{nonce}\n{sha256_hex(body)}")` (hex) |
| `Idempotency-Key` | write route only; a repeat returns the first post, never a new one      |

`receive-draft` body (JSON): `{title, content (HTML), status ("draft"|"pending"), page_type,
focus_keyword, jsonld}` (`confidence` is never sent) → `{ "id": <post id>, "status": <status> }`
(`201` on create, `200` on an idempotent repeat). The read routes' request/response shapes are
documented in `src/local_writer/wp_client.py`.

### Auth / security model

Auth **is** the HMAC token — there is no WordPress application-password. The permission gate
checks, in order: IP allowlist (when configured) → HMAC signature (constant-time `hash_equals`)
→ timestamp skew → single-use nonce (a replay within the window is rejected). Any failure
returns `401`/`403` and nothing happens. The read routes expose content the site already serves
publicly; the only write path creates **drafts** behind the human review gate.

## Verifying signing compatibility

The HMAC signing must be byte-identical to the Python client. Committed golden vectors
(`tests/vectors.json` — a FAKE secret, incl. the `read_routes` vectors) pin it on both sides:

- **Python (CI):** `uv run pytest tests/test_wp_plugin_contract.py` asserts `publisher.sign`
  reproduces the vectors.
- **PHP (run locally):** `php tests/test_signing.php` asserts this plugin's `lw_sign`/`lw_verify`
  reproduce the SAME vectors. Expected output ends with `all signing checks passed`, exit 0.

## Deploy-time notes

- **Run the signing harness first:** `php tests/test_signing.php` (expect `all signing checks
  passed`, exit 0) confirms this PHP reproduces the Python client's signatures before going live.
- **IP allowlist + reverse proxies:** the allowlist compares `$_SERVER['REMOTE_ADDR']`, which is the
  *connecting* IP. If WordPress sits behind a proxy / load balancer / CDN, that is the proxy's IP,
  not the client's — so the allowlist is only meaningful when WordPress terminates the connection.
  `X-Forwarded-For` is intentionally NOT trusted (it is client-spoofable). The HMAC signature is the
  primary auth regardless; treat the allowlist as a secondary control.
- **Nonce / idempotency under concurrency:** single-use nonces and the idempotency key are stored in
  WordPress transients with a get-then-set that is best-effort, not atomic. The Python client is
  synchronous (one signed request at a time, a fresh nonce per call), so normal use never races; a
  narrow window exists only for an attacker replaying a captured valid request *in parallel*, and the
  worst case is a few duplicate **draft** posts behind the human review gate. A persistent object
  cache (Redis/Memcached) narrows the window further.

## End-to-end (against a real WordPress site)

With the plugin installed + configured and the client's `.env` pointing at the site
(`LW_WP_BASE_URL` + `WP_HMAC_SECRET`):

```
uv run local-writer-publish --run-id <id> --approve   # publish an approved run as a draft
uv run local-writer-web → עוד ▾ → מלאי האתר            # browse the live site + run a page audit
```

A passing (approved) run is POSTed; the draft appears in *Posts* with the `lw_page_type` /
`lw_focus_keyword` custom fields and the JSON-LD `<script>` in the page `<head>`. Re-running with
the same run reuses the `Idempotency-Key` and does not create a second post.
