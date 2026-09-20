# funnypot-wordpress 🍯

[![Docs](https://img.shields.io/badge/docs-funnypot.org-f46800.svg)](https://funnypot.org/packages/funnypot-wordpress/)

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → [funnypot-app](https://github.com/metrictower/funnypot-app)
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → funnypot-wordpress **← you are here**
> - Detection **and** IP reporting in any PHP app, batteries included → [funnypot](https://github.com/metrictower/funnypot)
> - Embedding the deception/detection **engine** in your own PHP / PSR-15 app → [funnypot-core](https://github.com/metrictower/funnypot-core)
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → [funnypot-policy](https://github.com/metrictower/funnypot-policy)

A **thin WordPress adapter** over the [`metrictower/funnypot-policy`](../funnypot-policy) decision
engine. The plugin does **not** decide whether a request is an attack, whether to deceive, block, or
report — that is the shared policy engine's job. D only:

1. **normalizes** the WP request into a neutral `RequestEvidence` + a `WpSiteProfile` (the real-route
   oracle — the one job only WordPress can do),
2. asks `Funnypot\Policy\PolicyEngine::evaluate()` for a `Decision`, and
3. **executes** that `Decision`: `allow`/`log` → WordPress proceeds; `deceive` → emit core's byte-exact
   fake and exit before the theme loads; `block` → emit an honest app-chosen `403`.

All decision logic (cheapest-first precedence, learn-then-enforce, pin/TTL, report suppression) lives
once in `funnypot-policy`. The deception content is core's (`metrictower/funnypot-core`), unchanged.

## Status

**Inert by default.** A fresh install decides nothing until an operator enables a posture. Reputation
checking and reporting are each off, and both require a `MAINNET_KEY`.

The plugin code is **PHP 7.3-clean** (old WP hosts run old PHP), and the bundled `funnypot-core` is now
PHP **7.3+** too — the 7.3 re-floor and the two-phase `classify()`/`synthesize()` split shipped in core
`v0.0.1`.

## Install

### As a downloadable zip (recommended for WP hosts)

`bin/build.sh` (see *Build*) produces `build/funnypot-wordpress.zip` with
`vendor/metrictower/{funnypot-policy,funnypot-core,mainnet-client}/` and core's rules artifacts
bundled. Upload it under **Plugins → Add New → Upload Plugin**, then activate.

### As a Composer package

```
composer require metrictower/funnypot-wordpress
```

On activation the plugin creates its tables, generates a per-install `sensor_id`, and copies a
must-use loader shim into `wp-content/mu-plugins/` so the BEFORE position runs at the earliest hook. If
that directory is not writable it falls back to `plugins_loaded` and raises an admin notice.

## Configure

**Settings → Honeypot** produces the policy config array. Key choices:

- **Posture:** `honeypot` (FALLBACK — upgrade a genuine 404, FP-free), `WAF` (BEFORE — block/deceive
  ahead of routing), or `both`.
- **Response mode** — the primary behaviour selector, composed in the plugin from two engine seams:
  - `stealth` — capture-only. The hit is logged + reported, then WordPress serves its own **plain 404
    on every band** (every non-`allow` action band is clamped to `log`, decoys are forced off). No
    decoy, no 403 — the lowest fingerprint, pure intel.
  - `realistic` (default) — byte-exact core template fakes, versioned decoys, and the authed wp-admin
    skin when armed. Reproduces the plugin's prior default behaviour exactly.
  - `taunt` — the troll "nice try" persona layered over the same decoy; still only ever **upgrades a
    404** (any engine fault degrades to a plain 404, never a 5xx).

  The old `response_style` field is folded into `response_mode`: on upgrade an install with no saved
  mode derives it from its legacy style (`taunt`→`taunt`, `realistic`/`minimal`→`realistic`). A legacy
  `minimal` install therefore moves to `realistic`, which serves richer fake bodies than core's terse
  `minimal` tokens — intentional, since core `minimal` still emits a matcher-satisfying fake and is not
  the capture-only stealth mode.
- **Decoys** — `decoy_xmlrpc` and `decoy_wp_login` (both off by default) toggle the xmlrpc and wp-login
  decoys; `decoy_session_key` (a per-deploy secret) arms the wp-login mock-auth authed dashboard. All
  are forced off in stealth mode.
- **Login relocation (`login_relocation_enabled` + `login_slug`, off by default):** moves the real
  WordPress login to a secret slug (`/your-slug`) and inverts the vacated default — every hit on
  `/wp-login.php` (and the anon `/wp-admin` bounce that lands there) is now an attacker, so it serves
  the wp-login mock-auth decoy (auto-armed when relocation is active) + WP-native capture, with zero
  false positives from real users. The technique is re-derived from WPS Hide Login (no code vendored):
  no core files are renamed and no rewrite rules are added, so **deactivating the plugin (or clearing
  the slug) restores `/wp-login.php` immediately**. Key behaviours and caveats:
  - **No-lockout / fail-open:** the slug is allowlisted from the engine (a hard `safe-path` allow under
    every posture), an invalid/empty slug leaves relocation off (the real login is untouched), an
    authenticated operator and `action=postpass` (password-protected posts) are carved out to the real
    login, and every hook degrades to the real login on any fault — never a lockout, never a 5xx.
  - **Slug-leak guard (divergence from WPS Hide Login):** login-URL rewriting is scoped to the slug
    page itself + authenticated contexts. `login_url` is **never** rewritten for anonymous requests, so
    an anon `/wp-admin` bounce and front-end login links resolve to the **default** `/wp-login.php` (the
    decoy), never the slug. **Bookmark the slug** — `/wp-admin` deliberately does not auto-bounce to the
    real login (that would hand the secret to any attacker who probes `/wp-admin`).
  - **Scope:** relocation does **not** hide REST (`/wp-json`) or XML-RPC (`xmlrpc.php`) authentication —
    they bypass `wp-login.php` and are covered separately by WP-native capture + the xmlrpc decoy. Most
    effective in `realistic`/`taunt` (stealth serves no decoy — the vacated default is capture-only and
    the real login stays reachable there). **Single-site only in v1** (multisite is a clean no-op). A
    page cache in front of WordPress should exclude the slug and `/wp-login.php` from caching.
- **Advanced: real-route actions / severity ceiling / attack emulation / nuclei reflection** — how a
  fake looks and which per-band action (`allow`/`log`/`block`/`deceive`) runs within realistic/taunt.
- **Plugin/theme enumeration absorber (on by default):** a real site runs ~10-30 plugins, so a
  request for `/wp-content/plugins/<slug>/readme.txt` (or a theme `style.css`) whose slug is **not
  installed** is an unambiguous enumeration probe. When on, `WpSiteProfile` consults the installed set
  (from `get_plugins()`/`wp_get_themes()`, cached in a transient and refreshed on
  (de)activation / theme switch / upgrade — never called on the request path) so an uninstalled-slug
  probe becomes sacrificial and the policy engine deceives + reports it; an installed slug stays a real
  route. A nuclei-wordfence sweep is 80k+ requests, so the burst is **absorbed**: per source, a 60s
  window collapses to one local `mass_plugin_scan` rollup row (with a probed-slug count + sample), not
  one row per probe. `enum_escalate_threshold` sets the per-window escalation point; `enum_auto_ban`
  (off by default) blocks a source past it for `enum_ban_ttl_secs`. Fail-safe: a cold/unwarmed installed
  set reverts to the historical blanket behavior, so a genuine installed asset is never flagged. Turn
  the absorber off to restore blanket `/wp-content/plugins|themes/` handling.
- **WP-native capture (`wp_native_capture`, off by default):** captures attacks that WordPress handles
  itself — and which therefore never reach the Interceptor — into the **local** hit store by hooking
  WP's own pipelines: `wp_login_failed` (credential stuffing), `xmlrpc_call` (`system.multicall`
  amplification, `wp.getUsersBlogs` credential probing, `pingback.ping`), and REST
  (`rest_authentication_errors`, `rest_user_query` user-enumeration). Capture-only: the REST filters
  return their incoming value **unchanged**, so login/xmlrpc/REST behaviour is byte-identical whether
  it is on or off. **Local intel only — nothing new is sent to mainnet** (it never builds a report
  intent or calls the reporter). It never logs a real credential: the password is never in scope (it
  hooks `wp_login_failed`, not `authenticate`), and a real-account failure is anonymised via a
  `username_exists()` self-guard — no submitted username/password/XML-RPC arg/pingback URL is ever
  stored, only IP + a fixed opaque reason + a bounded User-Agent. Durable rows are **rollup-gated** per
  IP per channel per 60s window exactly like the enumeration absorber, so a single `system.multicall`
  with N sub-calls (N `xmlrpc_call` fires) writes at most one hit row — the burst is captured as the
  per-IP aggregate count (velocity), not as N rows. Every callback is degrade-safe: a capture fault
  never breaks WP login/xmlrpc/REST.
- **XML-RPC pingback shield (`wp_pingback_shield`, off by default):** neutralizes the classic
  `pingback.ping` SSRF / DDoS-reflection vector on a **real** WordPress site. It hooks WordPress's own
  `pingback_ping_source_uri` filter at priority 1 (before WP's `wp_http_validate_url`), captures a
  bounded, sanitized copy of the attacker-chosen **source URI** — the URL WordPress would fetch, i.e.
  the SSRF/DDoS target — into a local `pingback` channel, then returns `''` so `pingback_ping()` faults
  with its own canonical *"A valid URL was not provided."* error **before** `wp_safe_remote_get`. Two
  independent no-fetch guarantees hold: **no HTTP/socket primitive exists anywhere on this path** (SSRF-
  safe by construction), and returning `''` makes WordPress short-circuit before its own fetch — so the
  operator's real site can never be coerced into an open pingback relay. Unlike WP-native capture this
  **changes what `xmlrpc.php` returns for `pingback.ping`** (matching WordPress's own validation fault,
  so it is not a tell), which is why it has a **dedicated opt-in toggle**. Off/unconfirmed ⇒ the filter
  returns the source **unchanged** (native WP behaviour); on ⇒ it always short-circuits, even on a
  capture fault. The captured URL is **local intel only** — never a durable-row column (no schema
  change), never a report intent, never relayed to mainnet — stored as a bounded distinct sample
  (≤ 8 URLs, each ≤ 255 chars, control chars stripped) in the per-IP aggregate slot, rollup-gated to one
  durable row per IP per 60s window so a pingback flood cannot exhaust the table.
- **Reputation (verdict-first):** `check_enabled` + `block_verdicts` (default `malicious`, `critical`)
  + optional `min_block_score`. Cache-first, fail-open, never a synchronous request-path call. Off by
  default; requires `MAINNET_KEY`.
- **Country policy (optional):** deny-list or allow-list; action defaults to `score-modifier` (a hard
  `block` in the honeypot posture is a tell — eyes-open opt-in). Resolved from a **local** GeoIP DB.
- **Reporting:** off by default; `mainnet_base_url` (scheme+host only) + `MAINNET_KEY` + `self_ips`
  (the operator's own egress, never reported).

### wp-config.php constants (override the stored settings)

```php
define('HONEYPOT_WP_MAINNET_BASE_URL', 'https://mainnet.example');  // scheme+host only
define('HONEYPOT_WP_MAINNET_KEY', '…');                             // a sensor-tier key
```

Reporting/checking are **inert without a key**. The single key is a mainnet **`sensor`**-tier key
carrying both report rights and an escalation-check quota (O2).

## Local intel dashboard

**Settings → Honeypot Intel** is a read-only view of what the honeypot has caught locally (the
Wordfence "Live Traffic" analog — the operator's reason to install). It renders the `honeypot_wp_hits`
store and local state: summary tiles (total events, events in the last 24h, report-queue depth,
blacklist-mirror age), a paginated recent-events table (time, IP, method, path, action, reason,
status), top attacker IPs over the last 24h, and the `mass_plugin_scan` rollups. When WP-native
capture is on, the login/xmlrpc/REST rows appear here too. When the pingback shield is on, a
**"XML-RPC pingback SSRF targets (captured)"** table lists the captured source URIs per IP — every
target is attacker-supplied and is escaped as text on output (never emitted raw or in an attribute).

- `manage_options`-gated and **read-only**: it makes no state changes, so it carries no nonce (the
  guards are the capability gate + `absint`-clamped pagination). The recent-events list can be filtered
  by a fixed action whitelist (`log`/`deceive`/`block`).
- **No external I/O on render** — only local `$wpdb` and state reads. It never drains the reporter or
  triggers a GeoIP/blacklist refresh.
- **Escapes every value at output.** IP/path/User-Agent are attacker-controlled; they render only as
  escaped text-node content, never into an HTML attribute.
- Top-IP **User-Agent** and **current-window velocity** are a best-effort enrichment from the per-IP
  aggregate slots (recent-window; an older IP shows "—"). The aggregate `count` is a current-60s-window
  velocity, not a cumulative total, and is labelled as such. **Country** shows "—" until a local GeoIP
  reader is wired (none is today); it is never a network lookup.

### WP-Cron caveat

WP-Cron only fires on traffic, so on a low-traffic site the report drain, the O1 blacklist-mirror
pull, and the GeoIP refresh can stall between visits. For any install that enables reporting,
checking, or the mirror, disable WP-Cron and use a real system cron:

```
define('DISABLE_WP_CRON', true);   // in wp-config.php
# crontab:
*/5 * * * * wp honeypot report-drain --path=/var/www/html >/dev/null 2>&1
0   * * * * wp honeypot mirror-pull  --path=/var/www/html >/dev/null 2>&1
```

## WP-CLI

```
wp honeypot status                 # enabled?, posture, CONFIGURED position, VERIFIED mount, style, queue depth, mirror age
wp honeypot enable  [--posture=honeypot|WAF|both]
wp honeypot disable
wp honeypot test <path> [--method=GET]
wp honeypot report-drain [--limit=200]
wp honeypot mirror-pull
wp honeypot geoip-refresh
wp honeypot promote <rule-id>      # advance a rule SHADOW -> TUNING -> ENFORCED
wp honeypot shadow  [<rule-id>|--all]
```

`status` reports the **verified** BEFORE mount (`mu-plugin` / `plugins_loaded (degraded)` /
`not running`), not the configured intent — so a wiped shim that silently demoted the BEFORE position
is visible (Wordfence gap a).

## Security invariants

- **Fail-safe to allow, never a 5xx.** Any policy/evaluator/store fault degrades to "WordPress
  proceeds" — a 500 is itself a tell. The must-use loader shim is **degrade-safe** (SF-4): a plugin
  folder deleted without deactivation leaves the shim inert, never fatal.
- **Only ever upgrade a 404.** The FALLBACK position fires only on a genuine `is_404()`, and the
  `WpSiteProfile` real-route oracle keeps a fake from ever colliding with a real WP route.
- **Content-Type matches the request; status is app-chosen** (never model-chosen — no open redirect).
- **Reporting is key-gated and self-guarded**: inert without `MAINNET_KEY`, refuses the operator's own
  `self_ips`, reports public-routable IPs only. The reporter enqueue arg order matches F's
  `Funnypot\Mainnet\Reporter` exactly: `enqueue($ip, $comment, $categories)`.

## Testing

### Unit suite (green here)

Pure PHPUnit + Brain Monkey — no WordPress, no DB. Every test drives either a fake `PolicyEngine` or
the real one wired with D's real ports; WP I/O is mocked.

```
composer install
vendor/bin/phpunit --testsuite unit
```

The suite includes an end-to-end "wired ports" test (a scanner-probe / sacrificial `/.env` evidence →
a `deceive`/`block` Decision through the real `PolicyEngine` + D's real adapters), the SF-4
shim-takedown proof, and a real-`Funnypot\Honeypot` integration smoke test.

### Live: wp-env integration suite

Integration against a **real WordPress** — booted by `@wordpress/env` in Docker — is live. The suite
issues real HTTP requests to the booted site and asserts the plugin's actual request-time behavior:
a scanner probe for `/.env` is **deceived** (the 404 is upgraded into a fake-vulnerable `200` serving
a synthetic `.env`), a benign unknown path **passes through** as WordPress' own 404, and the homepage
is served untouched. Needs Docker. It **skips cleanly** when the base URL is unreachable, so it is
safe in a CI stage without Docker.

```
npm install && npx wp-env start && bash bin/wp-env-provision.sh
vendor/bin/phpunit --testsuite integration   # or: npm run test:integration
npx wp-env stop
```

Full run instructions, the observed-behavior table, and the environment notes (PHP 8.2 container,
sibling-package mappings, the pinned wp-env version) are in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Build

```
bash bin/build.sh    # composer install --no-dev (bundle policy/core/mainnet-client) + zip
```

## Deferred / prerequisites

- ~~**C — funnypot-core to PHP 7.3 + the two-phase split**~~ **DONE** (core `v0.0.1`): the bundled core
  is now PHP 7.3+, so the zip is shippable on 7.x hosts. The plugin's own glue was already 7.3-clean and
  CI-lint-gated.
- Golden-emit parity vs the standalone app (byte-identical fake surfaces) + reporter/reputation wire
  tests. The live wp-env suite (`docs/INTEGRATION.md`) already covers the core deceive / passthrough
  behavior over real HTTP; these deeper parity checks are the remaining follow-up.
- A production local **GeoIP DB reader** — the `WpGeoIp` port + refresh cron are built; wiring a
  concrete DB-IP Lite MMDB reader is a data-distribution follow-up (the port fail-opens to `null`
  until then).
- The reserved L6 local allow/deny overlay; runtime signed rule-update in the WP admin; multisite
  network UI; wordpress.org SVN distribution.

## Try it locally (Docker)

A `docker-compose.yml` stands up real WordPress with this plugin live-mounted and activated, so you can
click through the Funnypot settings/intel screens and confirm it installs cleanly. It doubles as an
install smoke test.

```bash
docker compose up -d          # first boot provisions WP, creates the admin, activates the plugin
open http://localhost:8919/wp-admin/     # log in: admin / funnypot
docker compose down           # stop  (add -v to also wipe the db + wp volumes)
```

- **Non-standard host port `8919`** so it won't collide with other local stacks; the DB has no host port.
- **Dev admin `admin` / `funnypot`** — a LOCAL-ONLY convenience, **not a secret**, never for a real site.
- Settings: **Settings → Honeypot** (`/wp-admin/options-general.php?page=honeypot-wp`); the Intel dashboard
  is its submenu.
- The plugin is bind-mounted from the working tree (with its vendored `funnypot-core`/`-policy`), so edits
  are live — reload wp-admin to see them. If a fresh clone has no `vendor/`, run `composer install` first.
- Requires Docker; the run itself is developer/operator-invoked (not part of CI's PHP-only gates).
