# Honeypot for WordPress (piece D)

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

The plugin code is **PHP 7.3-clean** (old WP hosts run old PHP). The bundled `funnypot-core` still
requires PHP 8.0 today; re-flooring it to 7.3 (plus the two-phase `classify()`/`synthesize()` split) is
the **hard prerequisite C** — see "Deferred / prerequisites" below.

## Install

### As a downloadable zip (recommended for WP hosts)

`bin/build.sh` (see *Build*) produces `build/honeypot-wordpress.zip` with
`vendor/metrictower/{funnypot-policy,funnypot-core,mainnet-client}/` and core's rules artifacts
bundled. Upload it under **Plugins → Add New → Upload Plugin**, then activate.

### As a Composer package

```
composer require metrictower/honeypot-wordpress
```

On activation the plugin creates its tables, generates a per-install `sensor_id`, and copies a
must-use loader shim into `wp-content/mu-plugins/` so the BEFORE position runs at the earliest hook. If
that directory is not writable it falls back to `plugins_loaded` and raises an admin notice.

## Configure

**Settings → Honeypot** produces the policy config array. Key choices:

- **Posture:** `honeypot` (FALLBACK — upgrade a genuine 404, FP-free), `WAF` (BEFORE — block/deceive
  ahead of routing), or `both`.
- **Response style / severity ceiling / attack emulation / nuclei reflection** — how a fake looks.
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

### Deferred: wp-env integration

Full integration against a **real WordPress** (theme render, byte-identical plugin-off surfaces,
golden-emit parity vs the standalone app, reporter/reputation wire tests) needs a running WP and is
**deferred** — it is not available in this build environment. It runs via `@wordpress/env`:

```
npm ci && npx wp-env start && composer test:integration
```

`tests/Integration/` currently carries a documented skipped placeholder; the assertion list is
enumerated in `docs/2026-08-19-honeypot-wordpress-plan.md` (Phase 9).

## Build

```
bash bin/build.sh    # composer install --no-dev (bundle policy/core/mainnet-client) + zip
```

## Deferred / prerequisites

- **C — funnypot-core to PHP 7.3 + the two-phase split** (hard prerequisite). The bundled core is
  PHP 8 today; the plugin's own glue is already 7.3-clean and CI-lint-gated so nothing regresses when
  C lands. Do **not** ship the zip on a 7.x host until C is merged.
- Real-WordPress (wp-env) integration + golden-emit parity (Phase 9).
- A production local **GeoIP DB reader** — the `WpGeoIp` port + refresh cron are built; wiring a
  concrete DB-IP Lite MMDB reader is a data-distribution follow-up (the port fail-opens to `null`
  until then).
- The reserved L6 local allow/deny overlay; runtime signed rule-update in the WP admin; multisite
  network UI; wordpress.org SVN distribution.
