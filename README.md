# Honeypot for WordPress (piece D)

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
