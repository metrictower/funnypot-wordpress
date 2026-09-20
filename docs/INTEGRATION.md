# Live wp-env integration suite

The `integration` PHPUnit suite drives the plugin against a **real WordPress** booted by
[`@wordpress/env`](https://www.npmjs.com/package/@wordpress/env) in Docker, issuing real HTTP
requests and asserting the response the plugin actually produces at request time. This is the
end-to-end complement to the unit suite (Brain Monkey, no WordPress).

## Prerequisites

- **Docker** running (wp-env pulls the WordPress + MySQL images and boots two containers).
- **Node** + npm (for `@wordpress/env`).

## Run it

```bash
npm install                                   # installs @wordpress/env (pinned, see note below)
npx wp-env start                              # boots WordPress + MySQL (first run pulls images)
bash bin/wp-env-provision.sh                  # idempotent: pretty permalinks + enable the plugin
vendor/bin/phpunit --testsuite integration    # the live assertions
npx wp-env stop                               # when done
```

Or in one shot (start + provision + test):

```bash
npm run test:integration
```

The site is served at `http://localhost:8888` (override with `HONEYPOT_WP_BASE_URL`). The suite
**skips cleanly** if that base URL is unreachable, so it is safe to leave enabled in a CI stage
without Docker.

## Why the two provisioning steps

The plugin ships **inert by default** (`enabled=false`) and its honeypot posture intercepts on
WordPress' `template_redirect` hook, acting only on a genuine `is_404()`. So two preconditions must
hold before its behavior is observable over HTTP — `bin/wp-env-provision.sh` sets both, idempotently:

1. **Pretty permalinks** (`/%postname%/`). With WordPress' default *plain* permalinks, an unknown
   URL never matches a rewrite rule, so Apache returns its own 404 and WordPress (hence the plugin)
   never runs. Pretty permalinks route unknown URLs through `index.php` into WordPress, where the
   fallback position can see the 404.
2. **Plugin enabled** in honeypot posture:
   `wp option update honeypot_wp_settings --format=json '{"enabled":true,"posture":"honeypot"}'`.

The integration test also runs this provisioning best-effort in `setUp()`, so a bare
`vendor/bin/phpunit --testsuite integration` right after `wp-env start` still works.

## What it asserts (the plugin's real behavior)

| Request | Observed response | Meaning |
| --- | --- | --- |
| `GET /.env` | `200`, header `X-Request-Id`, body is a synthetic `.env` (`DB_PASSWORD=…`), `application/octet-stream` | **Deception** — the honeypot upgrades the 404 into a fake-vulnerable hit so the scanner logs a false positive |
| `GET /<unknown benign path>` | `404`, no `X-Request-Id`, empty body | **Passthrough** — WordPress' own 404; no false positive on benign traffic |
| `GET /` | `200`, no `X-Request-Id` | **Untouched** — real routes are never intercepted |

### Login relocation (FP-0490)

Needs live WordPress, so it is an operator/CI scenario (not run by the unit suite). Provision with a
valid slug — e.g. `wp option update honeypot_wp_settings --format=json
'{"enabled":true,"posture":"honeypot","response_mode":"realistic","login_relocation_enabled":true,"login_slug":"secret-login"}'`
— then assert:

| Request | Expected | Meaning |
| --- | --- | --- |
| `GET /secret-login` (logged out) | real WordPress login form | the slug reaches the genuine `wp-login.php` |
| `POST /secret-login` valid creds | authenticated, `redirect_to` honored | real auth runs natively at the slug |
| `GET /secret-login` (logged in) | redirect to the dashboard | authed operator bounced off the login |
| `GET /wp-login.php` (logged out) | the wp-login mock-auth decoy | vacated default inverted to the decoy |
| `GET /wp-admin/` (logged out) | bounced to the decoy at `/wp-login.php`, **not** the slug | slug-leak guard holds |
| `POST /wp-login.php?action=postpass` | works (real WordPress) | password-protected-post carve-out |
| deactivate the plugin / clear the slug | `/wp-login.php` is the real login again | no on-disk change, no rewrite flush |

### Blocked response mode (FP-0494)

`response_mode` selects the served posture: `stealth` (capture-only plain 404), `realistic` (default —
byte-exact fakes + decoys), `taunt` (troll persona over the decoy), or `blocked`. In `blocked` mode
every non-`allow` band is clamped **up** to `block`, so instead of a decoy the plugin returns a generic
`text/html` **403 "Access Denied"** page (no WAF/product branding, an inert reference token). Provision
with e.g. `wp option update honeypot_wp_settings --format=json
'{"enabled":true,"posture":"honeypot","response_mode":"blocked"}'` — then assert:

| Request | Expected | Meaning |
| --- | --- | --- |
| `GET /.env` | `403`, `text/html`, generic "Access Denied" block page (no decoy body) | non-`allow` band clamped to block |
| `GET /<unknown benign path>` | `403` block page | the `suspicious`/`attack` bands 403 too (a hardened posture; opt-in FP risk) |
| `GET /` | `200`, untouched | `allow` (clean traffic) is never blocked |

It is opt-in because a block page advertises a defense (a fingerprint tradeoff vs the stay-hidden
default). `allow` and the relocated-login `safe_paths` are left intact — no operator lockout.

### Deception corpus auto-update (FP-0502)

Not exercised by this live suite — it is **default-off** and its trust/swap flow is covered by the
unit suite against the real vendored core (`tests/Unit/RulesAutoUpdateTest.php`,
`tests/Unit/WpRemoteRulesFetcherTest.php`, `tests/Unit/RulesCronWiringTest.php`) with a test-keyed
verifier + a network-free fetcher, so no network or signing keys are needed to test it. A live
end-to-end pull additionally requires the `metrictower/funnypot-rules` distribution repo + published
ed25519 signing keys, which do not exist yet; until then a pull fail-safes to the bundled corpus. The
plugin ships **DATA only** via this path — engine **code** still updates via WP plugin auto-update /
`composer`. See the README's "Deception corpus auto-update" section for the operator-facing details.

## Environment notes

- **PHP 8.2** in the container (`.wp-env.json` `phpVersion`) — a version WordPress 6.5 fully supports.
  Both the plugin and the bundled `metrictower/funnypot-core` are PHP **7.3+** (core's two-phase +
  7.3 re-floor shipped in `v0.0.1`). Exercising the harness at the 7.3/7.4 floor in real WordPress is a
  follow-up (see the meta QUEUE).
- **Sibling package mappings.** The plugin's Composer autoloader reaches `funnypot-core`,
  `funnypot-policy`, and `funnypot-mainnet-client` through relative symlinks under
  `vendor/metrictower/` that resolve to `wp-content/plugins/<sibling>` inside the container.
  `.wp-env.json` `mappings` mount the sibling source trees at exactly those paths so the classes —
  and core's ~6 MB compiled rules artifact — load. The container is given `WP_MEMORY_LIMIT=512M` to
  cover compiling that artifact on a request.
- **`@wordpress/env` is pinned to `10.38.0`.** `10.39.0` added an `@wp-playground/cli` dependency
  that pulls a native `@php-wasm/node` (`fs-ext`) module which fails to compile on Node >= 26. Only
  the Docker path is used here, which needs none of it.
