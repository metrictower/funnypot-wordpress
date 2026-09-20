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
WordPress' `template_redirect` hook (priority 0, before WP's own `redirect_canonical` at priority 10).
It acts on a genuine `is_404()` **and** — for core-owned scanner paths — on a WP-preempted request WP
would otherwise 301/soft-200 (see *Scanner panel paths* below). So two preconditions must hold before
its behavior is observable over HTTP — `bin/wp-env-provision.sh` sets both, idempotently:

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

### Scanner panel paths (FP-0504)

On a real WordPress site, WP would 301-canonical-redirect or soft-200 (homepage) an unknown panel path
like `/phpmyadmin`, so it never reaches a clean `is_404()`. The plugin now serves the **core-owned**
decoy for these at `template_redirect@0` — before the 301 is emitted — so a scanner gets the panel on
its first request. The decoy content lives in funnypot-core (the same index the dedicated app box
uses); the plugin asks core "do you own a decoy for this exact path?" and never ships its own path list.

| Request | Observed response | Meaning |
| --- | --- | --- |
| `GET /phpmyadmin` | `200`, `X-Detected`, `<title>phpMyAdmin` panel body | **Deception** — core-owned panel served before WP's 301 |
| `GET /solr/admin`, `/actuator/health`, `/telescope/requests` | `200` + the matching core decoy + `X-Detected` | same — a WP-preempted, core-owned path |
| `GET /feed/`, `/robots.txt`, `/favicon.ico`, `/?s=…` | WP's real response, **no** `X-Detected`, no panel | **Untouched** — legitimate WP endpoints, spared by the fail-safe-to-genuine oracle even though core owns decoys for some of them |
| `GET /sitemap_index.xml` (SEO plugin active) | the real SEO sitemap, no `X-Detected` | **Untouched** — carries a `sitemap` query var (non-empty main query) → genuine |

**Safety model.** A path is eligible for the owned-decoy serve only when it is *not genuine* — a hard
404, or a front-page/blog-index fallthrough off root **with an empty main query** — and then only when
core owns a decoy. Ownership is **not** a safety signal: core owns decoys for `/feed`, `/robots.txt`,
`/sitemap.xml`, `/favicon.ico` too, so the fail-safe-to-genuine oracle (`Interceptor::isGenuineRoute`)
runs first and can only be *narrowed* by ownership, never promoted. Any doubt (an unreadable WP global,
a `function_exists` miss) resolves to genuine. The serve is gated by the response mode: only
`realistic`/`taunt` serve the decoy; `stealth`/`blocked` stay WP-normal and log. The bare harness has
no SEO plugin, so the SEO-sitemap sparing is covered by a unit test, not the harness.

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

### Login honeypot field (FP-0505)

An invisible decoy `<input>` injected into WordPress's **own** login form (the `login_form` action —
the plugin does not override `/wp-login.php`), plus a passive detector on the login POST. Default off;
independent of `wp_native_capture`. Provision with e.g. `wp option update honeypot_wp_settings
--format=json '{"enabled":true,"login_honeypot_field":true}'` — then assert:

| Request | Expected | Meaning |
| --- | --- | --- |
| `GET /wp-login.php` | the real WP login form with an extra `display:none` field (`tabindex=-1`, `aria-hidden`, `autocomplete=off`; an ordinary contact-field name) | the decoy is injected additively; a real user/browser never fills it |
| `POST /wp-login.php` with the decoy field **filled** (bad creds) | login fails as normal; one local hit row, reason `login_honeypot_field` | a scripted bot that fills every input is flagged |
| `POST /wp-login.php` with the decoy field **empty/absent** (bad creds) | login fails as normal; **no** honeypot hit | zero false positives for real users |
| `POST /wp-login.php` valid creds (decoy empty) | authenticated normally | the login is never blocked or altered |

The field name is derived per-site from `crc32(host|salt)` (server-side `home_url()` host, not the
client `Host` header), so a bot's GET-render name and POST-submit name always agree, the name differs
per install (no fleet constant), and a spoofed `Host` header cannot shift it. **Passive-signal
ceiling:** detection hooks `wp_login_failed` (password-free), so a bot that fills the decoy **and**
submits valid credentials succeeds without firing that hook and is not caught — a rare, non-target case
left uncaught on purpose (catching it needs `authenticate`, which would pull the password into scope).
Local intel only — the value is inspected for emptiness only, never stored, reflected, or sent to
mainnet. Full real-`wp-login` end-to-end verification belongs to the FP-0497 harness (operator/CI-run).

### Bot-gated fake lockout (FP-0506)

After a failed login on the real `/wp-login.php`, serve the core fake-lockout page (vendored
`WordpressSkin::renderLockout`, no core change) to a **suspected bot only** so it believes it tripped a
rate-limiter. Default off; requires `realistic` or `taunt` response mode. Gated on a **bot signal**,
**never** a plain failed-login count: the FP-0505 honeypot field tripped, **or** a conservative per-IP
failed-login **velocity** (dedicated 60s counter, default `login_lockout_velocity` = 15, clamped
`[5,240]`, on its own key so it works with `wp_native_capture` off). Provision with e.g. `wp option
update honeypot_wp_settings --format=json '{"enabled":true,"response_mode":"realistic",
"login_fake_lockout":true,"login_honeypot_field":true}'` — then assert:

| Request | Expected | Meaning |
| --- | --- | --- |
| `POST /wp-login.php` with the decoy field **filled** (bad creds) | HTTP 200 `text/html` fake-lockout login page (*"Too many failed login attempts…N minutes"*) | a definitive bot signal shows the cosmetic lockout |
| `POST /wp-login.php` bad creds at/over the velocity threshold (default 15/60s) | HTTP 200 fake-lockout page | brute-force shape shows the cosmetic lockout |
| `POST /wp-login.php` a few ordinary bad-creds attempts (no decoy, below velocity) | WordPress's **normal** login-failed page | a real user who mistypes is never shown the lockout |
| `POST /wp-login.php` **valid** creds afterwards (even from an IP that tripped velocity) | authenticated normally | the account is never locked — `wp_signon` re-runs fresh |

**Never locks a real user — structural, not tuning:** the trigger is `wp_login_failed` (fires only
*after* WordPress rejected the credentials) and the feature registers **no**
`authenticate`/`wp_signon`/`login_redirect` hook, so the auth decision is out of scope; it writes **no
persistent lock** (only the ephemeral velocity counter, read solely by this cosmetic gate); and the
lockout is a **per-request cosmetic lie** — the next POST is evaluated fresh, so a correct password
always authenticates (a false-positive velocity trip behind a shared NAT is harmless — it decorates one
already-failed request and never gates the next). The countdown minutes + persona are seeded from
`crc32(host|salt)` (same as the honeypot field), so the page is deterministic per deploy and stable on
re-scan. Fingerprint-safe (FP-0491-vetted page — small 1–2 digit minutes, no `llar`/six-digit
rule-id), no PII (submitted username/password/decoy value is never read into the page), degrade-safe
(any render/emit fault, or output already sent, falls through to normal WordPress — never a 500).
**Passive-signal ceiling:** the signals are passive — a bot that neither fills the field nor sustains
the velocity is not shown the lockout, on purpose (the alternative would risk a real user). Full
real-`wp-login` end-to-end verification (real `exit`, real 200 body) belongs to the FP-0497 harness
(operator/CI-run).

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
- **Degrade-safe capture / schema-ensure.** Every request/cron-facing `$wpdb` write to a plugin table
  (`honeypot_wp_hits`, the report queue/sidecar) runs with wpdb's error output suppressed, so a
  missing or broken table degrades to a silent no-op — a raw "WordPress database error" is never
  echoed onto a response as a fingerprint tell. Complementarily, the Docker harness
  (`docker/wp-init.sh`) verifies the hits table exists after activating the plugin and re-activates
  once if a first-run activation did not create it, so a fresh `docker compose up` has the schema
  present without a manual re-activate.
