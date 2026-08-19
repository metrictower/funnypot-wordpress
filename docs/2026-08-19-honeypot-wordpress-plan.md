# honeypot-wordpress · D — implementation plan

**Status:** draft for review · **Date:** 2026-08-19 · **Piece:** D of the funnypot-mainnet program
**Implements:** [`2026-08-19-honeypot-wordpress-design.md`](./2026-08-19-honeypot-wordpress-design.md) (the design is the source of truth; this plan executes it and does not redesign it).
**Primary dependency:** **`metrictower/funnypot-policy`** (decision M — the position-blind decision
engine; D is a thin adapter over it). **Hard prerequisite:** **C** (funnypot-core re-floored to PHP 7.3
**and** split into the M2 two-phase `classify()`+`synthesize()` engine behind the policy's
`EvaluatorInterface`). **Reporter:** provided by **F** (`Funnypot\Mainnet\Reporter` in
`metrictower/mainnet-client`, transitive) — no separate `Funnypot\Report\*` prerequisite.

This is a disciplined, test-driven build plan. Each phase is a small, independently verifiable
increment: the change, the test written **first**, the exact command to run it green, and
done-criteria. Phases are ordered so each builds on the last and the whole suite stays green
throughout. A builder (human or subagent) should execute them in order without re-deriving the design.

---

## Orientation

### What exists now

`honeypot-wordpress/` contains only `docs/` (the design spec + this plan). **No code, no
`composer.json`, no plugin file yet.** This build creates the plugin from scratch.

What the plugin consumes exists (or is being built in parallel) in the sibling repos:

- **`funnypot-policy` public API** (the primary dependency; `funnypot-policy/docs/2026-08-19-funnypot-policy-design.md`):
  - `Funnypot\Policy\PolicyEngine::evaluate(RequestEvidence $e): Decision` — the one call D makes per
    position. Never throws on the request path by contract (fail-safe to `Decision::allow`), but D still
    guards (invariant §6.2).
  - Ports D implements or wires: `Funnypot\Policy\Port\EvaluatorInterface` (the core-backed engine —
    `classify()`+`synthesize()`), `ReputationInterface` (F, cache-first), `StateStoreInterface` (D's
    `WpStateStore`), `Clock` (D's `WpClock`), `Logger` (D's `WpLogger`), and the **optional**
    `GeoIpInterface` (D's `WpGeoIp`, wired only when country policy is enabled — decision R, Phase 4c).
  - Value objects: `Funnypot\Policy\Decision` (`action()` ∈ `allow|log|block|deceive`, `status()`,
    `fakeHandle()`, `pinTtl()`, `report()`, `reason()`), `RequestEvidence`, `SiteProfile` (D's
    `WpSiteProfile`: `stack()`/`routeExists()`/`isSacrificialPath()`), `ReportIntent`, `Verdict`,
    `FakeResponse`.
  - `Funnypot\Policy\PolicyConfig::fromArray(array): self` — the §8 config array builder (7.3, no named
    args, M15). D produces the array from settings; the engine reads only the array.
- **funnypot-core (transitive, behind the policy's `EvaluatorInterface` — M2 split, a C task):**
  - The two-phase engine: `classify(RequestEvidence, SiteProfile) → Verdict` + `synthesize(Verdict,
    SiteProfile, seed) → FakeResponse`. D does **not** call `Honeypot::respond()`/`detect()` and does
    **not** build a respond-mode `Config` with `gate`/`probeSignature`/`killSwitch` closures — the
    WHEN/WHETHER now lives in the policy. The concrete adapter that satisfies `EvaluatorInterface` from
    core ships with policy/core; D consumes it and only sets the STYLE/engine `Config` (Phase 4).
  - `Funnypot\Config` — the STYLE/rendering knobs that feed `synthesize()` (`responseStyle`,
    `severityCeiling`, `attackEmulation`, `nucleiReflection`, `exclude`, `seedSalt`, `latencyMs`,
    `latencyJitterMs`, `maxBodyBytes`). C re-floors it to 7.3 (promotion removed); on 7.3 there are no
    named args, so D uses core's 7.3-callable `Config` factory (preferred, a C task) or constructs
    positionally (Phase 4, M15). **Note:** positions 3 (`pathScope`) and 5 (`personaBreadth`) are not in
    D's mapping but must still be passed at their positions in the positional-fallback recipe — omitting
    a middle positional arg silently misassigns later ones.
  - `Funnypot\Http\ResponseEmitter::emit(...): void` — the one output side effect D uses, to emit the
    `Decision.fakeHandle` (`http_response_code` + `header` + `echo`, header-splitting defence).
- **The reporter contract (piece F, relocated from B)**: `metrictower/mainnet-client` ships
  `Funnypot\Mainnet\Reporter` + `Funnypot\Mainnet\Report\ReportQueue` + `ReportTransport`, PHP-7.3-clean,
  storage-agnostic — transitive via core/policy. D binds a `WpdbReportQueue implements
  \Funnypot\Mainnet\Report\ReportQueue` and a `WpReporterBridge` (named to avoid shadowing
  `Funnypot\Mainnet\Reporter` — M8) that composes it and is driven by the policy's `Decision.report`
  intent. The bridge's `enqueue(string $ip, string $comment, string $categories = '21')` matches the
  reporter's arg order exactly. The enqueue/drain **transport** guards (self-IP, public-IP-only, per-IP
  dedup, daily cap; POST to `MAINNET_BASE_URL` + `/v1/report`, body `ip,categories,comment,timestamp` +
  `sensor_id` + `Key:` header, key-gated) are the port of `funnypot/src/App/ThreatIntel/AbuseIpdb.php`,
  kept as a backstop under the policy's own 4-layer suppression.
- **The reputation contract (piece F, behind the policy's `ReputationInterface`)**: F's
  `Funnypot\Mainnet\ReputationGate` / `Client::check` + a PSR-16-style `Funnypot\Mainnet\Cache` seam,
  transitive via core/policy. D binds only a `WpCache implements \Funnypot\Mainnet\Cache` (WP transients
  / object cache); reputation is a **policy config knob** (`reputation.enabled`/`block_verdicts`, design
  §4.8), consumed cache-first — D no longer calls `decide()` in the interceptor. Inert unless
  `check_enabled` **and** `MAINNET_KEY` are both set, fail-open by default.

### How this repo will run its tests

The design names "WP test scaffolding / Brain Monkey for hook mocking, PHP 7.3–8.x matrix" for unit
tests and "a real WordPress in Docker" for integration. This plan sets up:

- **Unit suite** — pure PHPUnit `^9.5` + `brain/monkey ^2.6` (mocks WP functions like
  `add_action`, `get_option`, `wp_schedule_event`) + `mockery`. No WordPress install, no DB. Runs on
  the PHP 7.3→8.x matrix. Fast; this is where the vast majority of logic lives.
  - **Command:** `composer install && vendor/bin/phpunit --testsuite unit`
- **Integration suite** — real WordPress via `@wordpress/env` (`wp-env`, Docker). Plugin active
  against a live WP.
  - **Command:** `npm ci && npx wp-env start && composer test:integration`
- **Dependencies are available to the build via Composer path repositories** pointing at
  `../funnypot-policy`, `../funnypot-core`, and `../mainnet-client`
  (`repositories: [{type: path, ...}]`, `require metrictower/funnypot-policy:@dev` — which pulls core +
  mainnet-client transitively). Development and unit tests run against the **real** packages on the 8.x
  host today; the shipped zip bundles policy + core + mainnet-client (Phase 9/10). **The 7.3 runtime is
  blocked on C** (see Risks) — but D's own glue is written 7.3-clean from Phase 1 and lint-gated against
  7.3 in CI (Phase 10) so nothing regresses when C lands and the matrix goes green on 7.3. Every unit
  phase drives a **fake `PolicyEngine`** so no policy logic is exercised or re-tested in D's suite.

### Conventions (from the design §4)

Namespace `Honeypot\WP\` (PSR-4 → `src/`). Text domain `honeypot-wp`. Settings option
`honeypot_wp_settings`. Tables `{$wpdb->prefix}honeypot_wp_hits`, `{$wpdb->prefix}honeypot_wp_report_queue`
(+ dedup/daily sidecar). **All D glue code is PHP 7.3-compatible**: no enums, no `match`, no
constructor property promotion, no named args in D's own calls, no arrow functions in shipped code, no
typed properties, no `??=`. (This mirrors the B design's 7.3 rule and is what lets the plugin run on
old WP hosts once C lands.)

---

## Phase 0 — Repo scaffold + green empty suite

**Change.** Create the plugin skeleton so `vendor/bin/phpunit` runs:
- `composer.json` — name `metrictower/honeypot-wordpress`, `"require": {"php": ">=7.3",
  "metrictower/funnypot-policy": "@dev"}` (which pulls `funnypot-core` + `mainnet-client`
  transitively), `require-dev` phpunit/brain-monkey/mockery, PSR-4 `Honeypot\\WP\\ → src/` and
  `Honeypot\\WP\\Tests\\ → tests/`, `repositories` path entries to `../funnypot-policy`,
  `../funnypot-core`, `../mainnet-client`, and scripts `test` / `test:integration`.
- `phpunit.xml.dist` — two testsuites: `unit` (`tests/Unit`) and `integration` (`tests/Integration`),
  `bootstrap=tests/bootstrap.php`.
- `tests/bootstrap.php` — `require vendor/autoload.php`; wire Brain Monkey setUp/tearDown via a base
  `TestCase` in `tests/Unit/TestCase.php`.
- `honeypot-wordpress.php` — plugin main file with the WP plugin header only (no logic yet); guarded
  by `if (!defined('ABSPATH')) { return; }`.
- `.gitignore` (vendor/, node_modules/, build/), `README.md` stub.

**Test first.** `tests/Unit/ScaffoldTest.php`: asserts the Composer autoloader resolves
`Honeypot\WP\` (e.g. a trivial `Honeypot\WP\Version::STRING` constant class) and that Brain Monkey's
`Monkey\setUp()`/`tearDown()` cycle runs without error.

**Verify.** `composer install && vendor/bin/phpunit --testsuite unit` → green (1 test).

**Done when.** The suite runs and is green from an empty checkout; `php -l honeypot-wordpress.php`
passes; the plugin header is valid (parseable `Plugin Name`, `Requires PHP: 7.3`, `Text Domain:
honeypot-wp`).

---

## Phase 1 — `Settings` value object (pure, no WP)

**Change.** `src/Settings.php`: a plain immutable object built from the raw settings array with typed
getters and defaults exactly per design §5. It carries three families of knobs — the **policy** knobs
(posture/position/actions/learn/suppression/allowlist/self_ips/reputation), the **STYLE/engine** knobs
(response_style, severity_ceiling, attack_emulation, nuclei_reflection, catalog_disabled, seed_salt,
latency), and the **request/report** knobs (enabled, trusted_proxies, report_enabled, mainnet_base_url,
mainnet_key, daily_cap). Defaults: `enabled=false`, `posture='honeypot'`,
`position=['fallback'=>true,'before'=>false]`, `response_style`, `severity_ceiling='high'`,
`attack_emulation=false`, `nuclei_reflection=true`, `catalog_disabled=[]`, `trusted_proxies=[]`,
`seed_salt`, `latency_ms=0`, `latency_jitter_ms=0`, `pin_ttl_seconds=3600`, the `learn`/`suppression`
blocks at the policy §8 defaults, `allowlist`/`self_ips=[]`, `report_enabled=false`, `mainnet_base_url`
(defaults to the **mainnet placeholder host**, scheme+host only — **never** AbuseIPDB), `mainnet_key=''`,
`daily_cap=1000`, plus the reputation keys (design §4.8 / F/H1): `check_enabled=false`,
`block_verdicts=['malicious','critical']` (verdict-first, **no** score threshold), `min_block_score=null`,
`cache_ttl_hours=24`, `fail_mode='open'`. Include:
- `Settings::fromArray(array): self` — normalize/whitelist unknown keys, clamp types.
- **`toPolicyConfig(string $position): array`** — render the design §8 / policy §8 config array that
  `PolicyConfig::fromArray()` consumes: `posture`, `position` (with the given position forced on),
  per-band `actions`, `reputation` (`enabled`/`block_verdicts`/`min_block_score`/`fail_mode`/
  `cache_ttl_hours`), `learn`, `pin`, `suppression`, `allowlist`, `self_ips`. This is D's one
  settings→policy mapping method (the thin-adapter admin-UI-produces-the-array responsibility).
- `mainnetBaseUrl(): string` / `mainnetKey(): string` — **env override wins** via an injected constant
  resolver (`HONEYPOT_WP_MAINNET_BASE_URL` / `HONEYPOT_WP_MAINNET_KEY`), else the stored value, else the
  placeholder host / `''`. Base URL is **scheme+host only, no path** (the bridge appends `/v1/report`).
- `reportingActive(): bool` — `report_enabled && mainnetKey() !== ''` (D2: **inert without a key**).
- `checkActive(): bool` — `check_enabled && mainnetKey() !== ''` (F: reputation **inert without a key**,
  independent of `report_enabled`). Getters `checkEnabled()`, `blockVerdicts()`, `minBlockScore()`,
  `cacheTtlHours()`, `failMode()` back the reputation block of the policy config. There is **no**
  `blockThreshold()` — the score knob was replaced by verdict-first `block_verdicts` + `min_block_score`.
- **New N/O + future-proofing knobs.** Add getters + defaults for: `localStateBackend()`
  (`object-cache|file`, **default `object-cache`** — RS-10; the default must work where the plugin dir is
  not writable); `mirrorEnabled()` (**default false** — O1; inert unless `checkActive()`),
  `mirrorPullIntervalSecs()` (default `3600`); the SF-6 drain bounds `drainBudgetSecs()` (default `10`,
  decision N), `drainMaxAttempts()` / `drainMaxAgeSecs()` (re-queue caps), `queueCap()` (hard queue size,
  oldest-dropped-first). The `mainnet_key` getter's docblock states it is a **`sensor`-tier key** (report
  **+** escalation-check rights, O2) — one key, both jobs. `toPolicyConfig` carries the SF-6 drain bounds
  and the O1 mirror-first read posture into the policy config where they belong; RS-10/mirror/drain-cron
  knobs that are D-adapter-local (not policy decisions) are read directly by the bridge/mirror/store.
- **New R (country policy) knobs.** Add getters + defaults for the `country` block: `countryPosture()`
  (`off|deny_list|allow_list`, **default `off`**), `countryList()` (ISO-3166 alpha-2 `string[]`, default
  `[]`), `countryAction()` (`block|deceive|score-modifier`, **default `score-modifier`** — R3).
  `toPolicyConfig` renders these into the §8 policy array's **`country`** block (the country gate is the
  policy's, M5); when the posture is `off` the block renders **inert**. These are policy knobs; the one
  D-adapter-local knob is `geoipRefreshIntervalSecs()` (**default monthly** — the DB-IP Lite cadence), read
  by the Phase-8 GeoIP-refresh cron, not carried into the policy config.

**Test first.** `tests/Unit/SettingsTest.php`: default install is inert (`enabled=false`,
`reportingActive()===false`, `checkActive()===false`); unknown keys dropped; `mainnetBaseUrl()` defaults
to the placeholder host (**not** AbuseIPDB), env-constant precedence proven, never carries a `/v1/...`
path; `reportingActive()`/`checkActive()` false without a key even when their enable flag is set;
`block_verdicts` defaults to `['malicious','critical']` and coerces junk out; `min_block_score` int|null;
`cache_ttl_hours` numeric default `24`; `fail_mode` whitelists to `open|closed`; `local_state_backend`
defaults to `object-cache` and whitelists to `object-cache|file` (RS-10); `mirror_enabled` default false
(O1); the SF-6 drain knobs (`drain_budget_secs=10`, `queue_cap`, `drain_max_attempts`/`drain_max_age_secs`)
default and clamp to sane ranges; **the R country knobs** default (`country_posture='off'`,
`country_action='score-modifier'`) and whitelist to their enums (`off|deny_list|allow_list`,
`block|deceive|score-modifier`), with junk countries coerced out. **`toPolicyConfig`**:
asserts the default renders `posture='honeypot'` + `position.fallback=true` + `reputation.enabled=false`
+ the §8 suppression/learn defaults + an **inert `country` block** (`posture='off'`), and that the given
position is forced on in the returned array.

**Verify.** `vendor/bin/phpunit --filter SettingsTest`.

**Done when.** Settings round-trips defaults, `toPolicyConfig` renders the inert-by-default policy
array, the env override precedence is proven, reporting **and** reputation are both inert without a key,
and no WP function is called (pure object).

---

## Phase 1b — `SensorId`: per-install UUID (D3)

**Change.** `src/SensorId.php` per design §4.11: a stable per-install UUID, generated once on first run
and persisted to the `honeypot_wp_sensor_id` WP option, sent as `sensor_id` on every report. Keep the
pure part unit-testable by injecting the option get/set and the UUID generator:
- `SensorId::resolve(callable $getOption, callable $setOption, callable $generate): string` — return
  the stored id if present and well-formed; otherwise generate one (`wp_generate_uuid4()` when
  available, else a random-bytes v4 fallback — the injected `$generate`), persist it, and return it.
  **Never** derive from a hardware id (blocked reads, privacy, portability).
The real WP wiring (`get_option`/`update_option`, generated on activation and lazily on first report)
lands in Phase 8; this phase is the pure resolver.

**Test first.** `tests/Unit/SensorIdTest.php`: a missing option triggers one generate + one persist and
returns the new id; a present well-formed option returns it **without** regenerating or re-persisting; a
malformed stored value is replaced; the returned value is a v4 UUID shape.

**Verify.** `vendor/bin/phpunit --filter SensorIdTest`.

**Done when.** The id is generated exactly once, persisted, stable across calls, and no hardware id is
read.

---

## Phase 2 — `WpSiteProfile` — declared stack + real-route oracle

**Change.** `src/WpSiteProfile.php` per design §4.2 — D's `\Funnypot\Policy\SiteProfile` (the old
`SurfaceAllowlist` knowledge as the policy's FP-safety input data, not a bespoke skip-list):
- `stack(): string` — always `'wordpress'`.
- `routeExists(string $path): bool` — true for the genuine-WP static reserved set (`/`, `/wp-login.php`,
  `/wp-cron.php`, `/wp-comments-post.php`, `/xmlrpc.php`, and any path under `/wp-admin/`, `/wp-json/`,
  `/wp-content/uploads/`). `xmlrpc.php`/`wp-login.php` count as real-route (reserved) **unless** the
  operator both opted the decoy in via the catalog **and** disabled the real feature — two settings
  flags the method reads; default = real-route. The live published-post resolution needs WP's query, so
  the FALLBACK-position `WpSiteProfile` also consults `is_404()` (injected as a bool/callable so the
  method stays pure-unit-testable); at the BEFORE position the query has not run, so only the
  static-prefix set is covered (documented seam — the policy's matched-only `classify()` handles the
  rest; open decision, Risk 4).
- `isSacrificialPath(string $path): bool` — true for the provably-nonexistent WP set (`/.env`,
  `/.git/config`, `/wp-config.php.bak`, `/wp-content/debug.log`, the CVE-probe paths), the day-1
  auto-enforce carve-out. Keep the class WP-function-free apart from the injected `is_404` seam.

**Test first.** `tests/Unit/WpSiteProfileTest.php`: `routeExists` true for genuine endpoints, false for
scanner paths; `isSacrificialPath` true for `/.env`/`/.git/config`/`/wp-config.php.bak`/`debug.log` and
false for genuine surfaces; `xmlrpc`/`wp-login` are real-route by default and become sacrificial only
when both opt-in flags are set; the injected `is_404` flips `routeExists` for a resolved-post path;
case/trailing-slash variants handled.

**Verify.** `vendor/bin/phpunit --filter WpSiteProfileTest`.

**Done when.** The oracle marks every genuine WP surface as existing and every documented scanner
target as sacrificial, with the xmlrpc/wp-login opt-in and the `is_404` seam proven — so the policy can
never deceive on a real route.

---

## Phase 3 — `RequestFactory`: `RequestEvidence` + client IP

**Change.** `src/RequestFactory.php` per design §4.4. Take `$server` (an array, injected — not the
`$_SERVER` superglobal directly) and `$rawBody` so it is unit-testable:
- `evidence(array $server, ?string $rawBody, Settings $s): \Funnypot\Policy\RequestEvidence` — build the
  policy's neutral evidence (method, path, query, header map, **body-shape only — never the raw body**,
  OAST hygiene) plus the resolved client IP as the actor id. No core `RequestContext` here (the
  evaluator builds that internally).
- `clientIp(array $server, Settings $s): string` — **default the source IP to `REMOTE_ADDR`** (the
  socket peer); trust `X-Forwarded-For` **only** when `REMOTE_ADDR` is inside a configured
  trusted-proxy CIDR; otherwise use `REMOTE_ADDR`. Never trust the raw spoofable header. This is a
  **v1 requirement, not a fast-follow** (D7) — untrusted XFF = spoofable third-party report poisoning
  and actor/persona enumeration — and it is the reference posture piece E (Laravel) mirrors. This value
  is the policy's actor id (seeds deception, keys the pin/reputation, is what a report carries).
- A private CIDR-match helper (IPv4 + IPv6).

**Test first.** `tests/Unit/RequestFactoryTest.php`: XFF honored only behind a trusted proxy; a
forged XFF from an untrusted peer is ignored (returns `REMOTE_ADDR`); IPv6 peer handling; the
`RequestEvidence` header map is built correctly; method/path/query split; the raw body never appears in
the evidence (body-shape only).

**Verify.** `vendor/bin/phpunit --filter RequestFactoryTest`.

**Done when.** Spoofed-XFF cannot rotate the resolved actor id; the trusted-proxy path resolves the
real client; the evidence carries no raw body. (The anti-enumeration + OAST-hygiene invariants of §4.4.)

---

## Phase 4 — `EvaluatorConfig`: Settings → core `Config` (STYLE/engine, behind the evaluator)

**Change.** `src/EvaluatorConfig.php` per design §4.7. This is **only** the STYLE/rendering `Config`
that core's `synthesize()` reads — D no longer builds a respond-mode `Config` with WHEN/WHETHER
closures (`gate`/`probeSignature`/`killSwitch`/`personaSeed` are the policy's concern now, gone from
D). `PolicyFactory` (Phase 7) hands this `Config` to the core-backed evaluator that satisfies
`EvaluatorInterface`; D consumes that evaluator as-is (its concrete adapter ships with policy/core, a C
task) and never calls `classify()`/`synthesize()` itself.
- `fromSettings(Settings $s): \Funnypot\Config` — map the STYLE/engine knobs only:
  `responseStyle`, `severityCeiling`, `attackEmulation`, `nucleiReflection`, `exclude` (=
  `catalog_disabled`), `seedSalt` (= `seed_salt` if set, else WP `AUTH_SALT` via injected resolver),
  `latencyMs`, `latencyJitterMs`, `maxBodyBytes`.

**Config construction on 7.3 (M15).** Do **not** model this on core's
`FunnypotServiceProvider::buildConfig` (named arguments, rejected by D's 7.3 lint). **Prefer** core's
7.3-callable `Config` array/builder factory if C exposed it (named map, no positional coupling — a C
task). **Fallback** until it lands: build `Config` **positionally** with an explicit recipe passing
params **1..N in exact order** up to the highest one D sets, supplying **core's own default** for every
unmapped param — and passing **`pathScope` (pos 3)** and **`personaBreadth` (pos 5)** at their positions
even though the mapping omits them (a skipped middle positional arg silently misassigns later ones). A
code comment pins each position to its source.

**Test first.** `tests/Unit/EvaluatorConfigTest.php` (against real core via the path repo): the built
`Config` reads back the expected value for **every** STYLE/engine field D sets (`responseStyle`,
`severityCeiling`, `attackEmulation`, `nucleiReflection`, `exclude`, `seedSalt`, latency) — the **M15
positional guard** (a wrong value surfaces a misassigned `pathScope`/`personaBreadth`); `seedSalt`
falls back to `AUTH_SALT` when unset; `catalog_disabled` lands in `exclude`. No respond-mode closure
fields are set (assert `gate`/`probeSignature` are core defaults, not D-authored closures).

**Verify.** `vendor/bin/phpunit --filter EvaluatorConfigTest`.

**Done when.** The STYLE/engine settings→`Config` mapping reads back every set field (M15 guard green),
and D authors no WHEN/WHETHER closure (that logic is the policy's).

---

## Phase 4b — `WpStateStore`: the `StateStoreInterface` seam

**Change.** `src/WpStateStore.php implements \Funnypot\Policy\Port\StateStoreInterface` per design §4.6
— the one persistence seam the policy engine reads/writes through. D maps each method to a WP storage
primitive; it authors **no** pin/TTL, learn-then-enforce, or suppression *logic* (all in the policy).
Inject the WP primitives (`get_transient`/`set_transient`/`get_option`/`update_option`/a `$wpdb`
handle) so it is Brain-Monkey-mockable:
- pins + local blocklist → namespaced short-TTL transients (`getPin`/`setPin` with `ttlSeconds`,
  `isBlocked`);
- learn-then-enforce per-rule state → an autoloaded option (`ruleState`/`putRuleState`/
  `bumpRuleEvaluated`);
- suppression ledger + per-actor counters → transients + a bounded `$wpdb` sidecar
  (`seenVerdict`/`incrAlertCount`/`bufferReport`/`takeReportBuffer`/`aggregateScore`/`actorFacts`/`incr`),
  `$wpdb->prepare`d, pruned by the cron sweep. Namespace keys (`honeypot_wp_ss_`) separately from the
  reputation cache's `WpCache` keys (Phase 6b) so the two concerns never collide.
- **local mirror (O1)** → `putMirror(rows, etag, generatedAt, ttl)` / `mirrorVerdict(scoreKey)` /
  `mirrorMeta()`: the cron-pulled thin blacklist rows `{ip→(verdict, expires_at)}` + `{etag,
  generated_at}` meta, the PRIMARY request-path fresh-read (design §4.6/§4.13). Bounded + TTL'd; an
  off-mirror IP returns null (→ escalation), a stale/empty mirror falls through fail-open.
- **selectable backend (RS-10)** → the storage primitive is chosen at construction by
  `Settings::localStateBackend()` (`object-cache` = transients/object-cache + `$wpdb` sidecar; `file` =
  a plugin-owned state dir). **Default `object-cache`** so the default never writes into the plugin dir
  (works on read-only-plugin-dir hosts). Every method's contract is backend-independent; add a small
  `StateBackend` seam (two implementations) the store delegates to. The same backend backs the O1 mirror
  and the decision-N breaker-marker fallback (`sys_get_temp_dir()` filemtime, Phase 6).

**Test first.** `tests/Unit/WpStateStoreTest.php` (Brain Monkey mocks): `setPin`→`getPin` round-trips
with the TTL passed to `set_transient`; `isBlocked` reflects a blocklist entry; `putRuleState`→
`ruleState` round-trips and `bumpRuleEvaluated` increments the counter; `seenVerdict` returns false
then true within the window; `incr`/`incrAlertCount` count within the window; keys are namespaced.
**O1:** `putMirror` then `mirrorVerdict` resolves an on-mirror IP and returns null for an off-mirror one;
`mirrorMeta` returns the stored etag/generated_at. **RS-10:** the whole port contract round-trips under
**both** `local_state_backend=object-cache` and `=file` (a `StateBackend` fake per mode); the default is
`object-cache` and no test path writes into the plugin dir.

**Verify.** `vendor/bin/phpunit --filter WpStateStoreTest`.

**Done when.** Every port method round-trips against a mocked WP store with correct TTLs and namespaced
keys under both backends (default `object-cache`, no plugin-dir write), the O1 mirror methods round-trip,
and D contains no policy logic — only storage mapping.

---

## Phase 4c — `WpGeoIp`: the local GeoIP port (decision R)

**Change.** `src/Geo/WpGeoIp.php implements \Funnypot\Policy\Port\GeoIpInterface` per design §4.14 — the
country-resolution port the policy's country gate (M5, R1) consults. `country(string $ip): ?string`
returns an ISO-3166 alpha-2 code from the **local GeoIP DB** (**DB-IP Lite**, reused from the dashboard +
A1 enrichment; GeoLite2 alternative), **never a network call** (M5), IPv4 + IPv6. Inject the DB reader (a
file/path handle + a lookup callable) so it is pure-unit-testable and a stale/missing DB is handled: an
unresolved IP or an absent/unreadable DB returns **null** (**fail-open** — the country gate then
contributes nothing, never an error). D authors **no** country *decision* logic (the posture/action is
the policy's, from the `country` config, Phase 1). The optional port is wired by `PolicyFactory` only when
`countryPosture() !== 'off'` (Phase 7); the local-DB refresh cron is Phase 8.

**Test first.** `tests/Unit/WpGeoIpTest.php` (injected fake reader): a known IPv4 resolves to its country;
a known IPv6 resolves (v6 support, per P/Q enrichment); an unknown IP returns null; a missing/unreadable
DB returns null **without throwing** (fail-open); no network call is made.

**Verify.** `vendor/bin/phpunit --filter WpGeoIpTest`.

**Done when.** The port resolves IPv4 + IPv6 from the local DB, returns null on miss / absent-DB without
throwing, makes no network call, and carries no country decision logic (that stays the policy's).

---

## Phase 5 — `DecisionExecutor`: perform the effect of a `Decision`

**Change.** `src/DecisionExecutor.php` per design §4.5 — the one place a policy `Decision` becomes a WP
effect. There is **no** `\Funnypot\Observer` any more (observation is the `log` action + the `Logger`
port). Inject the emitter, halt, a `HitLogWriter` seam (`record(array $row): void`), the
`WpStateStore`, and the `WpReporterBridge` so it is unit-testable without side effects:
- `execute(\Funnypot\Policy\Decision $d, \Funnypot\Policy\RequestEvidence $e): bool` — switch on
  `$d->action()`:
  - `allow` → return false (WP proceeds).
  - `log` → write a hit-log row (ts, ip, method, path, action, `$d->reason()`, matched signal handle,
    severity), return false (WP proceeds).
  - `deceive` → `emitter($d->fakeHandle(), $d->status())` then `halt()` — emit core's `synthesize()`
    fake with the **app-chosen** status; return true.
  - `block` → emit an honest `$d->status()` (default `403`) with no honeypot body, then `halt()`;
    return true.
  Then, regardless of action: if `$d->pinTtl()` is set, `stateStore->setPin(...)`; if `$d->report()`
  returns a `ReportIntent`, `reporterBridge->enqueueIntent(...)` (never a blocking POST here). **Status
  is taken from the `Decision`, never invented** (invariant §6.3). Wrap the report/pin side-effects so a
  fault never affects the response.
Also `src/WpdbHitLogWriter.php` (the real `$wpdb->insert`, `$wpdb->prepare`d, bounded) — thin, tested in
integration (Phase 9), not unit.

**Test first.** `tests/Unit/DecisionExecutorTest.php` with fake emitter/halt/writer/store/reporter and a
scripted `Decision` per action: `allow` → no emit, no row, returns false; `log` → one row, no emit,
returns false; `deceive` → emits the `fakeHandle` with the Decision's status then halts (returns true);
`block` → emits a `403` (or the Decision's status) then halts; a `Decision` carrying `pinTtl` calls
`setPin`; one carrying a `report` intent calls `enqueueIntent` once; a throwing reporter/store does not
bubble into the response.

**Verify.** `vendor/bin/phpunit --filter DecisionExecutorTest`.

**Done when.** Each of the four actions performs the right effect with the app-chosen status, the pin +
report side-channels fire when present, and side-effect faults are swallowed.

---

## Phase 6 — `WpdbReportQueue` + `WpReporterBridge`

**Change.** Bridge the reporter to mainnet, mirroring `AbuseIpdb`'s enqueue/drain split and its
transport guards (design §4.9). The bridge is **driven by the policy's `Decision.report` intent** — the
4-layer suppression is the policy's (§9), so the bridge only enqueues/drains what the policy already
vetted; the transport guards are a belt-and-suspenders backstop. The bridge class is
**`WpReporterBridge`** (M8) — **not** `MainnetReporter`, so it does not shadow the relocated
`Funnypot\Mainnet\Reporter` (in `metrictower/mainnet-client`, née piece B, transitive — no
`Funnypot\Report\*` tree, no "if B landed" fork; re-review #6). D binds:
- `src/Report/WpdbReportQueue.php implements \Funnypot\Mainnet\Report\ReportQueue` (push/take/delete/
  dedup/daily against `{$prefix}honeypot_wp_report_queue` + sidecar, `$wpdb->prepare`d), and a thin
  `src/Report/WpReporterBridge.php` that composes **`Funnypot\Mainnet\Reporter`** with `WpdbReportQueue`
  and a `Funnypot\Mainnet\Report\ReportTransport` (WP `wp_remote_post` transport). The transport guards
  (self-IP / public-IP-only / dedup / daily cap) live in the mainnet-client reporter; the bridge is the
  WP-Cron/`$wpdb` adapter.
- **`enqueueIntent(\Funnypot\Policy\ReportIntent $r): void`** — maps the policy's intent onto
  `enqueue(ip, comment, categories)`. This is the entry `DecisionExecutor` (Phase 5) calls.
- **Local-availability fallback (packaging only, not a B/core fork):** if `metrictower/mainnet-client`
  is not yet resolvable in the dev/build checkout, `WpReporterBridge` may carry a **self-contained port**
  of the enqueue/drain + guards with the **identical public shape** (`Funnypot\Mainnet\*` interfaces), so
  it collapses onto the composed reporter with no caller change once the package resolves.
- Either binding POSTs **`Settings::mainnetBaseUrl()` + `/v1/report`** (base URL is scheme+host only; the
  bridge appends the path — D1) with a `Key:` header (`Settings::mainnetKey()`) and body
  `ip,categories,comment,timestamp` **plus `sensor_id`** (the per-install UUID from Phase 1b — D3).
- **`enqueue` signature** matches the reporter exactly: **`enqueue(string $ip, string $comment, string
  $categories = '21')`** (M8) — never the arg-swapped `($ip, $categories, $comment)`.
Either way: **key-gate — empty `MAINNET_KEY` ⇒ inert** (enqueues/sends nothing, D2); self-IP guard
(empty `self_ips` ⇒ reporting disabled, fail-safe), public-routable-IP-only
(`FILTER_FLAG_NO_PRIV_RANGE | NO_RES_RANGE`), per-IP dedup window, daily cap; inject the transport
(`sender` callable) so tests never hit the network.
- **Outage-bounded drain (SF-6 / decision N).** `drain()` takes an injected clock and enforces: a
  per-tick **wall-clock budget** (`Settings::drainBudgetSecs()`, default 10 s) after which it stops;
  **early abort after 3 consecutive transport-class failures**, writing the **shared decision-N breaker
  marker** (`mnc:breaker` in the injected persistent cache, or a `sys_get_temp_dir()` filemtime fallback
  when none is available — the same marker the reputation check/warmer path reads, N6); it **consults
  that marker first** and skips the tick while OPEN. Branch the two 429 classes on the Error `code`
  (SF-7): `duplicate_report` → drop (never loop), `quota_exhausted` → park the marker OPEN until
  `max(Retry-After, X-RateLimit-Reset)` (cap 6 h), never a 30 s re-probe. Re-queued rows carry
  `drainMaxAttempts()`/`drainMaxAgeSecs()` caps (dropped past either); the queue has a hard `queueCap()`
  (oldest dropped first). Inject the marker store + clock so all of this is deterministic in tests.

**Test first.** `tests/Unit/WpReporterBridgeTest.php` with an injected fake transport + in-memory
queue: `enqueueIntent` maps a `ReportIntent` onto `enqueue($ip, $comment, $categories)` in the correct
arg order (M8 — the comment is the comment, not the category CSV); enqueue skips self-IP, skips private
IP, skips when `self_ips` empty, **skips entirely when `MAINNET_KEY` is empty** (D2), skips duplicates
within the window, stops at the daily cap; `drain()` POSTs to **`${mainnetBaseUrl}/v1/report`** (asserts
the base URL had no path and the bridge appended `/v1/report`), uses a `Key:` header, and the body
carries exactly `ip,categories,comment,timestamp` **plus `sensor_id`** (parity with the app's
`AbuseIpdb` and the A1/F contract); 2xx drops, 4xx drops, 5xx retries up to 3. **SF-6 drain bounds** (a
fake clock + stubbed-down transport): the drain stops within `drain_budget_secs`; aborts after 3
consecutive transport failures and **writes the decision-N marker**; a later tick **skips while the
marker is OPEN**; a `duplicate_report` 429 drops without looping while a `quota_exhausted` 429 parks the
marker until the retry-header time; a re-queued row is dropped past `drain_max_attempts`/`drain_max_age`;
the queue never exceeds `queue_cap` (oldest dropped first).

**Verify.** `vendor/bin/phpunit --filter WpReporterBridgeTest`.

**Done when.** `enqueueIntent`'s intent→`enqueue` mapping, the key-gate, all transport guards, the
exact `enqueue(ip, comment, categories)` arg order, the wire shape (`${mainnetBaseUrl}/v1/report`,
body incl. `sensor_id`), and the **SF-6 drain bounds (budget / 3-fail abort + N-marker / 429-class
branch / re-queue + queue caps)** are proven against a stub `/v1/report`, with no real network call.
(Design §7 "Reporter swap test".)

---

## Phase 6b — `WpCache` (reputation cache seam, decision F/M)

**Change.** Under decision M, reputation is a **policy config knob**, not a D-run gate — so D no longer
builds a `ReputationGateFactory` or calls `decide()`. D contributes only the WP **cache backend** F's
`ReputationInterface` reads through; the reputation config (`enabled`/`block_verdicts`/`min_block_score`/
`fail_mode`/`cache_ttl_hours`) is rendered into the policy config array by `Settings::toPolicyConfig`
(Phase 1) and mapped to F's `Config` inside `PolicyFactory` (Phase 7). One small unit:
- `src/Reputation/WpCache.php implements \Funnypot\Mainnet\Cache` — F's PSR-16-style seam over WP
  transients (which ride the persistent object cache when the host has one). Inject the
  `get_transient` / `set_transient` callables (Brain Monkey-mockable) so it is pure-unit-testable;
  namespace the keys (`honeypot_wp_rep_`, distinct from the `WpStateStore` namespace) and set the
  transient TTL from `cache_ttl_hours` (hours → seconds). Cache **both** positive and negative verdicts
  (F caches misses too). 7.3-clean.

**Test first.** `tests/Unit/WpCacheTest.php`: a set/get round-trips a verdict; the TTL passed to
`set_transient` equals `cache_ttl_hours * 3600`; keys are namespaced; a miss returns the injected
default (no exception). The settings→F-`Config` reputation mapping (`check_enabled`, verdict-first
`block_verdicts` + optional `min_block_score` — **no** score `block_threshold` — `cache_ttl_hours`,
`fail_mode`, short `timeout_ms ~1500`) is asserted in `PolicyFactory`'s test (Phase 7): the config
reads back the reputation block only when `checkActive()`, and asserts no `block_threshold` key exists.

**Verify.** `vendor/bin/phpunit --filter WpCacheTest`.

**Done when.** The cache adapter round-trips with the `cache_ttl_hours` TTL and namespaced keys, caches
misses, and stays a pure storage seam — the reputation *decision* is the policy's, wired in Phase 7.

---

## Phase 6c — `BlacklistMirror` (O1 local-mirror-lite) + reputation warmer (SF-6)

**Change.** The O1 fleet-scale fresh-read + the SF-6 warmer, both pure/injected so they unit-test
without WP or the network (design §4.8/§4.13, decisions O1/SF-6/N):
- `src/Mirror/BlacklistMirror.php` — a cron-driven, **conditional** pull of A1's **thin blacklist
  artifact** (`Settings::mainnetBaseUrl()` + `/v1/blacklist`, `variant=thin`, `format=json`, `Key:`
  header) sending the stored `ETag`. Inject the HTTP sender + clock. A `200` → `WpStateStore::putMirror(
  rows, etag, generatedAt, ttl)`; a `304` refreshes only freshness; **breaker-guarded** (consults the
  decision-N marker; a mainnet outage skips the pull and the mirror simply ages) and **fail-open** (a
  stale/empty mirror never blocks). Inert unless `checkActive()` **and** `mirrorEnabled()`. **P2/Q2:** a
  thin row's `ip` field may be a **CIDR** (IPv4 `/24`, IPv6 `/64`) or an **ASN**, not just a `/128`/`/32`;
  `BlacklistMirror` stores rows as-is and the request-path match is by **CIDR-containment / ASN-lookup —
  the containment matcher is `funnypot-policy`'s** (consumed via the `ReputationInterface` / mirror-lookup
  seam), never reimplemented in D. The client normalises an IPv6 to its `/64` `score_key` before the
  lookup (P2). No new D build beyond consuming the policy's matcher — this note only records the
  range-row shape D must store and pass through faithfully.
- `src/Reputation/Warmer.php` — the out-of-band reputation warmer: `enqueue(string $ip)` (bounded local
  queue of uncached, **off-mirror** actor IPs, filled by the interceptor, Phase 7) + `drain(int $limit)`
  draining through F's `Client::check`/`cachedVerdict`, **breaker-guarded** and **bounded per tick**,
  populating F's `WpCache`. **Never an inline request-path check** (M5). Inject the client + clock +
  marker store.
- The request-path read order the `ReputationInterface` adapter uses becomes **mirror-first
  (`mirrorVerdict`) → F's cache → fail-open `unknown`**, and an off-mirror uncached IP is handed to the
  warmer queue instead of a synchronous check (wired in Phase 7).
- `src/Geo/GeoIpRefresh.php` (**decision R2**) — a cron-driven, **conditional** refresh of the local
  GeoIP DB the `WpGeoIp` port (Phase 4c) reads, riding the **same data-distribution / freshness seam** as
  `BlacklistMirror`: an `ETag`/`Last-Modified`-conditional pull of the DB-IP Lite dataset that writes the
  file **in place** and refreshes only freshness on a `304`. Inject the HTTP sender + clock + file writer.
  Runs on a slow cadence (`geoipRefreshIntervalSecs()`, default monthly), inert unless
  `countryPosture() !== 'off'`, and **fail-open** (a failed/stale pull leaves the existing DB; a
  missing DB makes `country()` return null). Not a request-path concern — request-time resolution is the
  local read only (M5).

**Test first.**
- `tests/Unit/BlacklistMirrorTest.php`: a `200` calls `putMirror` with the rows/etag/generated_at; a
  `304` refreshes freshness only; the stored `ETag` is sent on the next pull; a breaker-OPEN marker skips
  the pull (no sender call); disabled (`mirror_enabled=false` or `checkActive()==false`) → no-op.
- `tests/Unit/WarmerTest.php`: `enqueue` bounds the queue (cap enforced); `drain` calls the client only
  up to the per-tick limit and stops; a breaker-OPEN marker skips the drain; a fault is swallowed
  (fail-open), never thrown into a caller.
- `tests/Unit/GeoIpRefreshTest.php` (**R2**): a `200` writes the new DB file (injected writer) and stores
  the `ETag`; a `304` writes nothing and only refreshes freshness; the stored `ETag`/`Last-Modified` is
  sent on the next pull; disabled (`country_posture=off`) → no-op; a failed pull leaves the existing file
  untouched (fail-open) and never throws.

**Verify.** `vendor/bin/phpunit --filter 'BlacklistMirrorTest|WarmerTest|GeoIpRefreshTest'`.

**Done when.** The mirror pulls conditionally (ETag/304), populates the store, and is breaker-guarded +
inert-by-default; the warmer enqueues off-mirror IPs and drains them bounded + breaker-guarded, never
inline — so the request path is mirror-first and never makes a synchronous check (M5/O1/SF-6); the GeoIP
refresh pulls the local DB conditionally, writes in place, is inert unless country policy is enabled, and
is fail-open (R2) — never a request-path network call.

---

## Phase 7 — `PolicyFactory` + `Interceptor`: normalize → evaluate → execute, degrade-safe

**Change (7a — `PolicyFactory`).** `src/PolicyFactory.php` per design §4.3.
`forPosition(Settings $s, string $position): \Funnypot\Policy\PolicyEngine` builds the §8 config array
(`PolicyConfig::fromArray($s->toPolicyConfig($position))`) and injects the five ports: the core-backed
`EvaluatorInterface` (constructed with `EvaluatorConfig::fromSettings`, Phase 4), F's
`ReputationInterface` mapped from settings (`base_url`/`key`/`check_enabled`/`block_verdicts`/
`min_block_score`/`fail_mode`/`cache_ttl_hours`/short `timeout_ms`, verdict-first — **no**
`block_threshold`) backed by `WpCache` (Phase 6b), `WpStateStore` (Phase 4b), a `WpClock`, and a
`WpLogger`. **When `Settings::countryPosture() !== 'off'` (decision R)** it also injects the optional
**sixth** port — `WpGeoIp` (Phase 4c) as the policy's `GeoIpInterface`, backed by the local GeoIP DB — so
the policy's country gate can resolve a country; otherwise `WpGeoIp` is not constructed and the port is
absent. D authors no decision logic here — only wiring.

**Change (7b — `Interceptor`).** `src/Interceptor.php` per design §3 + §4.1, §6.2. Two public entry
points hooked at priority 0, each **idempotent** via its own static `$ran` guard: `runBefore()` and
`runFallback()`. Inject settable seams (a static `$emitter` default `\Funnypot\Http\ResponseEmitter::emit`,
a static `$halt` default `exit`, a settable `$policyFactory` default `PolicyFactory::forPosition`, and a
`$decisionExecutor`) so the flow is driven by a **fake `PolicyEngine`** in tests. Shared private body
`handle(string $position)`:
0. **Record the runtime mount (Wordfence gap a).** On first `runBefore` entry, record **which hook
   fired** — `muplugins_loaded` vs `plugins_loaded` — to a short-TTL mount marker (via `WpStateStore`),
   so `status` (Phase 8) can report the *verified* BEFORE mount (`mu-plugin` | `plugins_loaded
   (degraded)` | `not running`) rather than the configured intent. A pure `mountState()` helper maps the
   observed hook + configured position → the reported state; extract it for unit test.
1. master switch off (`!Settings->enabled`) → return, WP proceeds. Position gate: `runBefore` returns
   unless `position.before`; `runFallback` returns unless `position.fallback` **and** `is_404()`.
2. build `RequestEvidence` + `WpSiteProfile` (RequestFactory / Phase 3, WpSiteProfile / Phase 2 — the
   fallback profile consults `is_404()`).
3. `$engine = PolicyFactory::forPosition(settings, position)`.
4. `$decision = $engine->evaluate($evidence)`.
5. `$decisionExecutor->execute($decision, $evidence)` (Phase 5) — performs allow/log/deceive/block +
   pin + report; emits+halts on deceive/block via the injected seams.
6. **Wrap 2–5 in `try { } catch (\Throwable $e) { return; }`** so any policy/evaluator fault degrades to
   "WP proceeds normally" (`Decision::allow`), never a 500 (invariant §6.2 — a 500 is itself a tell).

The mirror-first read + off-mirror warmer enqueue (O1/SF-6) lives inside the `ReputationInterface`
adapter `PolicyFactory` wires (Phase 6b/6c), not in the interceptor body: the adapter reads
`mirrorVerdict` → `WpCache` → fail-open and enqueues an uncached off-mirror actor IP to the `Warmer`
(Phase 6c) — never a synchronous check. `PolicyFactory` therefore also injects the `BlacklistMirror`/
`Warmer` seams into that adapter when `checkActive()`.

**Test first.** `tests/Unit/PolicyFactoryTest.php`: the built engine's config reads back
`posture`/`position`/`actions` from settings; the reputation block is present only when `checkActive()`,
reads back `block_verdicts=['malicious','critical']` (+ `min_block_score` when set, else null), and has
**no** `block_threshold` key; the built config's `country` block reads back from settings and the
**`GeoIpInterface` port is injected only when `countryPosture() !== 'off'`** (absent by default, decision
R); the injected ports are the WP adapters.
`tests/Unit/InterceptorTest.php` with Brain Monkey + injected emitter/halt spies + a **fake
`PolicyEngine`**: master-off returns without evaluating; `runBefore` returns when `position.before` is
false; `runFallback` returns when `is_404()` is false; a fake engine returning `deceive` calls the
emitter once with the fake's status then halts; `block` emits a `403` then halts; `allow`/`log` fall
through without emitting; a thrown `\Throwable` from `evaluate` is swallowed (no emit, no halt, no
rethrow — fail-safe, no 500); each entry called twice fires its body once (idempotency); **the mount
marker records the hook that fired and `mountState()` maps observed-hook + configured-position →
`mu-plugin`/`plugins_loaded (degraded)`/`not running`** (Wordfence gap a).

**Verify.** `vendor/bin/phpunit --filter 'PolicyFactoryTest|InterceptorTest'`.

**Done when.** `PolicyFactory` wires the five ports + config (reputation present only when active), and
both interceptor entry points normalize→evaluate→execute with correct position gating, degrade-safe
try/catch, and idempotency — the emit/exit side effects observed through injected spies.

---

## Phase 8 — Bootstrap, hooks, activation shim, admin screen, WP-CLI

**Change.** Wire everything into WordPress (design §4.1, §4.3, §4.10, §5, §6). Mostly WP-integration;
unit-test the pure pieces:
- `honeypot-wordpress.php` — register the **two position hooks**:
  `add_action('muplugins_loaded', [Interceptor::class,'runBefore'], 0)` +
  `add_action('plugins_loaded', [Interceptor::class,'runBefore'], 0)` (idempotent guard makes the double
  registration safe) and `add_action('template_redirect', [Interceptor::class,'runFallback'], 0)`, plus
  admin menu, WP-CLI, activation/deactivation hooks.
- `src/MuLoaderInstaller.php` + the shipped `mu-loader` shim — activation copies a tiny loader shim into
  `wp-content/mu-plugins/` (fires at `muplugins_loaded` for the BEFORE position); if that dir is not
  writable, register an admin notice and fall back to `plugins_loaded`. Deactivation removes the shim.
  The FALLBACK hook needs no shim. Split the writability decision into a pure `plan(bool $writable):
  string` (`'mu'|'fallback'`) so it is unit-testable; the filesystem write itself is integration-tested.
  **The shim is degrade-safe (SF-4):** its body is `if (!file_exists($bootstrap)) { return; }` (never
  fatal on a missing plugin), `require`s **one stable versioned entry file** (`mu-entry.php`) and calls a
  single **guarded static** (`class_exists`/`method_exists` + `try/catch`) so shim/plugin version skew
  degrades to inert, not fatal. The plugin **self-heals** a stale/missing shim on normal load and the
  shim **self-removes/no-ops** when the plugin is gone. Extract a pure `shimBody(bool $pluginPresent):
  string` / `isStale($shim): bool` for unit test; the actual FS write is integration-tested.
- `src/Admin/SettingsScreen.php` — Settings → Honeypot: master enable, **posture (`honeypot|WAF|both`)**,
  **position (`before`/`fallback` checkboxes)**, **per-band actions**, response style, severity ceiling,
  attack-emulation, nuclei-reflection, per-class catalog toggles, the **learn-then-enforce controls**
  (a rule table with SHADOW→TUNING→ENFORCED one-click promotions + a global kill-switch), the
  **suppression** knobs, reporting fields (`mainnet_base_url` — scheme+host only, `mainnet_key`,
  `self_ips`, `daily_cap`), and the **reputation fields (verdict-first): `check_enabled` (default off),
  `block_verdicts` (multi-select, default `['malicious','critical']`), `min_block_score` (optional floor,
  default blank/null), `cache_ttl_hours`, `fail_mode`** (the `mainnet_key` field is shared with
  reporting), the **country-policy fields (decision R): `country_posture` (`off|deny_list|allow_list`,
  default `off`), `country_list` (ISO-3166 alpha-2 multi-select), `country_action`
  (`block|deceive|score-modifier`, default `score-modifier`)** — with UI copy noting a hard `block` /
  allow-list is an eyes-open, FP-blunt opt-in (R3/R4), + a plain recent-hits table. The screen's job is to
  **produce the §8 policy config array** via `Settings::toPolicyConfig`. `manage_options` capability,
  nonce-protected; a `sanitize` callback whitelists to the `Settings` shape (design §6.6): **strips any
  path from `mainnet_base_url`** (D1), whitelists `posture`/`fail_mode` and `block_verdicts` to their
  enums, coerces `min_block_score` to int|null, clamps `cache_ttl_hours` + the suppression numerics to
  sane ranges, and whitelists `country_posture`/`country_action` to their enums + `country_list` to valid
  alpha-2 codes (decision R). Unit-test the sanitize callback in isolation.
- **Sensor id wiring (D3):** on activation, call `SensorId::resolve(get_option, update_option,
  'wp_generate_uuid4')` to generate + persist the `honeypot_wp_sensor_id` option once; the reporter
  reads it lazily on first report too. The pure resolver is proven in Phase 1b; this is the WP wiring.
- `src/Cli/HoneypotCommand.php` — `wp honeypot status|enable|disable|test|catalog|report-drain|
  mirror-pull|geoip-refresh|promote|shadow` (design §4.10). `test <path>` dry-runs `evaluate()` and prints
  the `Decision` action + status + Content-Type + `reason`; `promote`/`shadow` drive learn-then-enforce
  transitions via `WpStateStore`; **`status` reports the verified BEFORE mount** (`mu-plugin` |
  `plugins_loaded (degraded)` | `not running`, from the Phase-7 mount marker) + the O1 mirror age, not
  just the configured intent; **`mirror-pull`** runs `BlacklistMirror` once and **`geoip-refresh`** runs
  `GeoIpRefresh` once (real-cron installs, R2). Registered only when `defined('WP_CLI')`.
- `src/Admin/Notices.php` — an **admin notice when the effective position is degraded below the
  configured one** (mount marker shows `plugins_loaded (degraded)` / `not running` while a BEFORE posture
  is configured, or the mu-dir was unwritable at install) — Wordfence gap a. Pure
  `noticeFor(mountState, configuredPosition): ?string`.
- `src/Cron.php` — `wp_schedule_event` hooks: a 5-minute **report-drain** (design §4.9; also `wp honeypot
  report-drain`), the SF-6 **reputation warmer** drain (bounded per tick), the O1 **mirror-pull**
  (default hourly; also `wp honeypot mirror-pull`), and the R2 **GeoIP-refresh** (default monthly, the
  DB-IP Lite cadence; also `wp honeypot geoip-refresh`; inert unless country policy is enabled). All are
  outage-bounded / breaker-guarded / fail-open and **document the WP-Cron low-traffic caveat + recommend a
  real system cron** (`DISABLE_WP_CRON` + a server crontab) for reporting/checking/mirror/geo installs.
- Table DDL (`dbDelta`) for `honeypot_wp_hits`, `honeypot_wp_report_queue` + sidecar, the `WpStateStore`
  suppression sidecar, and (when `local_state_backend=object-cache`) the O1 mirror + warmer-queue rows,
  created on activation (design §5).

**Test first.**
- `tests/Unit/MuLoaderInstallerTest.php`: `plan(true)==='mu'`, `plan(false)==='fallback'`; **SF-4**
  `shimBody(false)` produces an inert no-op body and `shimBody(true)` a `file_exists`-guarded body that
  `require`s the stable entry + calls the guarded static; `isStale` detects a skewed/missing shim (drives
  self-heal); the generated shim body contains no fatal path when the bootstrap is absent.
- `tests/Unit/SettingsSanitizeTest.php`: the admin sanitize callback rejects/normalizes junk to the
  `Settings` shape (posture/position enums; per-band actions; the reputation fields — `check_enabled`
  bool default off, `block_verdicts` whitelisted to the verdict enum default `['malicious','critical']`,
  `min_block_score` int|null, `cache_ttl_hours` clamped, `fail_mode` `open|closed`; suppression numerics
  clamped; **`local_state_backend` whitelisted to `object-cache|file` default `object-cache`**;
  `mirror_enabled` bool; the SF-6 drain numerics clamped; **the R country fields — `country_posture`
  whitelisted to `off|deny_list|allow_list` default `off`, `country_action` to
  `block|deceive|score-modifier` default `score-modifier`, `country_list` to valid alpha-2 codes**);
  capability + nonce paths asserted via Brain Monkey.
- `tests/Unit/CliStatusTest.php`: `status` composes the summary string (posture / configured position /
  **verified mount** / rule phases / queue depth / mirror age) from a `Settings` + a fake mount marker +
  fake state source without touching WP-CLI I/O (extract the summary builder as a pure method).
- `tests/Unit/NoticesTest.php`: `noticeFor` returns a degraded-position notice when the mount state is
  below the configured BEFORE posture, and null when the mount matches (Wordfence gap a).

**Verify.** `vendor/bin/phpunit --testsuite unit` (whole unit suite green).

**Done when.** Hooks/menu/CLI/cron are wired, the shim install/fallback decision and the settings
sanitizer are unit-proven, and the unit suite is green end to end. (Runtime behavior in a real WP is
Phase 9.)

---

## Phase 9 — Integration on real WordPress (Docker) + golden parity

**Change.** `.wp-env.json` mounting the plugin (and a stock theme), plus `tests/Integration/*` using
the wp-env PHPUnit bridge. Bundle policy + core + mainnet-client into `vendor/` for the running site
(the build step of Phase 10, run here for the test site). Integration cases (design §7):
- **FALLBACK deceive**: `GET /.env` (posture `honeypot`, `position.fallback`) is deceived with core's
  fake at the correct `Content-Type` + expected status, and the **theme never renders the 404 template**
  (assert no theme 404 output). This runs at `template_redirect` on a genuine `is_404()`.
- A real published page **and** `/wp-login.php` are byte-identical to plugin-off (untouched).
- Master-switch-off is inert on the wire (both positions return).
- **Golden emit parity**: the same deceived probe + fixed seed yields a body/headers byte-identical to
  the standalone funnypot app (proves the plugin adds nothing on-wire). Pin the seed via `seed_salt` and
  assert against a captured golden fixture from the app for the same bundled rules.
- **Reporter swap**: point the reporter at a stub `/v1/report` and assert the POST body/headers match
  the app's `AbuseIpdb` shape (driven by a `Decision.report` intent).
- **BEFORE reputation-block (F/M)**: with `check_enabled` off (default) the site behaves as above (no
  reputation lookup). With posture `WAF`, `position.before`, `reputation.enabled`+key set, and a
  **pre-warmed stub reputation cache / mirror**, a `malicious` IP gets a plain `403` at the
  before-position, an `unknown` IP falls through, and a fail-open verdict (`429`/timeout in the warmer)
  leaves the request proceeding — the site never goes down.
- **SF-4 shim takedown**: install the plugin (mu-shim copied), then **remove the plugin directory
  without deactivating** and assert a normal request (and wp-admin) still serves — the stale shim is
  inert, never fatal.
- **O1 mirror-first read**: with a stub `/v1/blacklist` thin artifact, `wp honeypot mirror-pull`
  populates the mirror; a subsequent request for an on-mirror `malicious` IP is blocked (WAF posture)
  **with zero `/v1/check` calls** (assert the check stub was not hit), while an off-mirror IP is enqueued
  to the warmer, not checked in-request; a `304` on the next pull re-uses the mirror. **Status mount**:
  after wiping the mu-shim, `wp honeypot status` reports `plugins_loaded (degraded)` and the admin notice
  appears.
- **Country policy (R)**: with a bundled test GeoIP DB and `country_posture` set, a request from an IP
  that geolocates into a deny-listed country gets the configured action (default `score-modifier` — the
  request is flagged/scrutinised, not hard-blocked; and, under an explicit `block` opt-in, a `403`), while
  an unlisted-country IP falls through; the country resolution makes **zero network calls** (local DB
  only); a missing/removed GeoIP DB leaves the gate inert (fail-open — `country()` null) and the site
  serves normally.

**Test first.** Write each assertion before enabling the corresponding path; run against a freshly
`wp-env start`ed site.

**Verify.** `npm ci && npx wp-env start && composer test:integration`.

**Done when.** All integration + golden-parity + reporter-swap + reputation-block + **SF-4 shim-takedown
+ O1 mirror-first + status-mount** cases pass on a real WP, and the plugin-off byte-identity for genuine
surfaces holds.

---

## Phase 10 — Build, package, static analysis, CI matrix

**Change.**
- `bin/build.sh` — `composer install --no-dev` with policy + core + mainnet-client resolved from the
  path repos (or published VCS repos), producing `vendor/metrictower/{funnypot-policy,funnypot-core,
  mainnet-client}/` + core's bundled rules artifacts, then zip the plugin
  (`build/honeypot-wordpress.zip`). Committed vendor is out; the zip carries it (design §5, §8.6). Also
  bundle/reference the **local GeoIP DB** (DB-IP Lite) the country gate reads (decision R2) — a
  refreshed-in-place data asset, distinct from the never-written vendor bundle; the `geoip-refresh` cron
  updates it (Phase 8).
- `phpcs.xml.dist` — WordPress-Coding-Standards over the WP-glue code (design §7).
- `.github/workflows/ci.yml` — matrix `php: [7.3, 7.4, 8.0, 8.1, 8.2, 8.3]` running the unit suite and
  `php -l` over `src/` (the 7.3 lint is the gate that keeps D's glue 7.3-clean **before** C lands),
  plus `phpcs`, plus the wp-env integration job.
- `README.md` — install (zip / `composer require metrictower/honeypot-wordpress`), the inert-by-default
  posture, how to enable a posture (honeypot/WAF/both) and position, the `HONEYPOT_WP_MAINNET_BASE_URL`
  / `HONEYPOT_WP_MAINNET_KEY` constants (base URL is scheme+host only; reporting inert without a key),
  and the C dependency note.

**Test first.** A CI smoke assertion: the built zip contains
`vendor/metrictower/{funnypot-policy,funnypot-core,mainnet-client}/` and core's rules artifacts, and
`php -l` passes on every `src/*.php` under 7.3.

**Verify.** `bin/build.sh && phpcs && vendor/bin/phpunit --testsuite unit` locally; the CI matrix
green on push.

**Done when.** A single command produces a self-contained installable zip, the 7.3→8.3 lint/unit
matrix is green, and phpcs passes on glue code.

---

## Risks & open decisions

1. **HARD BLOCK — C must land before the plugin can run on real WP hosts.** Core is `"php": ">=8.0"`;
   the real 7.3 blockers are **constructor property promotion** plus the 7.4-only constructs (**typed
   properties, arrow functions, `??=`**) — core uses **no** named arguments and **no** union types (per
   C's audit), so those are not blockers (`funnypot-core/composer.json`, `Config.php:48`). **C must also
   land the M2 two-phase split** (`classify()`+`synthesize()` behind the policy's `EvaluatorInterface`) —
   D consumes the core-backed evaluator, not `respond()`. Until C re-floors core to 7.3 and ships the
   split (keeping the fingerprint CI gates green), the bundled core will fatal on a 7.3 host and the
   evaluator seam is absent. **Mitigation:** Phases 1–8 build and test D's glue against a **fake
   `PolicyEngine`** and current packages on the 8.x host via the path repos; D's own code is 7.3-clean
   and lint-gated from Phase 1; only Phase 9/10's 7.3-runtime + real-evaluator rows are gated on C. **Do
   not ship the zip until C (and funnypot-policy) are merged.** Coordinate with the C and policy owners.
1b. **funnypot-policy must land** (the primary dependency). It is being authored in parallel
   (`funnypot-policy/docs/`); D develops against its published interface + a fake engine. If the policy
   package's public API shifts, D's adapter seams (the five ports, `Decision`/`RequestEvidence`/
   `SiteProfile` shapes, `PolicyConfig::fromArray`) shift with it — track against the policy spec as the
   source of truth for the contract.
2. **`metrictower/mainnet-client` may not be resolvable in a local checkout** when Phase 6 runs. This
   is now a **packaging/vendoring** question, not a B/core fork: decision F puts the reporter
   (`Funnypot\Mainnet\Reporter`) in the client package, transitive via core, so it is *always* the
   binding target — there is no "reporter in core" branch to gate on. The bridge composes
   `Funnypot\Mainnet\Reporter` when the package resolves, and otherwise carries a self-contained port
   behind the **identical `Funnypot\Mainnet\*` interfaces** so it collapses onto the composed reporter
   with no caller change. Reporting is off by default regardless. **Open decision for review:** ship v1
   with the self-contained port to avoid blocking on the package landing, or gate reporting on it?
   (Recommend: self-contained port.)
3. **`muplugins_loaded` shim write** into `wp-content/mu-plugins/` is a filesystem side effect on a
   directory that is often not writable (managed WP, hardened perms). The `plugins_loaded` fallback is
   specced and tested, but it runs slightly later; confirm at review that `plugins_loaded` priority 0
   is still before any theme/`template_redirect` output on the target hosts. **The stale-shim takedown
   risk is now closed by SF-4** (Phase 8): the shim `file_exists`-guards the bootstrap, uses a guarded
   static + versioned entry for skew, self-heals and self-removes — so a plugin dir removed without
   deactivation leaves the shim inert, never fatal (integration-tested in Phase 9). The residual open
   item is purely the writability/timing confirmation above, not a takedown vector.
4. **`WpSiteProfile.routeExists` at the BEFORE position (Phase 2/7).** At `muplugins_loaded`/
   `plugins_loaded` the main query has **not run yet**, so the BEFORE-position `routeExists` covers only
   the static reserved-prefix set — a real permalink is not yet known to exist. The policy's matched-only
   `classify()` + precedence keep a real content path from being deceived there (a real post path is not
   a compiled scanner persona), and the FALLBACK position resolves `is_404()` exactly, so this is
   belt-and-suspenders. **Open decision:** is the static-prefix oracle + matched-only classify sufficient
   at BEFORE, or do we need a permalink-aware pre-check? (Recommend: rely on matched-only + the FALLBACK
   `is_404()` oracle; document that real content paths are never compiled personas.)
5. **Golden-emit parity (Phase 9)** couples D to the app's exact bundled rules + persona seed. If the
   two repos drift on rules versions the fixture breaks. **Mitigation:** pin the golden fixture to a
   named rules artifact version and regenerate it in CI when core's rules bump.
6. **wp-env / Docker in CI** adds a heavy integration job. If CI Docker is unavailable, Phase 9 can
   run locally/nightly while the unit matrix gates PRs.
7. **AUTH_SALT as default `seedSalt`.** Convenient, but if a site rotates salts the persona mapping
   shifts. Acceptable (re-scans just re-spread), but confirm at review.

## Definition of done

- `vendor/bin/phpunit --testsuite unit` green on the PHP 7.3→8.3 matrix; `php -l src/*.php` clean on
  7.3; phpcs (WordPress-Coding-Standards) clean on glue code. Every unit phase drives a **fake
  `PolicyEngine`** (no policy logic re-tested in D).
- `composer test:integration` green on a real wp-env WordPress: a FALLBACK `/.env` probe deceived with
  correct Content-Type and no 404-template render; genuine surfaces (`/wp-login.php`, a real page)
  byte-identical to plugin-off; master-off inert.
- Golden-emit parity test passes (byte-identical body/headers vs the standalone app for a fixed seed).
- Reporter enqueue/drain guards proven; `enqueueIntent` maps a `ReportIntent` onto `enqueue(ip, comment,
  categories)` in the correct arg order (M8); POST to `${mainnetBaseUrl}/v1/report` (base URL scheme+host
  only) with body incl. `sensor_id` matches the AbuseIpdb/F/A1 wire shape; reporting off by default,
  **inert without `MAINNET_KEY`**, fail-safe when `self_ips` empty, and driven by the policy's
  suppression-vetted `Decision.report`.
- Reputation proven as **policy config** (F/M): off by default and inert unless
  `reputation.enabled`+`MAINNET_KEY`; **mirror-first → cache → fail-open** on the request path (no sync
  call, via `WpCache`/O1 mirror); a block is a `Decision.action` the executor emits as a plain app-chosen
  `403` at the BEFORE position; **fail-open** on mainnet down/timeout/`429`; reputation is a modifier
  (never primary, never deceive/block on its own by default). No `ReputationGateFactory` / home-grown
  gate.
- **SF-4** — the mu-plugin shim is degrade-safe (missing-bootstrap → inert, guarded static + versioned
  entry for skew, self-heal/self-remove); the shim-takedown integration test (plugin dir removed without
  deactivation → site serves) passes.
- **SF-6 / decision N** — the report drain is outage-bounded (10 s budget, 3-fail abort writing the
  shared `mnc:breaker` marker, 429-class branch, re-queue + queue caps); the reputation warmer is a
  specced v1 deliverable (enqueue off-mirror uncached IPs, cron-drained, breaker-guarded, bounded per
  tick, never inline); the WP-Cron low-traffic caveat is documented + real cron recommended.
- **O1** — local-mirror-lite is the PRIMARY fresh-read: the thin blacklist artifact is pulled on cron
  (ETag/304) into `WpStateStore` and consulted before any per-IP `check`; the mirror-first integration
  test blocks an on-mirror IP with zero `/v1/check` calls.
- **O2** — D/E hold a single `sensor`-tier key (report + escalation-check rights, metered per-install);
  the F-vs-D key contradiction is reconciled.
- **RS-10** — the local-state backend is selectable (`object-cache|file`), default `object-cache`, and
  works where the plugin dir is not writable (both-backend port round-trip proven).
- **Runtime position self-check (Wordfence gap a)** — `status` reports the verified BEFORE mount
  (`mu-plugin` | `plugins_loaded (degraded)` | `not running`) and a degraded mount raises an admin
  notice.
- **P2/Q2** — the O1 mirror stores range/ASN rows (CIDR `/24`, IPv6 `/64`, ASN) and the request-path
  match is by containment / ASN-lookup via `funnypot-policy`'s matcher (not reimplemented in D); an IPv6
  is normalised to its `/64` `score_key` before lookup.
- **R (country policy)** — the admin produces a `country` config block (deny-list/allow-list posture;
  action `block|deceive|score-modifier`, default `score-modifier`); `WpGeoIp` resolves country from the
  **local** GeoIP DB (DB-IP Lite, no network call, IPv4 + IPv6, fail-open on miss/absent-DB); the local DB
  is bundled/referenced and refreshed in place on cron (the same data-distribution seam as the O1 mirror);
  the country gate is the policy's, D authors no country decision logic.
- `bin/build.sh` produces a self-contained zip bundling
  `vendor/metrictower/{funnypot-policy,funnypot-core,mainnet-client}/` + rules + the local GeoIP DB.
- Install is inert by default; enabling a posture/position is an explicit operator action; the
  RCE-adjacent runtime rule-update path is **not** exposed in the WP admin (design §6.5).
- No new core API required beyond the C re-floor + the M2 two-phase split (design §9); all security
  invariants of §6 hold by delegation to the policy + core (deception governing rule / opaque signal
  handle, fail-safe-to-allow / degrade-never-500, CT-matches-request + app-chosen status, report
  self-guard + suppression backstops).

## Key decisions I made (confirm at review)

1. **D is a thin adapter over `funnypot-policy` (decision M).** Every phase drives a **fake
   `PolicyEngine`**; D authors no precedence / state-machine / suppression logic. The phases build only
   the five §12 adapter responsibilities: normalize (`RequestFactory`/`WpSiteProfile`), execute
   (`DecisionExecutor`), storage (`WpStateStore`), hook placement (`Interceptor` two positions), admin UI
   (`SettingsScreen`→`toPolicyConfig`).
2. **Test stack = pure PHPUnit + Brain Monkey + Mockery for the unit suite, wp-env (Docker) for
   integration**, with policy + core + mainnet-client resolved via Composer **path repositories** during
   development and **bundled into the zip** at build. The vast majority of logic is fast-unit-tested with
   no WP install, matching the design's posture.
3. **Injected seams for the un-unit-testable side effects**: `Interceptor` takes settable
   `$emitter`/`$halt`/`$policyFactory`/`$decisionExecutor`; `RequestFactory` takes a `$server` array not
   the superglobal; the reporter takes a `sender` callable; `WpStateStore`/`WpCache` take the WP
   primitives; `EvaluatorConfig`/`Settings` take constant/`AUTH_SALT` resolvers. This lets Phases 1–8 be
   TDD'd without a browser or DB.
4. **Develop against current (PHP-8) packages + a fake engine; gate the 7.3-runtime + real-evaluator
   rows on C.** D's glue is written 7.3-clean and lint-gated from Phase 1, so nothing regresses when C
   (and the M2 split) land — but the whole plan does not wait on C, since Phases 1–8 are verifiable on
   the 8.x host today.
5. **Phase 6 binds the relocated `Funnypot\Mainnet\Reporter`** (transitive via core/policy — no
   `Funnypot\Report\*` tree, no "if B landed" fork). The only variance is packaging: compose the package's
   reporter when it resolves, else carry a self-contained port behind the identical `Funnypot\Mainnet\*`
   interfaces. Recommend shipping the port so D is not blocked on the package landing — open decision.
6. **Reputation is a policy config knob + `WpCache` backing, not a D-run gate** (design §4.8). D drops
   the `ReputationGateFactory` and the interceptor "step 0"; the reputation *decision* is the policy's,
   consumed cache-first (no sync request-path call, M5).
7. **Phase ordering builds pure→wired**: value objects + pure predicates first (Settings, WpSiteProfile,
   RequestFactory, EvaluatorConfig, WpStateStore, DecisionExecutor, Reporter, WpCache), then the
   `PolicyFactory` wiring + the orchestrating `Interceptor`, then WP bootstrap/admin/CLI, then real-WP
   integration, then packaging — so the suite stays green at every step and the risky Docker/parity work
   is isolated to Phase 9.
8. **Static-prefix `routeExists` + matched-only classify is treated as sufficient at the BEFORE
   position** for keeping real content untouched; the permalink-aware live-post pre-check is a documented
   belt-and-suspenders seam, not a hard requirement (open decision #4).

## Dependencies on other pieces

- **`metrictower/funnypot-policy` — PRIMARY (decision M).** D consumes `PolicyEngine::evaluate`, the five
  ports, the `Decision`/`RequestEvidence`/`SiteProfile`/`ReportIntent` value objects, and
  `PolicyConfig::fromArray`. PHP >=7.3, framework-free; bundled in the plugin `vendor/` (pulls core +
  mainnet-client transitively). Authored in parallel (`funnypot-policy/docs/`); the policy spec is the
  source of truth for the contract D adapts to.
- **C · funnypot-core → PHP 7.3 + the M2 two-phase split — HARD PREREQUISITE.** The plugin bundles core;
  core must run on 7.3 **and** expose `classify()`+`synthesize()` behind the policy's `EvaluatorInterface`
  before the zip is shippable. Phases 1–8 develop against a fake engine on the 8.x host; Phases 9–10's
  7.3-runtime + real-evaluator rows and the ship gate are blocked on C. C must keep the fingerprint CI
  gates green (design §6.1). D also asks C to expose a **7.3-callable `Config` array/builder factory**
  (M15) — preferred over the positional fallback in Phase 4, not a hard prerequisite.
- **B · report-to-mainnet — PROVIDED BY F, not a separate dependency.** F relocated the reporter into
  `metrictower/mainnet-client` as `Funnypot\Mainnet\Reporter` (+ `Report\ReportQueue`/`ReportTransport`),
  transitive — no `Funnypot\Report\*` tree, no "if B landed" fork. Phase 6 binds a `WpdbReportQueue` + a
  `WpReporterBridge` (M8) composing that reporter, driven by the policy's `Decision.report`, with a
  self-contained port as a local-availability fallback. Reporting off by default ⇒ no hard dependency.
- **A1 · mainnet-api — TRANSITIVE (via F), only when reporting/checking is enabled.** Reporting targets
  **`MAINNET_BASE_URL` + `/v1/report`** (base URL scheme+host only; the bridge appends the path) in the
  shape (`ip,categories,comment,timestamp` + `sensor_id` + `Key:` header) per
  `funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md` §5.1. **O1** adds a second A1 consumption: the
  BlacklistMirror pulls A1's **G3 thin blacklist artifact** (`GET /v1/blacklist`, `variant=thin`,
  `format=json`, ETag/304) as the fleet-scale fresh-read (Phase 6c). **O2:** D/E hold a mainnet
  **`sensor`-tier key** (report **+** escalation-check rights, metered per-install) — A1 must expose that
  tier; this supersedes the earlier "D/E hold a read-only `service` key" reading.
- **`metrictower/mainnet-client` (F) — TRANSITIVE (via core/policy).** Provides F's `ReputationGate`/
  `Client::check`/`cachedVerdict` (consumed behind the policy's `ReputationInterface`, mirror-first then
  cache via D's `WpCache`/O1 mirror, Phase 6b/6c) + the reporter + the decision-N breaker marker the
  drain/warmer share. Pulled in through the bundled `vendor/`, no direct composer entry. Reputation is
  off/inert by default, so it never blocks D's own phases.
- **funnypot (app)** — the golden-emit parity fixture (Phase 9) and the reporter body-shape parity test
  compare against `funnypot`/`funnypot-core` behavior; a shared pinned rules-artifact version keeps them
  from drifting.
- **E · honeypot-laravel** — sibling, independent; the same thin-adapter-over-`funnypot-policy` pattern
  (both keep only the five §12 responsibilities), no code dependency in either direction. D is the
  reference posture for `REMOTE_ADDR`-by-default IP resolution (D7).

---

## Review resolutions applied (2026-08-19)

- **D1** — Phase 1 `Settings` renamed `mainnet_host`/`mainnetHost()` → **`mainnet_base_url`** /
  **`mainnetBaseUrl()`** (scheme+host only; env constant `HONEYPOT_WP_MAINNET_BASE_URL`), added
  `mainnetKey()`; Phase 6 POSTs to `mainnetBaseUrl() + '/v1/report'` (appends the path itself); Phase 8
  settings sanitizer strips any path from the base URL; Phase 10 README + Definition of done + the
  Orientation reporter-contract and end Dependencies updated to base-URL naming.
- **D2** — Base URL defaults to the **mainnet placeholder host, never AbuseIPDB** (Phase 1); added
  `Settings::reportingActive()` (`report_enabled && key present`) and gated enqueue on it in Phase 5;
  Phase 6 is **inert without `MAINNET_KEY`** with a test asserting empty-key ⇒ nothing sent.
- **D3** — Added **Phase 1b** (`SensorId::resolve`, per-install UUID, test-first) and wired its
  generation/persistence into Phase 8 activation; Phases 6/10/DoD add `sensor_id` to the report body.
- **D7** — Phase 3 `clientIp()` restated as **`REMOTE_ADDR` by default**, trusted-proxy-only XFF, as a
  **v1 requirement** and the reference posture piece E mirrors.
- **M8** — Renamed the bridge class → **`WpReporterBridge`** (Phase 6, Orientation, end Dependencies)
  so it does not shadow core's `Funnypot\Report\MainnetReporter`; fixed the enqueue arg order to
  **`enqueue($ip, $comment, $categories)`** in Phase 5's hand-off and Phase 6, with regression tests in
  both phases (arg order + comment/category not swapped).
- **M15** — Phase 4 no longer "models on `buildConfig` (named args)"; it now **prefers core's
  7.3-callable `Config` factory** (a C task) and otherwise builds **positionally** with an explicit
  1..17 recipe, explicitly passing **`pathScope` (pos 3)** and **`personaBreadth` (pos 5)** and flagging
  silent-misassignment; added a Phase-4 test that reads back every set field. Orientation's `Config`
  and framework-pattern bullets updated to match.
- **Nit** — Risk 1 and the Orientation `Config` bullet trimmed the PHP-8 blocker list to **constructor
  promotion + 7.4 typed props / arrow-fns / `??=`**; removed the overstated named-args and union-types
  claims (C found 0 of each).
- **F — mainnet-client dependency + reputation check/block phases.** Added the transitive
  `metrictower/mainnet-client` dependency (via core) to Orientation and the end Dependencies, with its
  `ReputationGate`/`Cache` contract. Extended **Phase 1 `Settings`** with the reputation keys
  (`check_enabled` default off, `block_threshold=75`, `cache_ttl_hours=24`, `fail_mode=open`) and a
  `checkActive()` helper (key-gated, independent of reporting), plus tests. *(The `block_threshold=75`
  score knob was superseded by the verdict-first re-apply — see the K + re-review + L subsection below.)*
  Added **Phase 6b** —
  `WpCache implements \Funnypot\Mainnet\Cache` (transient/object-cache backend) + `ReputationGateFactory`
  mapping settings → F `Config`, TDD against a fake gate. Extended **Phase 7 `Interceptor`** with step 0:
  consult `decide(REMOTE_ADDR)` when `checkActive()`, emit a plain `403` on `block` ahead of the
  deception flow, fall through on allow/challenge, fail-open/swallow on gate fault — driven by an
  injected fake gate in tests. Added reputation fields to the **Phase 8** admin screen + sanitizer, a
  **Phase 9** integration case (stub `/v1/check`: block ⇒ 403, allow ⇒ pass, `429`/timeout ⇒ fail-open),
  and a Definition-of-done line. Reputation is off by default and inert without enable+key, so the
  existing engine/deception phases and the C hard-dependency are unchanged.

### K + re-review + L (2026-08-19)

- **Program envelope convention.** Every `/v1` response is a top-level `{ "data": ... }` envelope
  (blacklist keeps `{ "meta": {...}, "data": [...] }`), native snake_case field names only, **no**
  AbuseIPDB parity names. D reads none of these wires directly — it consumes F's `ReputationGate` /
  `CheckResult`, which already speak the native verdict-first model — so this is an inherited invariant,
  noted for the Phase 6/9 stub `/v1/report` + `/v1/check` bodies (native snake_case, `data`-wrapped).
- **Re-review #2 — verdict-first reputation gate (re-applied).** Replaced the **deleted** score
  `block_threshold` / `blockThreshold()` everywhere in the plan with the verdict-first **`block_verdicts`**
  (default `['malicious','critical']`) + optional **`min_block_score`** (default `null`), matching F's
  `ReputationGate` `Config`. Touched: the Orientation reputation-gate contract; Phase 1 `Settings` getters
  (`blockVerdicts()` + `minBlockScore()`, no `blockThreshold()`) and its test; Phase 6b
  `ReputationGateFactory` mapping (`block_verdicts` + `min_block_score` into F's `Config`) and the Config
  read-back test (asserts `block_verdicts` reads back and **no** `block_threshold` key exists); Phase 8
  admin fields (a `block_verdicts` multi-select + optional `min_block_score` floor) and the sanitize test
  (whitelist verdict enum, coerce `min_block_score` to int|null). `cache_ttl_hours` stays `24` for the WP
  host by design (F/E default 12; deliberate divergence).
- **Re-review #6 — reporter rebind (mainnet-client, not core).** Rewrote **Phase 6** to bind
  `WpdbReportQueue implements \Funnypot\Mainnet\Report\ReportQueue` and compose `Funnypot\Mainnet\Reporter`
  (in `metrictower/mainnet-client`, transitive via core), dropping the "if B has landed / core ships
  `Funnypot\Report\*`" fork — F's reporter is always present transitively. The only remaining variance is
  a **packaging** fallback (self-contained port behind the identical `Funnypot\Mainnet\*` interfaces if the
  package is not yet resolvable locally), not a B/core fork. Updated Risk 2, Key-decision 4, and the
  end-Dependencies B bullet to match (B demoted from a soft prerequisite to "provided by F via core"); all
  `Funnypot\Report\*` FQCNs dropped from the plan.
- **L6 — consumer decision overlay (reserved).** No plan phase (reserved, not built in v1); the overlay
  lives in the design (§4.9 + the §5 reserved settings sub-shape). Its v1 seeds already in this plan are
  `min_block_score` (the verdict-floor knob) and the `honeypot_wp/reputation_decision` filter (the escape
  hatch the structured overlay later formalizes).

**Ambiguity note:** the decisions doc's D3 client-UUID field is named `sensor_id` for the wire body; D
persists it in a dedicated `honeypot_wp_sensor_id` WP option (not folded into `honeypot_wp_settings`)
to keep it out of the operator-editable settings blob — implementing D3's stated intent (generate +
persist + send) without inventing new scope.

### M re-point onto `funnypot-policy` (2026-08-19)

Decision **M** re-points D onto the shared `funnypot-policy` package via a thin adapter (per the design's
M changelog). The plan phases were re-purposed to build only the five §12 adapter responsibilities, each
TDD'd against a **fake `PolicyEngine`**; D's deception/engine scope and the C hard-dependency are kept.
Phase-by-phase:

- **Orientation** — the consumed API is now `funnypot-policy`'s (`PolicyEngine::evaluate`, the five
  ports, `Decision`/`RequestEvidence`/`SiteProfile`, `PolicyConfig::fromArray`); core is consumed
  transitively behind `EvaluatorInterface` (no `respond()`/`detect()`); path repos now include
  `../funnypot-policy` + `../mainnet-client`.
- **Phase 0** — composer requires `metrictower/funnypot-policy` (transitively pulls core + mainnet-client).
- **Phase 1 `Settings`** — adds **`toPolicyConfig(position)`** rendering the §8 policy array (posture/
  position/actions/learn/suppression/allowlist/self_ips/reputation) plus the retained STYLE/engine knobs;
  reputation getters now back the policy config block, not a gate.
- **Phase 2** — `SurfaceAllowlist::isReserved` → **`WpSiteProfile`** (`routeExists` + `isSacrificialPath`
  + an injected `is_404` seam).
- **Phase 3** — `RequestFactory` builds `RequestEvidence` (body-shape only, OAST hygiene) instead of
  core's `RequestContext`; `clientIp` (D7) unchanged, now the actor id.
- **Phase 4** — `EngineFactory` (called `respond()`) → **`EvaluatorConfig`** (STYLE/engine → core `Config`
  behind the evaluator; M15 positional recipe moved here; gate/probeSignature/killSwitch closures dropped).
- **Phase 4b (new)** — **`WpStateStore implements StateStoreInterface`** (pins/TTL, rule state,
  suppression ledger, counters — storage mapping only).
- **Phase 5** — `HitObserver` (core `Observer`) → **`DecisionExecutor`** (perform each `Decision.action`
  + pin/report side-channels; app-chosen status).
- **Phase 6** — `WpReporterBridge` gains **`enqueueIntent(ReportIntent)`**, driven by `Decision.report`;
  the 4-layer suppression is the policy's, the transport guards a backstop.
- **Phase 6b** — drops `ReputationGateFactory`; keeps **`WpCache`** only (reputation is policy config,
  wired in Phase 7).
- **Phase 7** — adds **`PolicyFactory::forPosition`** (wire the five ports + config) and rewrites
  `Interceptor` to **`runBefore`/`runFallback`** → normalize → `evaluate()` → execute, position-gated,
  degrade-safe (fail to `allow`, never 500).
- **Phase 8** — two position hooks; the admin screen now produces the **policy config array** (posture/
  position/actions/learn-then-enforce controls/suppression/reputation); CLI adds `promote`/`shadow`;
  DDL adds the `WpStateStore` sidecar.
- **Phase 9** — integration cases reframed to FALLBACK-deceive + BEFORE-reputation-block (posture-driven).
- **Phase 10** — bundle policy + core + mainnet-client.
- **Risks / DoD / Key decisions / Dependencies** — restated: C now also owes the M2 split; funnypot-policy
  added as the primary dependency (Risk 1b); reputation is policy config; the BEFORE-position
  `routeExists` limitation is Risk 4 (was the live-post seam).

### N/O + future-proofing (2026-08-19)

Applies decisions **N**/**O** and the future-proofing-review items scoped to D (**SF-4, SF-6, O1, O2,
RS-10**, runtime position self-check / Wordfence gap a), tracking the design's matching changelog.

- **Phase 1 `Settings`** — new getters/defaults: `localStateBackend()` (`object-cache|file`, default
  `object-cache`, RS-10), `mirrorEnabled()`/`mirrorPullIntervalSecs()` (O1), the SF-6 drain bounds
  (`drainBudgetSecs=10`, `drainMaxAttempts`/`drainMaxAgeSecs`, `queueCap`); the `mainnet_key` docblock
  states it is a `sensor`-tier key (O2). Test asserts the new defaults + enum whitelists.
- **Phase 4b `WpStateStore`** — RS-10 selectable backend (a `StateBackend` seam, default `object-cache`,
  no plugin-dir write) + the O1 mirror methods (`putMirror`/`mirrorVerdict`/`mirrorMeta`); the port
  round-trips under both backends.
- **Phase 6 `WpReporterBridge`** — SF-6 outage-bounded drain: wall-clock budget, 3-fail early abort
  writing the shared decision-N `mnc:breaker` marker, 429-class branch (`duplicate_report` drop /
  `quota_exhausted` park), re-queue + `queue_cap` caps; tests added against a fake clock + stub transport.
- **Phase 6c (new)** — `BlacklistMirror` (O1 conditional thin-artifact pull, breaker-guarded, inert by
  default) + `Warmer` (SF-6 out-of-band reputation warmer, breaker-guarded, bounded per tick); the
  request-path read becomes mirror-first → cache → fail-open, off-mirror uncached IPs are warmed, never
  checked inline (M5).
- **Phase 7 `Interceptor`** — step 0 records which BEFORE hook fired + a pure `mountState()` mapper for
  the runtime position self-check; `PolicyFactory` injects the mirror/warmer seams into the reputation
  adapter when `checkActive()`.
- **Phase 8** — the mu-shim is degrade-safe (SF-4: `file_exists` guard, versioned entry + guarded static,
  self-heal/self-remove; pure `shimBody`/`isStale` unit-tested); `status` reports the verified mount +
  mirror age; a `Notices` admin notice on degraded position; CLI `mirror-pull`; Cron gains the warmer +
  mirror hooks with the WP-Cron caveat + real-cron recommendation; DDL adds the mirror + warmer-queue
  rows.
- **Phase 9** — new integration cases: SF-4 shim-takedown (plugin dir removed → site serves), O1
  mirror-first block with zero `/v1/check` calls, and the degraded-mount status/notice.
- **Risks / DoD / Dependencies** — Risk 3 notes SF-4 closes the stale-shim takedown vector; DoD lines for
  SF-4/SF-6/N/O1/O2/RS-10/position-self-check; the A1 + mainnet-client dependency bullets add the O1
  artifact consumption, the O2 `sensor` tier, and the shared decision-N marker.

### P/Q/R entity+geo (2026-08-19)

Applies decisions **P** (IPv6 hardening), **Q** (range/CIDR/ASN reputation — block ranges, not many IPs),
and **R** (country policy via LOCAL GeoIP) as scoped to D, tracking the design's matching changelog.
Everything not implicated (N/O + future-proofing, the M re-point, K/re-review/L) is preserved.

- **P2/Q2 (inherited) — range/ASN mirror rows matched by containment.** **Phase 6c** `BlacklistMirror`
  now records that a thin row's `ip` may be a **CIDR** (IPv4 `/24`, IPv6 `/64` per P2) or an **ASN** (per
  Q2); the request-path match is by **CIDR-containment / ASN-lookup — the matcher is `funnypot-policy`'s**
  (consumed via the `ReputationInterface` / mirror-lookup seam), never reimplemented in D; the client
  normalises an IPv6 to its `/64` `score_key` before lookup. No new D build — D stores + passes the range
  rows through faithfully.
- **R (country policy) — Settings + `WpGeoIp` + refresh cron.** **Phase 1 `Settings`** gains the `country`
  knobs (`country_posture` `off|deny_list|allow_list` default `off`, `country_list` alpha-2[],
  `country_action` `block|deceive|score-modifier` default `score-modifier` — R3) rendered into the §8
  policy `country` block by `toPolicyConfig` (inert when `off`), plus the D-local
  `geoip_refresh_interval_secs` (default monthly); its test asserts the defaults/enums. New **Phase 4c**
  `WpGeoIp implements \Funnypot\Policy\Port\GeoIpInterface` — the local GeoIP resolver (**DB-IP Lite**,
  never a network call, IPv4 + IPv6, null on miss/absent-DB → fail-open). **Phase 6c** adds
  `src/Geo/GeoIpRefresh` (a conditional cron pull of the local DB, riding the same data-distribution seam
  as the O1 mirror, inert unless country policy is on, fail-open). **Phase 7 `PolicyFactory`** injects the
  **optional sixth** `GeoIpInterface` port only when `countryPosture() !== 'off'`; its test asserts the
  port is absent by default. **Phase 8** adds the admin country fields + sanitizer whitelisting, the
  `geoip-refresh` CLI command, and the GeoIP-refresh cron (default monthly). **Phase 9** adds a
  country-policy integration case (deny-listed country → configured action, unlisted → falls through, zero
  network calls, missing DB → inert/fail-open). **Phase 10** bundles/references the local GeoIP DB as a
  refreshed-in-place asset. D authors no country *decision* logic — the gate is the policy's (M5).
