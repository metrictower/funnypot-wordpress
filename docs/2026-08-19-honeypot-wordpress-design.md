# honeypot-wordpress · D — design spec

**Status:** draft for review · **Date:** 2026-08-19 · **Piece:** D of the funnypot-mainnet program
**Depends on:** **C** (funnypot-core lowered to PHP 7.3) — HARD prerequisite, see §9.
**Consumes (primary):** `metrictower/funnypot-policy` (the position-blind **decision engine** — decision
M; [`funnypot-policy/docs/2026-08-19-funnypot-policy-design.md`](../../funnypot-policy/docs/2026-08-19-funnypot-policy-design.md)).
D is a **thin WordPress adapter** over it: request normalization, `Decision` execution, a WP
`StateStoreInterface`, hook placement, and the admin UI that produces the policy config array.
**Consumes (transitive, via funnypot-policy):** `metrictower/funnypot-core` (the two-phase
`classify()`+`synthesize()` deception engine — M2, held behind the policy's `EvaluatorInterface`) ·
`metrictower/mainnet-client` (the mainnet client library — F's `ReputationGate`/`Client::check` behind
the policy's `ReputationInterface`, plus the relocated `Funnypot\Mainnet\Reporter` (née piece B)). The
optional reporter is provided by F; the reputation-block feature is now a **policy action/config**, not
bespoke D logic (decision M).

---

## 1. What this is

A WordPress plugin that embeds the funnypot deception stack as a **thin WordPress adapter over
`metrictower/funnypot-policy`** (decision M). The plugin does **not** itself decide whether a request
is an attack, whether to deceive, whether to block, or whether to report — that is the shared policy
engine's job. D **normalizes** the incoming WP request into a neutral `RequestEvidence` + a
`SiteProfile` (declared stack `wordpress` + a real-route oracle), asks
`Funnypot\Policy\PolicyEngine::evaluate()` for a `Decision`, and **executes** that `Decision`:
`allow`/`log` → WordPress proceeds (optionally observed); `deceive` → emit core's byte-exact fake
(correct `Content-Type` + app-chosen status) and exit before WordPress loads a theme; `block` → emit an
honest app-chosen `403`. The **deception content is unchanged** — the same inert, byte-exact fakes
core's `synthesize()` renders, matching the standalone funnypot app — but the *when / whether / where*
now lives **once** in the shared package (the cheapest-first precedence, learn-then-enforce, pin/TTL,
report suppression), not in bespoke plugin logic.

WordPress is one of the most heavily scanned surfaces on the public web — probes for `/.env`,
`/wp-config.php.bak`, `/.git/config`, `xmlrpc.php`, `/wp-content/debug.log`, and thousands of plugin
CVE paths arrive constantly. The plugin runs the policy engine at up to **two positions** (M4): a
**BEFORE-position** middleware at the earliest safe WP hook and a **FALLBACK-position** 404 hook —
which run is a config/posture choice (honeypot / WAF / both, §8). On an `allow`/`log` outcome WordPress
proceeds normally, so real visitors and real admin traffic are untouched. An admin settings screen
produces the **policy config array** (§8) and drives the learn-then-enforce promotion controls; F's
optional reputation-check + reporting are folded into that config. funnypot-policy and its transitive
funnypot-core / mainnet-client are Composer-loaded from a `vendor/` bundled inside the plugin.

## 2. Scope

### v1 (this spec)

- Two **position** hooks driving one `PolicyEngine::evaluate()` call each (M4): a **BEFORE-position**
  middleware at the earliest safe WP hook (`muplugins_loaded` via a bundled must-use loader shim;
  `plugins_loaded` when installed as an ordinary plugin) and a **FALLBACK-position** 404 hook
  (`template_redirect` when `is_404()`). The posture/config selects which run (§3, §4.1, §8).
- **Request normalization** — `RequestFactory` builds the neutral `RequestEvidence`
  (method/path/query/headers/body-shape, proxy-aware IP per D7) and a **`WpSiteProfile`**
  (`Funnypot\Policy\SiteProfile`: stack `wordpress`, a `routeExists` oracle over the genuine-WP-surface
  set + `is_404()`/live-post resolution, and an `isSacrificialPath` set — `.env`, `.git/config`,
  `xmlrpc.php`/`wp-login.php` on an operator-disabled feature) so a fake never collides with a real WP
  route (§4.2, §4.4). This is the one job only the host can do — only WordPress knows its own routes.
- **`Decision` execution** — `allow`/`log` → WordPress proceeds (+ optional hit-log observe); `deceive`
  → emit the `Decision.fakeHandle` (core's `synthesize()` fake) via `ResponseEmitter`; `block` → emit an
  honest app-chosen `403`. The status is taken from the `Decision`, never invented (§4.5, §6.3).
- A **`WpStateStore implements \Funnypot\Policy\Port\StateStoreInterface`** over WP options / transients
  / the persistent object cache — deception-consistency pins + TTL, learn-then-enforce per-rule state,
  the suppression ledger, and per-actor counters (§4.6, §5). The one persistence seam the policy engine
  reads/writes through.
- An **admin settings screen** (Settings → Honeypot) that produces the §8 **policy config array**
  (posture `honeypot|WAF|both`, position, per-band actions on real routes, reputation, learn-then-
  enforce controls, pin TTL, suppression, allowlist/`self_ips`) **plus** the STYLE/engine knobs
  (response style, severity ceiling, attack-emulation, nuclei-reflection, catalog excludes) that feed
  core's `synthesize()` through the policy's evaluator (§4.3, §4.7, §5).
- **Optional** IP-reputation **check + block**, now a **policy config knob** (`reputation.enabled` +
  `block_verdicts`), consumed cache-first behind the policy's `ReputationInterface` (never a synchronous
  network call on the request path, M5) — off by default, key-gated, fail-open. D contributes only the
  WP cache backing F's verdict cache (`WpCache`); the block itself is a `Decision.action` the adapter
  executes, not a bespoke interceptor step (§4.8, §9).
- **Optional** report-to-mainnet: the policy emits a suppression-vetted `Decision.report`
  (`ReportIntent`); `WpReporterBridge` enqueues it and a cron tick drains it to mainnet `/v1/report`
  via the relocated mainnet-client reporter `Funnypot\Mainnet\Reporter` (decision F, née piece B). The
  4-layer suppression is the policy's, not D's; the drain is **outage-bounded** (per-tick budget, 3-fail
  abort writing the shared decision-N marker, 429-class branch, re-queue + queue caps — SF-6/N) (§4.9,
  §9).
- **Optional** O1 **local-mirror-lite**: a cron `BlacklistMirror` pulls A1's thin blacklist artifact
  (ETag/304) into `WpStateStore` as the **PRIMARY request-path fresh-read**, with per-IP `check` demoted
  to an out-of-band **warmer** for uncertain (off-mirror) IPs — never a synchronous request-path check
  (§4.8, §4.13). Off by default, `sensor`-key-gated.
- A **selectable local-state backend** (`object-cache|file`, RS-10) whose default works where the
  plugin dir is not writable (§4.6, §5).
- WP-CLI commands: `wp honeypot status|enable|disable|test|catalog|report-drain|mirror-pull|promote|
  shadow` — `status` reporting the **verified BEFORE mount** (Wordfence gap a) (§4.10).
- A per-install `sensor_id` UUID for report identity (§4.11, D3); D/E hold a `sensor`-tier mainnet key
  (report + escalation-check, O2, §4.8/§9).
- Bundled `vendor/metrictower/funnypot-policy` + transitive `funnypot-core` / `mainnet-client`
  (Composer-installed at build time), plus core's runtime rules artifacts (§5, §9).

### Non-goals (fast-follow / later)

- **Any policy logic in the plugin.** D never reimplements the cheapest-first precedence, the
  two-axis (actor × request) combination, the learn-then-enforce state machine, pin/TTL, or the report
  suppression — all of that lives once in `funnypot-policy` (M3). An adapter that reimplements any of it
  is a bug (policy design §12). D contributes only the five thin-adapter responsibilities of §2.
- **wordpress.org plugin-directory distribution** and the SVN release flow → fast-follow. v1 ships as
  a downloadable zip and a Composer package (`metrictower/honeypot-wordpress`).
- **Multisite network-admin** UI (per-network settings, network activation) → fast-follow; v1 works
  per-site.
- **Runtime signed rule-update** from inside WP (`funnypot rules:update`) → fast-follow; v1 ships the
  rules bundled with core and updates them on plugin update. The RCE-adjacent verified-update path
  (§6) is deliberately not exposed to the WP admin in v1.
- **Gutenberg/block or dashboard-widget analytics** → fast-follow; v1's admin screen is settings +
  a plain recent-hits table.
- **The pure-PHP SSH / TCP protocol emulators** from the funnypot *app* — out of scope; this plugin
  is HTTP-only (WordPress is an HTTP app).
- **LLM fake upgrade** (tiers 3–4) — app-layer only, not in core, not in this plugin.

## 3. Architecture

Stack: PHP 7.3+ (WordPress hosts commonly run PHP 7.x — this is why C is a prerequisite), WordPress
5.x/6.x, no framework beyond WP itself. Runs in-process inside the WP PHP worker (php-fpm / mod_php).
Pure PHP: funnypot-policy + core need no extensions, no DB, no network at request time (reputation is
cache-first, M5).

The plugin is a **thin adapter** (policy design §12): it normalizes the request, calls the shared
`PolicyEngine`, and executes the returned `Decision`. All of the *decision* logic — the cheapest-first
precedence, the two-axis combination, learn-then-enforce, pin/TTL, suppression — is inside
`funnypot-policy` and is never duplicated here.

```
        incoming HTTP request (Apache/nginx → php-fpm → WordPress)
                     │
   ┌─────────────────┴──────────────────────────────────────────────────┐
   │ BEFORE position (config)          │ FALLBACK position (config)       │
   │ mu-plugins/honeypot-wp-loader.php │ template_redirect when is_404()  │
   │ → Interceptor::runBefore()        │ → Interceptor::runFallback()     │
   └─────────────────┬──────────────────────────────────────────────────┘
                     ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ Interceptor (per position)                                    │
   │  1. master switch off?  → return, WP proceeds                 │
   │  2. RequestFactory → RequestEvidence + WpSiteProfile          │
   │       (proxy-aware IP, method/path/query/headers/body-shape;  │
   │        routeExists oracle; isSacrificialPath)                 │
   │  3. $engine = PolicyFactory::forPosition(BEFORE|FALLBACK)     │
   │       (injects: core-backed Evaluator, mainnet Reputation,    │
   │        WpStateStore, WpClock, WpLogger, PolicyConfig)         │
   │  4. $decision = $engine->evaluate($evidence)                  │
   │  5. execute $decision:                                        │
   │        allow / log  → return, WP proceeds (+ hit-log observe) │
   │        deceive      → ResponseEmitter::emit(fakeHandle); exit │
   │        block        → emit honest app-chosen 403;         exit│
   │       (wrapped in try/catch: any fault → allow, never a 500)  │
   │        + if $decision->report(): WpReporterBridge::enqueue()  │
   │        + if $decision->pinTtl(): WpStateStore::setPin()       │
   └──────────────────────────────────────────────────────────────┘
                     │
                     ▼
   HitLog table  +  suppression-vetted Reporter enqueue → WP-Cron drain → mainnet /v1/report
```

The **BEFORE** hook sits *in front of* WordPress routing (so a scanner probe or a known-bad actor is
handled before WP or the theme run); the **FALLBACK** hook fires only when WP itself resolved a genuine
404 (the classic honeypot 404-upgrade, FP-free by construction — the request already had no real
route). Which position(s) run is the operator's posture/config choice (§8): `honeypot` = FALLBACK only,
`WAF` = BEFORE only, `both` = BEFORE **and** FALLBACK. The `WpSiteProfile.routeExists` oracle is what
keeps deception from ever colliding with a real WP endpoint; the policy engine's own precedence keeps
ordinary WP traffic falling straight through as `allow`.

## 4. The concrete surface

Namespace `Honeypot\WP\` (PSR-4, `src/`). Text domain `honeypot-wp`. Option key
`honeypot_wp_settings`.

### 4.1 Bootstrap + hook wiring (two positions)

`honeypot-wordpress.php` (plugin main file, carries the WP plugin header) registers **up to two
position hooks** per the config (§8) — a BEFORE-position middleware and a FALLBACK-position 404 hook:

```php
// registers activation/deactivation, admin menu, WP-CLI, and the two position hooks.
add_action('muplugins_loaded', ['Honeypot\WP\Interceptor', 'runBefore'], 0);    // BEFORE (mu-plugin)
add_action('plugins_loaded',   ['Honeypot\WP\Interceptor', 'runBefore'], 0);    // BEFORE (ordinary-plugin fallback)
add_action('template_redirect',['Honeypot\WP\Interceptor', 'runFallback'], 0);  // FALLBACK (fires when is_404())
```

Both entry points are **idempotent** (each guards a static `$ran` flag) so the double BEFORE
registration fires its body exactly once regardless of which hook wins, and `runFallback` never
double-runs against `runBefore`. Each entry checks the config: `runBefore` returns immediately unless
`position.before` is set for the active posture; `runFallback` returns immediately unless
`position.fallback` is set **and** `is_404()` is true (the FALLBACK position only ever upgrades a
genuine 404 — FP-free by construction, §6.2).

`register_activation_hook()` copies a tiny loader shim into `wp-content/mu-plugins/` so the BEFORE
position runs at `muplugins_loaded` — the earliest hook that still has the plugin API and `$_SERVER`
available, before themes, `init`, and the main query. If the mu-plugins dir is not writable, the plugin
logs an admin notice and falls back to the `plugins_loaded` registration (still before
`template_redirect`, still before theme output). Deactivation removes the shim. The FALLBACK hook needs
no shim — `template_redirect` is a standard theme-time hook and `is_404()` is resolved by then.

**The shim is degrade-safe by construction (SF-4).** mu-plugins load unconditionally on **every**
request and cannot be deactivated from wp-admin — so a shim that `require`s a now-missing plugin
bootstrap would fatal every request, wp-admin included: the one path in the design where the WAF could
take down the site it protects. The shim therefore:

- **Never fatals on a missing bootstrap.** Its body is guarded — `if (!file_exists($bootstrap)) {
  return; }` — so a plugin folder deleted/renamed **without** deactivation (FTP cleanup, a failed
  auto-update, a host restore, `wp-cli` on a broken install) leaves the shim silently inert, not fatal.
- **Tolerates shim/plugin version skew.** The shim never inlines plugin logic or hard-codes an
  internal symbol; it `require`s one **stable, versioned entry file** (`mu-entry.php`) and calls a
  single **guarded static** (`Honeypot\WP\MuEntry::boot()` wrapped in `function_exists`/`class_exists`
  + a `try/catch`), so an old shim against a newer plugin (or the reverse) degrades to inert rather
  than fataling on a renamed/removed method.
- **Self-heals and self-removes.** On a normal load the plugin **rewrites the shim if it is stale or
  missing** (self-heal, so a manual delete or a skewed copy is repaired); the shim **no-ops / removes
  itself** when it detects the plugin is gone (bootstrap absent) so a stale copy left by an out-of-band
  removal does not linger. Both are best-effort and never fatal if the dir is unwritable.

**Runtime position self-check (Wordfence gap a).** Install-time degradation (dir not writable →
`plugins_loaded` fallback) is only half the story: a shim wiped **after** install silently demotes the
BEFORE position with no operator signal, and printing the *configured* posture would then lie. The
plugin therefore records **which hook actually fired** (a static set on first entry of `runBefore` —
`muplugins_loaded` vs `plugins_loaded` — persisted to a short-TTL transient), and derives a
**mounted-at state**: `mu-plugin` (running at the earliest hook), `plugins_loaded (degraded)` (the
mu-shim is absent/inert so BEFORE fell back), or `not running` (neither hook fired within the observed
window while a BEFORE posture is configured). This verified mount — not the configured intent — is what
`wp honeypot status` reports (§4.10) and what drives an **admin notice** when the effective position is
degraded below the configured one.

```php
namespace Honeypot\WP;

final class Interceptor
{
    /** BEFORE position: normalize, evaluate the policy, execute the Decision, emit-and-exit on block/deceive. */
    public static function runBefore(): void;                 // hooked at priority 0

    /** FALLBACK position: only when is_404(); upgrade the genuine 404 per the Decision (typically deceive). */
    public static function runFallback(): void;               // hooked at priority 0
}
```

The shared body (build `RequestEvidence` + `WpSiteProfile`, call `PolicyEngine::evaluate()`, execute
the `Decision`) is factored into one private method both entry points call with their position; the
`PolicyFactory` (§4.3) is handed the position so the config's per-position action ceilings apply.

### 4.2 `WpSiteProfile` — declared stack + real-route oracle

The old "genuine-WP-surface allowlist" is now expressed as the policy's **`SiteProfile`** (policy
design §2.6) — the single most important FP-safety input, because it is what stops a fake from ever
colliding with a real WP route. D builds a `WpSiteProfile` that satisfies `Funnypot\Policy\SiteProfile`:

```php
namespace Honeypot\WP;

final class WpSiteProfile   // implements the shape core/policy expect for \Funnypot\Policy\SiteProfile
{
    /** Declared stack — always 'wordpress' here; drives which paths are sacrificial. */
    public function stack(): string;                          // 'wordpress'

    /** Does this path resolve to a route that actually EXISTS on this site? (the FP-safety oracle) */
    public function routeExists(string $path): bool;

    /** Provably-nonexistent paths for a WP site (counterfactual is a 404) — the §6 day-1 carve-out set. */
    public function isSacrificialPath(string $path): bool;
}
```

- **`routeExists`** is the genuine-WP-surface check. It returns true for the static reserved set —
  `/`, `/wp-login.php`, `/wp-cron.php`, `/wp-comments-post.php`, `/xmlrpc.php`, `/wp-admin/*`,
  `/wp-json/*`, `/wp-content/uploads/*` — **and**, at the FALLBACK position where the main query has
  run, for any path WP resolved to a real published post/page (`is_404()` is false ⇒ the route exists).
  At the BEFORE position the main query has not run yet, so `routeExists` covers the static-prefix set
  only; the policy's precedence + matched-only classify keep a real content path from being deceived
  there (open decision, §8). `xmlrpc.php` / `wp-login.php` count as **non**-existent (sacrificial)
  **only** when the operator has both disabled the corresponding real WP feature and opted the decoy in
  via the catalog — otherwise emitting a decoy would break pingbacks / a live login, so they stay
  real-route by default.
- **`isSacrificialPath`** is the day-1 carve-out set for a WP site: `.env`, `.git/config`,
  `/wp-config.php.bak`, `/wp-content/debug.log`, and the CVE-probe paths that provably don't exist on a
  stock install. The policy auto-enforces deception on these on install day (counterfactual is a 404,
  FP cost zero — policy §6/§7); D only supplies the set, it does not decide to deceive.

This replaces the plugin's bespoke `SurfaceAllowlist::isReserved` safety layer: the same knowledge
(which WP paths are real, which are always-fake) is now the `SiteProfile` **data** the position-blind
engine consumes, and the *decision* it drives lives in the policy.

### 4.3 `PolicyFactory` — build + wire the `PolicyEngine`

```php
final class PolicyFactory
{
    /**
     * Build the shared PolicyEngine for a position, injecting all five ports + the config array.
     * @param string $position 'before' | 'fallback'
     */
    public static function forPosition(Settings $s, string $position): \Funnypot\Policy\PolicyEngine;
}
```

`PolicyFactory` is the plugin's one wiring point. It reads the stored settings, builds the §8
`PolicyConfig` array via `\Funnypot\Policy\PolicyConfig::fromArray($s->toPolicyConfig($position))`, and
constructs the `PolicyEngine` with the five injected ports:

| Port (`Funnypot\Policy\Port\*`) | D's adapter | Notes |
|---|---|---|
| `EvaluatorInterface` | the **core-backed evaluator** wired from bundled funnypot-core (§4.7) | holds `classify()`+`synthesize()`; carries the STYLE/engine config |
| `ReputationInterface` | the **mainnet reputation adapter** over F's `ReputationGate`, cache-first via `WpCache` (§4.8) | inert unless enabled+keyed; never a sync request-path call (M5) |
| `StateStoreInterface` | `WpStateStore` (§4.6) | WP options/transients/object-cache |
| `Clock` | `WpClock` (thin `time()` wrapper) | injected for deterministic tests |
| `Logger` | `WpLogger` (writes to the hit log / `error_log`; never a signature string, §6.1) | `NullLogger` when logging off |
| `GeoIpInterface` (optional, R) | `WpGeoIp` (§4.14) — local GeoIP DB, never a network call | an **optional sixth port**, wired only when country policy is enabled |

D does **not** author any of the decision logic — `PolicyFactory` only *assembles* the engine from
ports and hands it the config array. The posture / position / per-band action ceilings all come from
the config the admin screen produced (§5, §8); a code change is never needed to switch honeypot ⇄ WAF
or before ⇄ fallback (M4). The core-backed evaluator that satisfies `EvaluatorInterface` — the seam
that carries the STYLE/engine knobs and the M15 positional-`Config` concern — is described in §4.7; the
optional country gate's `WpGeoIp` port (decision R) is described in §4.14.

### 4.4 Request + client-IP resolution → `RequestEvidence`

```php
final class RequestFactory
{
    /** Build the policy's neutral RequestEvidence from $_SERVER, proxy-aware, no raw-body reflection. */
    public static function evidence(array $server, ?string $rawBody, Settings $s): \Funnypot\Policy\RequestEvidence;

    /** Coarsened real client IP (respecting configured trusted proxies) — the actor id for the policy. */
    public static function clientIp(array $server, Settings $s): string;
}
```

D produces the policy's neutral **`RequestEvidence`** (method / path / query / headers / body-shape —
never the raw body, OAST hygiene §4.9/policy §9) rather than core's `RequestContext` (which the
evaluator builds internally, §4.7). The resolved client IP becomes the policy's **actor id** — it
seeds deception (`sha1(actorId + siteSalt)` inside `synthesize()`, policy §2.7), keys the pin, keys
reputation, and is what a report carries.

The client IP defaults to **`REMOTE_ADDR`** (the socket peer); `X-Forwarded-For` is consulted **only**
when the peer is inside an operator-configured trusted-proxy CIDR — never the spoofable raw header.
This is a **v1 requirement, not a fast-follow** (untrusted XFF = spoofable third-party report
poisoning and persona enumeration), and it is the reference posture the Laravel piece (E) mirrors:
`REMOTE_ADDR` by default, trusted-proxy XFF only. Filters `honeypot_wp/trusted_proxies` and
`honeypot_wp/request_evidence` let advanced operators override the proxy set / post-process the
evidence.

### 4.5 `Decision` execution + hit log

The one place D turns the policy's pure-data `Decision` into a WordPress effect (policy §12 point 2).
There is no `\Funnypot\Observer` implementation any more — observation is the `log` action + the
`Logger` port, and the decision to report is the `Decision.report` intent (§4.9), both owned by the
policy.

```php
final class DecisionExecutor
{
    /** Perform the effect of a Decision at the given position; returns true iff it emitted+halted. */
    public function execute(\Funnypot\Policy\Decision $d, \Funnypot\Policy\RequestEvidence $e): bool;
}
```

`execute()` switches on `Decision.action()`:

- **`allow`** → return false; WordPress proceeds untouched.
- **`log`** → write a hit-log row and return false; WordPress proceeds (this is the SHADOW-phase and
  below-block output — no visible effect on the response).
- **`deceive`** → emit `Decision.fakeHandle()` (core's `synthesize()` `FakeResponse`) via
  `\Funnypot\Http\ResponseEmitter::emit()` with the **app-chosen** `Decision.status()`, then halt
  (`exit`). This is the only path that emits bytes an attacker sees.
- **`block`** → emit an honest `403` (or `Decision.status()` if the config set another) with no
  honeypot body, then halt. A `block` is only ever produced in a protect-mode posture (WAF / BEFORE).

After the action, `execute()` also honors the side-channel fields on the `Decision`: if
`Decision.pinTtl()` is set it calls `WpStateStore::setPin()` (deception-consistency, §4.6); if
`Decision.report()` returns a `ReportIntent` it hands it to `WpReporterBridge::enqueue()` (§4.9). The
whole `execute()` call sits inside the interceptor's `try/catch` so any fault degrades to `allow`,
never a 500 (§6.2).

**Status is taken from the `Decision`, never invented** (invariant §6.3) — no model-driven 3xx, no
open redirect. The hit-log row (`{$wpdb->prefix}honeypot_wp_hits`: ts, ip, method, path, action,
`Decision.reason()`, matched signal handle, severity) is written on `log`/`deceive`/`block`; the
matched signal is the policy's **opaque handle**, never a canonical signature string (§6.1).

### 4.6 `WpStateStore` — the persistence seam

D's `StateStoreInterface` implementation (policy §2.3) — the **only** place the policy engine touches
storage. It backs onto WP options + transients (which ride the persistent object cache when the host
has one) and, for the larger ledgers, the plugin's own `$wpdb` tables:

```php
final class WpStateStore   // implements \Funnypot\Policy\Port\StateStoreInterface
{
    // deception-consistency pins + local blocklist (transient-backed, TTL = pinTtl)
    public function getPin(string $ip);
    public function setPin(string $ip, string $action, string $seed, int $ttlSeconds);
    public function isBlocked(string $ip): bool;

    // learn-then-enforce per-rule state (option-backed; small, rarely written)
    public function ruleState(string $ruleId);
    public function putRuleState(string $ruleId, $s);
    public function bumpRuleEvaluated(string $ruleId, int $n = 1);

    // suppression ledger + per-actor counters (transient/$wpdb-backed)
    public function seenVerdict(string $dedupKey, int $ttlSeconds): bool;
    public function incrAlertCount(string $ip, int $windowSeconds): int;
    public function bufferReport(string $groupKey, array $report, int $ttlSeconds): int;
    public function takeReportBuffer(): array;
    public function aggregateScore(string $scoreKey, int $windowDays);
    public function actorFacts(string $ip);
    public function incr(string $counterKey, int $windowSeconds): int;

    // local-mirror-lite (O1): the cron-pulled thin blacklist artifact as the PRIMARY fresh-read
    public function mirrorVerdict(string $scoreKey);          // {verdict, expires_at} or null (not on the mirror)
    public function putMirror(array $rows, string $etag, int $generatedAt, int $ttlSeconds): void;
    public function mirrorMeta();                             // {etag, generated_at, count} for the conditional pull
}
```

D writes **none** of the pin/TTL, learn-then-enforce, or suppression *logic* — the policy engine does
all of that through this port. D only maps each method to a WP storage primitive (a namespaced
transient key, a `$wpdb->prepare`d row, an autoloaded option). Pins and counters are short-TTL
transients; the learn-then-enforce rule state is a small autoloaded option; the aggregate/dedup ledger
uses a bounded `$wpdb` sidecar pruned by the cron sweep (§5). This is the **same injected store** F's
reputation cache uses (`WpCache`, §4.8) — kept in a separate key namespace so the two concerns don't
collide (policy §2.3).

**Selectable local-state backend (RS-10).** The storage primitive `WpStateStore` maps onto is **not
hardcoded**: it is chosen by a `local_state_backend` setting (§5) — `object-cache` (WP transients on
the persistent object cache + a `$wpdb` sidecar for the larger ledgers) **or** `file` (a plugin-owned
state directory). This is the same pluggable-local-state requirement E mirrors, motivated by
read-only-filesystem / multi-node hosts where one backend or the other is unavailable. **The default
must work where the plugin directory is not writable** — so the shipped default is `object-cache`
(transients/`$wpdb`, never a file write into the plugin dir); the `file` backend is opt-in for hosts
that lack a persistent object cache but do offer a writable state path. The chosen backend also backs
the O1 local mirror and (for consumers without a shared object cache) the decision-N breaker marker
fallback (`sys_get_temp_dir()` filemtime, §4.9). `WpStateStore` selects the backend at construction;
every method's contract is backend-independent, so the policy engine is unaware which is active.

### 4.7 The core-backed evaluator + STYLE/engine knobs

`PolicyFactory` (§4.3) injects an `EvaluatorInterface` that wraps the bundled funnypot-core two-phase
engine — `classify(RequestEvidence, SiteProfile) → Verdict` and `synthesize(Verdict, SiteProfile,
seed) → FakeResponse` (core M2). The policy engine calls `classify()` **last** in its precedence and
`synthesize()` **only** when it has already chosen `deceive`; D never calls either directly. The
concrete adapter that satisfies `EvaluatorInterface` from core ships with `funnypot-policy`/core (a C
task — the position-blind split, §9); D consumes it, wiring it with the STYLE/engine config below.

**The STYLE/engine knobs are retained** — they are how the operator controls what a fake *looks* like,
and they flow into core's `synthesize()` via the evaluator's own config object (core's `Config`), **not**
into the policy engine (which is style-blind, policy §8):

| Setting (admin) | core `Config` field (feeds `synthesize()`) |
|---|---|
| Response style | `responseStyle` = `minimal\|realistic\|taunt` (STYLE, `FUNNYPOT_STYLE`) |
| Severity ceiling | `severityCeiling` (default `high`; fake-RCE off unless raised) |
| Attack-class emulation | `attackEmulation` (bool) |
| Nuclei reflection | `nucleiReflection` (bool) |
| Emulation-catalog toggles | `exclude[]` (template / product ids / tags to never serve) |
| Persona salt | `seedSalt` (defaults to WP `AUTH_SALT` if unset) |
| Latency / jitter (ms) | `latencyMs`, `latencyJitterMs` |

**Config construction on PHP 7.3 (M15).** Core's `Config` is a promoted constructor of ~20 positional
params with no named-argument support on 7.3. **Preferred:** consume core's 7.3-callable
array/builder factory for `Config` (a C task, §9) so the evaluator config is set by a named map.
**Fallback** until that factory lands: build `Config` **positionally**, passing params **1..N in exact
order** up to the highest one D sets, with core's own defaults filled in for every unmapped param —
and passing **`pathScope` (pos 3)** and **`personaBreadth` (pos 5)** at their positions even though the
table above never mentions them, because a skipped middle positional arg silently misassigns every
later one. The `gate` / `probeSignature` / `killSwitch` / `trustedBypass` closures that the old
respond-mode `Config` needed are **no longer D's concern**: WHEN to classify and WHETHER to deceive is
now the policy engine's precedence (§4/§8), not a core-`Config` closure. D sets only the style/rendering
fields above; everything positional in between is core's default.

### 4.8 Reputation (policy config) + `WpCache`

Reputation is **no longer a bespoke D interceptor step** — under decision M it is a **modifier axis
inside the policy engine's precedence** (policy §4, step 4) and a set of config knobs, not a gate D
runs and blocks on itself. The "check + block known-bad IPs" behavior is still available, but it is now
expressed as `reputation.enabled` + `reputation.block_verdicts` in the §8 config array, and the block
is a `Decision.action = block` the adapter executes (§4.5), produced under the policy's discipline:
**reputation is never primary, never deceives on its own, and by default never blocks on its own** —
only an operator who opts into reputation-block turns an extreme verdict into a `block`, and even then
only at the BEFORE position (policy §4 rules 1–3). D contributes only the WP cache backing:

```php
final class WpCache implements \Funnypot\Mainnet\Cache   // F's PSR-16-style cache seam
{
    // get/set over WP transients (which ride the persistent object cache when the host has one);
    // verdict TTL = cache_ttl_hours. Caches positive AND negative verdicts.
}
```

The policy's `ReputationInterface` adapter (over F's `Funnypot\Mainnet\ReputationGate`/`Client::check`,
transitive via core) reads **local-first** and **never makes a synchronous network call on the request
path** (M5): the request-path `lookup()` returns a verdict from the local mirror (O1, below), then F's
verdict cache, then a fail-open `unknown` — never a socket.

**Local-mirror-lite is the PRIMARY fresh-read (O1).** Rather than paying one keyed `/v1/check` per
uncached visitor IP (origin QPS that scales linearly with the fleet and exhausts quota by noon), the
plugin pulls the **thin blacklist artifact** on cron — a CDN-served, `ETag`/`304`-conditional GET
(~24 pulls/day, quota-cheap) — into `WpStateStore` (the `putMirror`/`mirrorVerdict` methods, §4.6). The
request-path lookup consults this local mirror **first**: an IP present on the mirror resolves to its
`{verdict, expires_at}` with zero network and zero per-IP quota. **Mirror rows may be range entries
(P2/Q2)** — an IPv4 `/24` CIDR, an IPv6 `/64` (per P2, since the IPv6 `score_key` IS the `/64`), or an
ASN (per Q2) — so the lookup matches the visitor IP against a mirror row by **CIDR-containment /
ASN-lookup, not exact IP**; the containment matcher is **`funnypot-policy`'s** (the mirror-lookup /
reputation seam), never reimplemented in D, and the client normalises an IPv6 to its `/64` `score_key`
before the lookup (P2). One `/24` row thus blocks 256 addresses and keeps the mirror small. **Per-IP
`check` becomes the
escalation path for *uncertain* IPs only** — an IP **not** on the mirror, where the operator has both
enabled checking and a valid `sensor` key, is enqueued for the out-of-band warmer (below), never
checked synchronously in-request. Fleet growth thus turns into CDN egress, not origin QPS, and gives
the server-built G3 blacklist artifact its consumer. (`/v1/changes` is the later delta-upgrade of this
same seam — the mirror store is designed not to assume per-IP-only reads.) The mirror is a firewall
mirror, not a scoring input; it never deceives or reports on its own.

**The warmer is a v1 deliverable, not an open item (SF-6).** When checking is enabled and an actor IP
is uncached **and** not on the mirror, the interceptor **enqueues** the IP (local, non-blocking); a
cron tick (the `BlacklistMirror` pull cron and the report-drain hook are both candidate hosts, §4.9/§5)
**drains** the queue through F's `Client::check`, **breaker-guarded** (decision N) and **bounded per
tick**, populating F's verdict cache for the next request. This is the exact E-mirrored shape (E §4.7):
the interceptor enqueues uncached actor IPs; the cron drains via `cachedVerdict`/`check`,
breaker-guarded, bounded per tick — never an inline check that re-creates a synchronous request-path
call. Behavior inherited from F and surfaced as config here:

- **Opt-in + key-gated; inert by default.** No lookup unless `reputation.enabled=true` **and** a valid
  `MAINNET_KEY` is set — a check spends mainnet credits and sends the visitor IP to a third party
  (privacy/GDPR: this is *why* it is off by default). A default install performs **no** reputation
  lookups and blocks nothing.
- **The key is a `sensor`-tier key — report rights *and* an escalation-check quota (O2).** D/E installs
  both report attacker IPs **and** check (escalating) uncertain visitor IPs, so the **single**
  `MAINNET_KEY` D holds is a mainnet **`sensor`**-tier key that carries both rights — resolving the
  earlier D-vs-F contradiction (F §8 said D/E hold a read-only `service` key, which cannot report; D §5
  said the key is shared with reporting). There is **one** key doing both jobs. Because O1 makes per-IP
  `check` an escalation-only path, the check quota the `sensor` tier needs is sized for *uncertain* IPs,
  not every visitor. The quota is **metered per-install** (`sensor_id` / server-observed `source_ip`),
  not per shared key (D3 blesses key reuse across sites), so sharing one `sensor` key across a fleet
  does not collapse the quota onto one bucket.
- **Source IP = `REMOTE_ADDR`** (D7) — the same trusted-proxy-only posture as reporting.
- **Fail-open by default.** mainnet down / timeout / out-of-credits / `429` ⇒ the port returns
  `unknown`, so the policy never blocks on a fault and the site never goes down; `fail_mode=closed` is
  an opt-in escape hatch. F's circuit breaker + short (~1.5s) timeout keep a hurting mainnet from
  stalling the request.
- **Verdict-first (H1/F).** `block_verdicts` (default `['malicious','critical']`) + optional
  `min_block_score` are the config the policy consults; there is **no** score-only threshold.

Because reputation is now an axis in the shared precedence (not a site-wide gate D runs first), the old
"reputation-block runs independently of the deception master switch" wording no longer applies verbatim:
the whole plugin runs the one `evaluate()` per position, and reputation is one input to it. The
`honeypot_wp/reputation_decision` filter still lets advanced operators post-process a verdict before it
feeds the policy (e.g. never-block their own office CIDRs — the L6 seam, §4.12).

### 4.9 Reporting — `Decision.report` → `WpReporterBridge`

Reporting is driven by the policy: when a report is warranted **and clears the policy's 4-layer
suppression** (24h verdict-dedup / per-IP alert cap / buffer-and-collapse / score-gate, plus the
≥2-source aggregate rule and the allowlist/`self_ips`/SAFE_PATHS/OAST backstops — policy §9), the
`Decision` carries a `ReportIntent` (`Decision.report()`). D's job is only to **enqueue and drain** it —
never to decide *whether* to report (that suppression logic left D and lives in the policy):

```php
final class WpReporterBridge        // thin WP-Cron/$wpdb adapter over the mainnet-client reporter
{
    // Arg order matches Funnypot\Mainnet\Reporter / AbuseIpdb exactly:
    // enqueue(string $ip, string $comment, string $categories = '21').
    public function enqueueIntent(\Funnypot\Policy\ReportIntent $r): void;   // maps intent → enqueue()
    public function enqueue(string $ip, string $comment, string $categories = '21'): void;  // fast, local
    public function drain(int $limit = 200): array;                                          // WP-Cron
}
```

The reporter is `Funnypot\Mainnet\Reporter` in **`metrictower/mainnet-client`** (decision F, née piece
B; transitive via core). `WpReporterBridge` is named so it does **not** shadow `Funnypot\Mainnet\Reporter`;
it composes that reporter (or a self-contained fallback port) over a `WpdbReportQueue`. Its `enqueue`
signature is byte-for-byte the reporter's `enqueue(string $ip, string $comment, string $categories =
'21')` — the `$comment` then `$categories` order is load-bearing (swapping them corrupts the feed).
`enqueueIntent` maps the policy's `ReportIntent` onto that call. **Never a blocking HTTP POST inside the
visitor request** — enqueue is local; `drain()` runs on a five-minute WP-Cron hook (or `wp honeypot
report-drain`).

**The drain is outage-bounded (SF-6 / decision N).** WP-Cron fires on a loopback request, and with
`ALTERNATE_WP_CRON` it runs **inside a real visitor's request** — so an unbounded drain that serially
burns `limit × timeout` seconds against a down mainnet would directly slow the protected site. `drain()`
therefore:

- **Has a per-tick wall-clock budget** (default **10 s**, decision N) and stops when the budget is
  spent, leaving the rest of the queue for the next tick.
- **Aborts early after 3 consecutive transport-class failures** (timeout / status 0 / 5xx / 401/403 /
  malformed), **writing the shared decision-N breaker marker** (`mnc:breaker`, §4.9/N6) so the next
  drain tick **and** the reputation check path both fast-skip while the marker is OPEN — one shared
  outage-discovery record across the report and check paths. The drain also **consults** that marker
  before its first POST and skips the tick while OPEN.
- **Distinguishes the two 429 classes** (decision N / SF-7): `code=duplicate_report` drops the row
  (never re-queues into a loop); `code=quota_exhausted` parks per the retry headers, tripping the marker
  OPEN until the server reset (cap 6 h) — never a wasteful 30 s re-probe.
- **Bounds re-queued work and storage:** re-queued rows carry **max-attempts + max-age** caps (dropped,
  not retried forever, past either), and the queue has a **hard size cap** (oldest dropped first) so an
  outage bounds the queue table instead of growing it without limit.
- **Canonical numbers:** drain budget 10 s, abort after 3 consecutive transport failures, drain limit
  200/tick (decision N); any deviation is an explicit note.

**WP-Cron caveat.** WP-Cron only fires when the site receives traffic, so on a **low-traffic** site the
drain (and the O1 mirror pull + the warmer) can stall between visits — reports and the mirror go stale.
The plugin **documents this and recommends a real system cron** (`wp-cron.php` disabled via
`DISABLE_WP_CRON` + a server crontab hitting `wp honeypot report-drain` / the mirror-pull command) for
any install that enables reporting, checking, or the mirror.

The bridge keeps the app's `Funnypot\App\ThreatIntel\AbuseIpdb`-shaped transport guards (self-IP,
public-IP-only, per-IP dedup window, daily cap) as a **transport-level backstop** — belt-and-suspenders
under the policy's own suppression — and targets **`MAINNET_BASE_URL` + `/v1/report`** with a `Key:`
header and the body `ip,categories,comment,timestamp` **plus a `sensor_id`** (§4.11). The queue lives in
`{$wpdb->prefix}honeypot_wp_report_queue`.

**Mainnet address + key (D1/D2).** `MAINNET_BASE_URL` is **scheme + host only, no path** (the bridge
appends `/v1/report`); `MAINNET_KEY` is the API key. Both are settings a `wp-config.php` constant may
wrap (`HONEYPOT_WP_MAINNET_BASE_URL` / `HONEYPOT_WP_MAINNET_KEY`) — the constant wins over the stored
setting — but the value convention is **base-URL-only** everywhere, defaulting to the **mainnet
placeholder host, never AbuseIPDB**. Reporting is **inert without `MAINNET_KEY`**: an empty key ⇒ the
bridge enqueues nothing and sends nothing (same fail-safe shape as the app's `AbuseIpdb`), independent
of the config's report switch and the self-IP guard.

### 4.10 WP-CLI

```
wp honeypot status                 # enabled?, posture, CONFIGURED position, VERIFIED mount, style, catalog, rule phases, queue depth, mirror age
wp honeypot enable  [--posture=honeypot|WAF|both]   # flip master switch + set posture (inert by default)
wp honeypot disable
wp honeypot test <path> [--method=GET]   # dry-run evaluate() for a path; prints action+status+CT+reason
wp honeypot catalog [--enable=<id>] [--disable=<id>]   # edit the emulation catalog (exclude set)
wp honeypot report-drain [--limit=200]   # drain the report queue now (for real-cron installs)
wp honeypot mirror-pull            # conditional (ETag/304) pull of the thin blacklist artifact into the mirror (O1, real-cron)
wp honeypot geoip-refresh          # refresh the local GeoIP DB used by the country gate (R2, real-cron)
wp honeypot promote <rule-id>      # advance a rule SHADOW→TUNING→ENFORCED (learn-then-enforce, M7)
wp honeypot shadow  [<rule-id>|--all]    # demote a rule (or all — the kill-switch) back to SHADOW
```

`status` reports the **verified runtime mount**, not the configured intent (§4.1): the
**BEFORE-mounted-at** line reads `mu-plugin`, `plugins_loaded (degraded)`, or `not running`, so an
operator sees when a wiped shim has silently demoted the BEFORE position (Wordfence gap a). It also
shows the O1 mirror's age (`generated_at` / last-pull) so a stale mirror is visible.

### 4.11 Sensor identity (install UUID)

On first run the plugin generates a stable **install UUID** and persists it to a dedicated
autoloaded WP option (`honeypot_wp_sensor_id`). It is sent on every report as **`sensor_id`** — a
convenience/label only, never a hardware id (blocked reads, privacy, portability). Server-side
distinctness is computed on the server-observed source IP (mainnet A1), not on this client-supplied
id, so a `sensor_id` reused across sites does not collapse distinct sensors. The install UUID is
generated once (`wp_generate_uuid4()` when available, else a random-bytes fallback) and never
regenerated for the life of the install.

### 4.12 Consumer decision overlay (reserved — L6)

**Reserved, not built in v1.** A forward-compat seam so the plugin can later carry a **local
allow/deny overlay** that sits between the mainnet verdict and the block decision, without a config
rewrite. The `honeypot_wp/reputation_decision` filter (§4.8) is the v1 escape hatch; the overlay is the
future structured form of it. When built it holds:

- A **local allow/deny list** (CIDRs / ASNs) with a **defined precedence**: explicit local allow beats
  local deny beats the mainnet verdict — so an operator's own office / partner ranges are never blocked
  and a locally-known-bad range blocks even on a `clean`/`unknown` mainnet verdict.
- A **verdict-floor knob** (`min_block_score` is its v1 seed): "block only at/above verdict X (and
  optional score floor)" stays operator-tunable as the overlay grows.
- **Scoped exceptions** — per-path / per-role carve-outs (e.g. never gate `wp-admin` for a logged-in
  editor).
- A **log-only (dry-run) mode** — evaluate the gate and record what it *would* do to the hit log
  without emitting the `403`, so an operator can measure false positives before enforcing.
- A **verified-good-bot field** — an allowlist of verified crawler identities (reverse-DNS-confirmed
  search engines / uptime monitors) that are never blocked regardless of verdict.

The overlay's inputs stay **extensible**: the verdict/evidence surface F exposes (the H1 `context`
struct — `usage_type`, `shared`, `allowlisted`, `asn`, `country`) is treated as an open, growable map,
not a fixed 5-key contract, so new signals (e.g. a future `verified_bot` or range-`decision` field) are
additive. v1 ships only the `honeypot_wp/reputation_decision` filter; the structured overlay + its
settings are reserved.

### 4.13 Local-mirror-lite pull (O1)

`src/Mirror/BlacklistMirror` is the O1 fresh-read primitive: a cron-driven, conditional pull of the
**thin** blacklist artifact (`variant=thin`, rows `{ip, verdict, expires_at}`) from
`MAINNET_BASE_URL` + `/v1/blacklist`. Per **P2/Q2** the `ip` field of a row may be a **CIDR** (IPv4
`/24`, IPv6 `/64`) or an **ASN**, not just a `/128`/`/32` — the mirror stores rows as-is and the
request-path match is by CIDR-containment / ASN-lookup (§4.8), not exact IP. The pull sends the stored
`ETag` so an unchanged artifact returns `304`
(no re-download, no per-IP quota). A `200` replaces the mirror in `WpStateStore` via `putMirror(rows,
etag, generated_at, ttl)` (§4.6); a `304` refreshes only the freshness timestamp. The pull runs on its
own cron hook (default hourly — well within the ~24 pulls/day quota budget) and via `wp honeypot
mirror-pull` for real-cron installs. It is **breaker-guarded** (decision N — a mainnet outage skips the
pull, the mirror simply ages) and **fail-open**: a stale or empty mirror never blocks; the request-path
lookup falls through to the warmer/escalation path (§4.8). The mirror is only consulted when checking is
enabled and a valid `sensor` key is set; a default install pulls nothing.

### 4.14 Country policy + local GeoIP (`WpGeoIp`) — decision R

Country policy is a **cheap-static gate in the policy ladder** (M5, decision R1): funnypot-policy gains an
optional country check that runs after the allowlist/pin and **before** reputation/content. D contributes
only two thin-adapter pieces — the **country config** (rendered into the §8 policy array by
`Settings::toPolicyConfig`, §5) and a **`WpGeoIp` adapter** that resolves a country from an IP for the
policy to consult. D authors **no** country *decision* logic; the posture + the per-match action live in
the policy, driven by the config.

**Config (admin → the §8 policy array, §5).** The operator picks one of two postures (R1):
- a **country deny-list** — the listed countries get the configured action; or
- a **country allow-list** — only the listed countries pass freely; every other country gets the
  configured action (stricter, higher-FP — R4).

with an **action** of `block | deceive | score-modifier` and, per **R3**, a **default of
`score-modifier`** (country as a suspicion modifier that raises scrutiny / feeds the reputation-check
trigger, not a hard verdict). A hard `block` or the allow-list posture is an **explicit opt-in**: in the
honeypot posture a country block is a *tell* (fingerprint-safety, §6.1) and deceiving a wrongly-geolocated
legit user is silent corruption (M6), and country-blocking is FP-blunt (VPN/CGNAT/roaming/cloud egress,
R4) — so the blunt options are never the default. A country allow-list is the H2/K3 infra allowlist
extended to geo: a listed country still gets content detection, it just skips country-scrutiny.

**`WpGeoIp` — LOCAL resolution, never a network call (R2).**

```php
final class WpGeoIp   // implements \Funnypot\Policy\Port\GeoIpInterface
{
    /** ISO-3166 alpha-2 country for an IP, from the LOCAL GeoIP DB; null when unresolved. */
    public function country(string $ip): ?string;
}
```

The country is resolved from a **local GeoIP database** — the **DB-IP Lite** dataset already used by the
honeypot dashboard + A1 enrichment (GeoLite2 is an alternative) — **never** a network call on the request
path (M5). It resolves both IPv4 and IPv6 (DB-IP / MaxMind support v6, per P/Q enrichment). When country
policy is off (`country_posture=off`) the port is not wired and `WpGeoIp` is never constructed.

**Local-GeoIP-DB distribution + refresh (a data-distribution concern).** The plugin **ships or
references** a local GeoIP DB and **refreshes it on cron** — riding the **same data-distribution +
freshness seam the O1 blacklist mirror uses** (§4.13): a `src/Geo/GeoIpRefresh` cron pull (conditional,
`ETag`/`304`-friendly) keeps the local dataset current on a slow cadence (the DB-IP Lite feed is monthly),
reusing the real-cron recommendation and the WP-Cron low-traffic caveat of §4.9. The dataset is a bundled
asset refreshed **in place** (unlike the never-written vendor bundle, §5), exposed via
`wp honeypot geoip-refresh` (§4.10). A stale or missing DB simply makes `country()` return null
(**fail-open** — the country gate then contributes nothing, never an error).

## 5. Data / config model

- **`honeypot_wp_settings`** (one `wp_options` row, autoloaded). The admin screen writes it; D reads it
  and, via `Settings::toPolicyConfig($position)`, renders the **policy config array** (policy §8) that
  `PolicyConfig::fromArray()` consumes. The stored settings carry:
  - **Policy knobs → the §8 array:** `posture` (`honeypot|WAF|both`, default `honeypot`), `position`
    (`{fallback, before}` — overridable per posture), per-band `actions` on real routes
    (`clean→allow`, `suspicious→log`, `attack_class→block`, `scanner_probe→deceive`), `pin_ttl_seconds`
    (default `3600`), the `learn` block (`shadow_days=7`, `shadow_min_reqs=5000`, `baseline_excluded[]`,
    `kill_switch=false`), the `suppression` block (24h verdict-dedup, per-IP cap 100/600s, buffer TTL
    900s, score-gate 200, aggregate ≥2 sources / ≥200 / 90d, TTL-decay 600s→86400s with +1/+10/+100
    increments — the iCabbiTools numbers, policy §9), `allowlist` (`ips`/`cidrs`/`safe_paths`),
    `self_ips` (operator egress — never self-score/report), and the **`country` block (R)** — `posture`
    (`off|deny_list|allow_list`, **default `off`**), `countries[]` (ISO-3166 alpha-2), `action`
    (`block|deceive|score-modifier`, **default `score-modifier`** — R3) — the operator's optional country
    gate (§4.14), inert when `off`.
  - **STYLE/engine knobs → core's `Config` behind the evaluator (§4.7):** `response_style`,
    `severity_ceiling`, `attack_emulation` (bool), `nuclei_reflection` (bool), `catalog_disabled`
    (string[] → `Config->exclude`), `seed_salt`, `latency_ms`, `latency_jitter_ms`.
  - **Request/report knobs:** `enabled` (bool, master switch — inert by default), `trusted_proxies`
    (CIDR[]), `report_enabled` (bool), `mainnet_base_url` (scheme+host only; defaults to the mainnet
    placeholder host — **never** AbuseIPDB), `mainnet_key` (empty ⇒ reporter **and** reputation both
    inert; the key is a `sensor`-tier key carrying report **and** escalation-check rights — O2),
    `daily_cap`, `drain_budget_secs` (default `10`), `drain_max_attempts` / `drain_max_age_secs`
    (re-queue caps), `queue_cap` (hard queue size, oldest-dropped-first) — the SF-6 drain bounds.
  - **Local-state / mirror knobs (RS-10 / O1):** `local_state_backend` (`object-cache|file`, **default
    `object-cache`** — the default must work where the plugin dir is not writable, §4.6);
    `mirror_enabled` (bool, **default false** — the O1 thin-blacklist mirror; inert unless checking is
    enabled and a `sensor` key is set), `mirror_pull_interval_secs` (default `3600`), and the derived
    warmer queue cap (bounded per tick).
  - **Reputation knobs → the §8 `reputation` block (§4.8, decision F/H1):** `check_enabled` (bool,
    **default false**), `block_verdicts` (string[], **default `['malicious','critical']`** — verdict-first,
    no score threshold), `min_block_score` (int|null, **default null**), `cache_ttl_hours` (number,
    default `24`), `fail_mode` (`open|closed`, **default open**). `mainnet_key` is shared with reporting;
    reputation is inert unless `check_enabled` **and** the key are both set. The request-path read is
    **mirror-first, then F's cache, then fail-open** (O1) — never a synchronous check.
- **`honeypot_wp_sensor_id`** (one autoloaded `wp_options` row): the per-install UUID (§4.11),
  generated once on first run and sent as `sensor_id` on every report.
- **Policy state (the `WpStateStore` backing, §4.6):** per-rule learn-then-enforce state (option),
  deception-consistency pins (short-TTL transients), and the suppression ledger / per-actor counters
  (transient + `$wpdb` sidecar). Written only by the policy engine through the port; pruned by the cron
  sweep. The concrete primitive is the **selectable `local_state_backend`** (`object-cache` vs `file`,
  RS-10) — the default (`object-cache`) never writes into the plugin dir.
- **Local mirror (O1, `WpStateStore.putMirror`/`mirrorVerdict`, §4.6/§4.13):** the cron-pulled thin
  blacklist rows `{ip→(verdict, expires_at)}` + its `{etag, generated_at}` meta, in the selected
  backend. The **primary** request-path fresh-read; refreshed by `wp honeypot mirror-pull` / the mirror
  cron. Bounded and TTL'd; a stale/empty mirror simply falls through (fail-open). Per **P2/Q2** the `ip`
  key of a row may be a **CIDR** (IPv4 `/24`, IPv6 `/64`) or an **ASN**, matched by containment /
  ASN-lookup (funnypot-policy's matcher), not exact IP — one range row covers many addresses (§4.8).
- **Local GeoIP DB (R2, when country policy is enabled):** a bundled/referenced local GeoIP dataset
  (**DB-IP Lite**, reused from the dashboard + A1 enrichment; GeoLite2 alternative) that `WpGeoIp`
  (§4.14) reads on the request path — **never** a network call. Distributed + refreshed on cron via
  `src/Geo/GeoIpRefresh` / `wp honeypot geoip-refresh` (the same data-distribution / freshness seam the
  O1 mirror rides, §4.13). Unlike the never-written vendor bundle it **is** refreshed in place; a
  stale/missing DB makes `country()` return null (fail-open).
- **Warmer queue (SF-6):** a bounded local queue of uncached, not-on-mirror actor IPs the interceptor
  enqueues; drained out-of-band through F's `Client::check` (breaker-guarded, bounded per tick) to
  populate F's verdict cache — never an inline request-path check.
- **Runtime mount marker (Wordfence gap a, §4.1/§4.10):** a short-TTL transient recording which BEFORE
  hook actually fired (`muplugins_loaded` | `plugins_loaded` | none), read by `wp honeypot status` and
  the degraded-position admin notice.
- **Decision-N breaker marker (`mnc:breaker`, §4.9/N):** the shared transport/quota cooldown record in
  the injected persistent cache (or a `sys_get_temp_dir()` filemtime fallback when no shared cache is
  available), written by the drain on repeated transport failure and read by both the drain and the
  reputation warmer/check path.
- **Reserved (L6, not built in v1):** a `decision_overlay` settings sub-shape for the local allow/deny
  overlay of §4.12 (allow/deny CIDRs+ASNs with defined precedence, verdict-floor knob, scoped
  exceptions, log-only mode, verified-good-bot list). Kept out of v1; the settings schema is designed so
  it can be added as an additive key without reshaping the existing options, and the F `context` surface
  it reads stays extensible.
- **`{$prefix}honeypot_wp_hits`** — recent-hits log (bounded, pruned by the cron sweep).
- **`{$prefix}honeypot_wp_report_queue`** + a small dedup/daily-count sidecar, mirroring the app's
  `abuse_queue` / `abuse_reports` / `abuse_daily` shape.
- **Bundled read-only assets**: `vendor/metrictower/funnypot-policy/` + transitive
  `vendor/metrictower/funnypot-core/` + `vendor/metrictower/mainnet-client/` (Composer-installed at
  build) and core's compiled rules artifacts. Never written at runtime by v1.

## 6. Security & invariants touched

1. **Fingerprint-safety holds by delegation.** All emitted bytes come from core's `synthesize()` +
   `ResponseEmitter`; the plugin never authors fake bodies and never emits scanner/matcher signature
   strings. The policy engine reasons over an **opaque signal handle**, never a canonical signature
   string (policy §10), so nothing D or the policy touches can leak a fingerprint. Core's CI fingerprint
   gates cover everything on the wire, and this plugin adds nothing to the wire. The framework-free rule
   binds the honeypot *engine* + the policy package; it does **not** bind this plugin's WP-glue code
   (hooks, admin screen), which lives inside WordPress by nature and is never emitted to an attacker.
   **Invariant for C:** lowering core to PHP 7.3 must keep those CI fingerprint gates green.
2. **Only ever upgrade a 404 / non-endpoint.** Deception is fenced by the policy's governing rule —
   *deceive where the counterfactual is a 404; above the block threshold on real routes; never in the
   uncertainty band* (policy §5). The **FALLBACK position only ever fires on a genuine `is_404()`**, and
   the `WpSiteProfile.routeExists` oracle (§4.2) keeps a fake from ever colliding with a real WP route,
   so a `deceive` can only *add* a fake where WP would otherwise 404 — it never turns a working page
   into a fake. A policy/evaluator fault degrades to `Decision::allow` (or a plain 404 at the fallback),
   never a 500 (a 500 is itself a tell): the interceptor wraps the whole evaluate+execute in a
   `try/catch` that, on any Throwable, returns silently and lets WP continue. **The mu-plugin loader
   shim extends this fail-safe to the load path (SF-4):** it never fatals on a missing/skewed plugin
   bootstrap (`file_exists` guard → silent inert, a guarded static entry, self-heal/self-remove, §4.1),
   so the one code path that runs unconditionally on every request — before the `try/catch` even exists —
   cannot take the site (or wp-admin) down. An outage in the mainnet check/report/mirror paths likewise
   only fails open: the drain is outage-bounded (§4.9), the mirror simply ages, and the request-path read
   is mirror-first/fail-open — never a synchronous stall (§4.8).
3. **Content-Type matches the request; status is app-chosen.** The `Decision.status()` is app-chosen,
   never model-chosen (policy §3); a `deceive` emits core's `synthesize()` fake whose Content-Type
   matches the request (enforced in core's synthesizer + emitter). No model-driven 3xx, no open redirect.
4. **Report self-guard + key-gate.** The policy's suppression backstops (allowlist-everywhere /
   SAFE_PATHS / `self_ips` / OAST hygiene, policy §9) mean an intent for the operator's own egress or an
   app-generated path is never emitted. On top of that, D's transport is **inert without `MAINNET_KEY`**
   (empty key ⇒ enqueues/sends nothing, fail-safe), refuses the site's own egress IP (`self_ips` must be
   set; empty ⇒ reporting disabled), and reports public-routable IPs only — identical posture to the
   app's `AbuseIpdb`. Reporting is **off by default**, and the mainnet base URL defaults to the mainnet
   placeholder host, never AbuseIPDB.
5. **RCE-adjacent rule updates are NOT exposed in v1.** Core's signed runtime rule-update path
   (ed25519 + per-file sha256 + array-literal validation before any `require`) stays bundled-only; the
   WP admin cannot trigger a fetch. The policy package itself has **no** RCE surface — it only reads
   request evidence and returns data, never `require`s anything derived from a request (policy §10).
6. **Least privilege in WP.** Settings and CLI mutations require `manage_options`; the settings form
   is nonce-protected; all queue/log/state writes are `$wpdb->prepare`d.
7. **Reputation is opt-in, key-gated, cache-first, and fail-open (§4.8, decision F/M).** It is inert
   unless `reputation.enabled` **and** `MAINNET_KEY` are both set — no lookup, no visitor IP leaves the
   host. On the request path it is **cache-first and never a synchronous network call** (M5); any fault
   (mainnet down / timeout / out-of-credits / `429`) yields a fail-open `unknown`, so the site never
   goes down. Reputation is a **modifier, never primary**: it never deceives on its own and, by default,
   never blocks on its own — only an operator opting into reputation-block turns an extreme verdict into
   an app-chosen `403` at the BEFORE position (policy §4 rules 1–3). `fail_mode=closed` is an opt-in
   escape hatch, not the default.

## 7. Testing strategy

- **The policy engine is trusted upstream** — its own exhaustive matrix (precedence, the deceive ladder,
  the state machine, suppression) is `funnypot-policy`'s suite, not re-run here (policy §11). Likewise
  core's own suite (nuclei-inversion, CRS, fingerprint gates) is not re-run; D depends on both passing
  their 7.3 CI. D tests only the **adapter** seams.
- **Plugin unit tests** (WP test scaffolding / Brain Monkey for hook mocking, PHP 7.3–8.x matrix),
  every one driving a **fake `PolicyEngine`** so no policy logic is re-implemented or re-tested here:
  - `RequestFactory` → `RequestEvidence` + proxy-IP resolution (XFF trusted only behind a trusted
    proxy, D7) and `WpSiteProfile` (`routeExists` true for genuine surfaces, `isSacrificialPath` true
    for `.env`/`.git`, xmlrpc/wp-login gated by the two opt-in flags).
  - `DecisionExecutor` — a fake `Decision` of each action drives the right effect: `allow`/`log` → no
    emit (WP proceeds; `log` writes a hit row); `deceive` → emit `fakeHandle` + halt; `block` → 403 +
    halt; `pinTtl` set → `WpStateStore::setPin`; `report` set → `WpReporterBridge::enqueueIntent`;
    status taken from the `Decision`, never invented.
  - `Interceptor::runBefore` / `runFallback` — position gating (before runs only when `position.before`;
    fallback only when `position.fallback` **and** `is_404()`), idempotency, and the `try/catch`
    degrade-to-allow (a throwing engine emits nothing, no 500).
  - `WpStateStore` — each method round-trips against a Brain-Monkey-mocked transient/option/`$wpdb`
    (pin get/set with TTL, rule-state put/get, dedup `seenVerdict`, counter `incr`).
  - `WpCache` — verdict round-trip, TTL = `cache_ttl_hours * 3600`, namespaced keys, caches misses.
  - `WpReporterBridge` — `enqueueIntent` maps a `ReportIntent` onto `enqueue(ip, comment, categories)`
    in the correct arg order (M8 regression); transport guards (self-IP, private-IP, dedup, cap,
    empty-key inert); `drain()` POSTs to `${mainnetBaseUrl}/v1/report` with the `sensor_id` body; **SF-6
    drain bounds** — a drain against a stubbed-down transport stops within the wall-clock budget, aborts
    after 3 consecutive transport failures and writes the decision-N marker, skips the tick while the
    marker is OPEN, drops a `duplicate_report` 429 without looping, parks on `quota_exhausted`, and
    honors max-attempts/max-age + the hard `queue_cap` (oldest dropped first).
  - `MuLoaderInstaller` / shim degrade-safety (**SF-4**) — `plan(true)==='mu'`, `plan(false)==='fallback'`;
    the shim body no-ops when the bootstrap file is absent (a fake missing-bootstrap path returns without
    fatal); the guarded static entry tolerates a skewed/missing symbol; self-heal rewrites a
    stale/missing shim and self-remove no-ops when the plugin is gone. **The load-path takedown test:
    shim present + plugin dir removed → the request serves normally (no fatal).**
  - Runtime position self-check (**Wordfence gap a**) — the mount marker records which BEFORE hook fired;
    `status` reports `mu-plugin` | `plugins_loaded (degraded)` | `not running` from the marker, not the
    configured intent, and a degraded mount raises the admin notice.
  - `BlacklistMirror` / mirror read (**O1**) — a `200` populates `putMirror` (rows + etag + generated_at);
    a `304` refreshes only freshness; a stored `ETag` is sent on the conditional pull; `mirrorVerdict`
    resolves an on-mirror IP with zero network and returns null for an off-mirror IP (→ escalation
    queue); a breaker-OPEN or empty mirror falls through fail-open.
  - `WpStateStore` backend selection (**RS-10**) — the same port contract round-trips under both
    `local_state_backend=object-cache` and `=file`; the default is `object-cache` and performs no write
    into the plugin dir.
  - `Settings::toPolicyConfig` — the settings→§8-array mapping (posture/position/actions/reputation/
    learn/suppression/allowlist) reads back correctly and defaults are inert; the O2 `sensor`-key,
    RS-10 backend, and O1 mirror knobs default inert.
  - `EvaluatorConfig` (§4.7) — the STYLE/engine settings→core-`Config` mapping reads back every set
    field (the M15 positional guard against a misassigned `pathScope`/`personaBreadth`).
- **Integration**: spin a real WordPress in Docker with the plugin + bundled policy/core active; assert
  (a) at the FALLBACK position a `GET /.env` is deceived with the right Content-Type and WP never boots
  the theme; (b) a real published page and `/wp-login.php` are untouched (byte-identical to plugin-off);
  (c) master-switch-off is inert on the wire; (d) at the BEFORE position with a stub reputation cache, a
  `malicious` IP under an opted-in reputation-block posture gets a 403, an `unknown` IP falls through.
- **Golden emit test**: the same probe (deceived) hitting the standalone funnypot app and the WP plugin
  yields byte-identical body/headers for a fixed seed (proves the plugin adds nothing on-wire).
- **Reporter swap test**: point the reporter at a stub `/v1/report` and assert body-shape parity with
  the app's `AbuseIpdb` POST (the piece-F/A1 contract).
- **Static**: `phpcs` WordPress-Coding-Standards on glue code; `node --check` n/a (no JS test runner);
  Plugin Check (PCP) for the eventual wordpress.org submission.

## 8. Key decisions I made (confirm at review)

1. **D is a thin adapter over `funnypot-policy` (decision M), not a bespoke responder.** The plugin
   normalizes the request, calls `PolicyEngine::evaluate()`, and executes the returned `Decision`. All
   decision logic — cheapest-first precedence, two-axis combination, learn-then-enforce, pin/TTL,
   suppression — lives once in the shared package; D reimplements none of it (policy §12). This is the
   single largest change from the pre-M design (which called `respond()` and ran a bespoke reputation
   gate).
2. **Two position hooks (M4):** a BEFORE-position middleware (`muplugins_loaded` via an installed
   mu-plugin shim, `plugins_loaded` fallback) and a FALLBACK-position 404 hook (`template_redirect` when
   `is_404()`). Which run is the operator's posture/config choice (`honeypot`=fallback, `WAF`=before,
   `both`=both). The FALLBACK hook is FP-free by construction — it only ever upgrades a genuine 404.
3. **The genuine-WP-surface knowledge becomes the `WpSiteProfile` real-route oracle** (§4.2), not a
   bespoke skip-list D runs before the engine. `routeExists` (the reserved set + `is_404()`/live-post)
   and `isSacrificialPath` (`.env`/`.git`/…) are **data** the position-blind engine consumes;
   `xmlrpc`/`wp-login` decoys stay opt-in behind disabling the real feature. This is the one job only
   the host can do, because only WordPress knows its own routes.
4. **Install default is inert** (`enabled=false`); the FALLBACK honeypot and any BEFORE actions are the
   operator's explicit posture choice. On enable, the default posture is `honeypot` (FALLBACK deceives
   every 404 — FP-free) with real-route rules in SHADOW (policy §7).
5. **Reporting is off by default, driven by the policy's suppression-vetted `Decision.report`
   intent**, enqueue-now / WP-Cron-drain, never a blocking POST in the visitor request; transport guards
   mirror the app's `AbuseIpdb` as a backstop under the policy's own suppression. Base-URL-only
   `MAINNET_BASE_URL` (the bridge appends `/v1/report`) defaulting to the mainnet placeholder host,
   inert without `MAINNET_KEY`, env-overridable via `wp-config.php` constants. A per-install `sensor_id`
   UUID is sent on every report.
6. **funnypot-policy + transitive funnypot-core / mainnet-client are bundled** (Composer-installed at
   build, committed into the plugin zip) rather than expecting the host to `composer require` them — WP
   sites generally have no Composer workflow. Rules ship bundled; runtime signed-update is deferred.
7. **HTTP-only, per-site v1.** No SSH/TCP emulators (those are app-only), no multisite network UI, no
   in-admin rule-update, no wordpress.org SVN release yet — all fast-follow.
8. **Namespace `Honeypot\WP\`, text domain `honeypot-wp`, single autoloaded settings option** that
   renders the policy config array, custom `$wpdb` tables for hits/queue, transient/option-backed
   `WpStateStore`.
9. **Reputation is a policy config knob + a WP cache backing, not a bespoke first-gate** (§4.8). D
   contributes only the `WpCache` (F's cache seam) and the `reputation.*` settings; the check is
   cache-first (never a sync request-path call, M5), fail-open, and a modifier — the block is a
   `Decision.action` the policy produces under its rules, executed by the adapter, not a site-wide gate D
   runs first. This is the cheap IP-reputation front door for the CRS-WAF posture, now expressed as
   policy config rather than plugin logic.

## 9. Dependencies on other pieces

- **`metrictower/funnypot-policy` (PRIMARY — decision M).** D consumes the policy engine's public API:
  `Funnypot\Policy\PolicyEngine::evaluate(RequestEvidence): Decision`, the five ports D implements or
  wires (`EvaluatorInterface`, `ReputationInterface`, `StateStoreInterface`, `Clock`, `Logger`), the
  `Funnypot\Policy\SiteProfile` shape, `Funnypot\Policy\Decision` / `RequestEvidence` / `ReportIntent`
  value objects, and `Funnypot\Policy\PolicyConfig::fromArray()` (the §8 array). PHP >=7.3, framework-free
  — same 7.3 posture as core-after-C. D bundles it (and its transitive deps) in the plugin `vendor/`.
- **C · funnypot-core → PHP 7.3 + the two-phase split (HARD PREREQUISITE).** WordPress hosts routinely
  run PHP 7.x; core is currently `"php": ">=8.0"` (see `funnypot-core/composer.json`). C must (a) re-floor
  core to 7.3 — the real blockers are **constructor property promotion** plus the 7.4-only constructs
  (**typed properties, arrow functions, `??=`**; core uses no named args and no union types) — and (b)
  land the **M2 position-blind split**: the responder becomes `classify(RequestEvidence, SiteProfile) →
  Verdict` + `synthesize(Verdict, SiteProfile, seed) → FakeResponse`, exposed to the policy behind
  `EvaluatorInterface`, with the deception content fully retained. **This plugin cannot ship until C
  lands** while keeping the fingerprint CI gates green — the single blocking dependency, the reason D is
  sequenced after C. D also asks C to expose a **7.3-callable `Config` array/builder factory** (§4.7, M15)
  so D need not construct the evaluator's core `Config` positionally.
- **funnypot-core (transitive, via funnypot-policy).** The two-phase engine behind the policy's
  `EvaluatorInterface`; D consumes it only through that seam plus `Funnypot\Http\ResponseEmitter::emit()`
  (to emit the `fakeHandle`). D no longer calls `Funnypot\Honeypot::respond()`/`detect()` or builds a
  respond-mode `Config` with gate/probeSignature closures — the WHEN/WHETHER now lives in the policy.
- **`metrictower/mainnet-client` (transitive, via core/policy; decision F).** The standalone mainnet
  client (PHP >=7.3, namespace `Funnypot\Mainnet\`, no framework). D consumes it two ways, both behind
  the policy: F's `ReputationGate`/`Client::check` is read through the policy's `ReputationInterface`
  (cache-first, backed by D's `WpCache`, §4.8); F's relocated reporter `Funnypot\Mainnet\Reporter`
  (née piece B) is composed by `WpReporterBridge` for the optional reporting path (§4.9). Inert unless
  enabled+keyed, so it adds nothing to a default install's request path.
- **Reporter (via F — OPTIONAL).** `Funnypot\Mainnet\Reporter` in `metrictower/mainnet-client`, pulled
  in transitively — no `Funnypot\Report\*` tree, no "if B landed" fork (F's reporter is always present).
  `WpReporterBridge` (named to avoid shadowing it) composes it over a `WpdbReportQueue implements
  \Funnypot\Mainnet\Report\ReportQueue`, reusing the enqueue/drain contract of
  `funnypot/src/App/ThreatIntel/AbuseIpdb.php`; driven by the policy's `Decision.report` intent. Until
  F's package resolves locally the plugin may carry a self-contained port with the identical public
  shape. The bridge's `enqueue(string $ip, string $comment, string $categories = '21')` signature
  matches the reporter's exactly (§4.9, M8). Reporting off ⇒ no dependency.
- **A1 · mainnet-api (transitive, via F).** Reporting targets **`MAINNET_BASE_URL` + `/v1/report`**
  (base URL is scheme+host only; the bridge appends the path) per
  `funnypot-mainnet/docs/2026-08-19-mainnet-api-design.md` §5.1 (form body `ip,categories,comment,
  timestamp` + `sensor_id`, `Key:` header). Only relevant when reporting is enabled. **O1** adds a
  second A1 consumption: the O1 mirror pulls A1's **G3 thin blacklist artifact** (`GET /v1/blacklist`,
  `variant=thin`, `format=json`, `ETag`/`304`) — the fleet-scale fresh-read that keeps origin QPS off
  per-IP `check` and finally gives the G3 artifact a consumer (§4.13). Only relevant when checking + the
  mirror are enabled.
- **Mainnet key tier (O2) — reconciles the D-vs-F key contradiction.** D/E hold a mainnet **`sensor`**-tier
  key: **report rights + an escalation-check quota** sized for per-visitor traffic and **metered
  per-install** (`sensor_id`/`source_ip`), not per shared key (D3 blesses key reuse). This supersedes the
  earlier F §8 "D/E hold a read-only `service` key" (a `service` key cannot report → the drain would
  silently permanent-drop reports) and the D §5 "the key is shared with reporting" ambiguity: **there is
  one `sensor` key doing both jobs.** The A1 tier/quota model must expose the `sensor` tier (decision O2).
- **E · honeypot-laravel** — sibling, independent; the same thin-adapter-over-`funnypot-policy` pattern
  (both keep only the five §12 responsibilities), but no code dependency in either direction. D is the
  reference posture for `REMOTE_ADDR`-by-default IP resolution (D7), the O1 local-mirror-lite fresh-read,
  and the SF-6 outage-bounded drain/warmer — E mirrors all three.

---

## Review resolutions applied (2026-08-19)

- **D1** — Renamed the mainnet address settings to the canonical **`MAINNET_BASE_URL`** (scheme+host
  only; the bridge appends `/v1/report` itself) + **`MAINNET_KEY`**. Replaced `mainnet_host` /
  `HONEYPOT_WP_MAINNET_HOST` with base-URL-only convention throughout §4.5, §5, §8.5, §9; the
  `wp-config.php` wrapping constants are now `HONEYPOT_WP_MAINNET_BASE_URL` / `HONEYPOT_WP_MAINNET_KEY`.
- **D2** — Mainnet base URL now **defaults to the mainnet placeholder host, never AbuseIPDB** (§4.5,
  §5, §6.4, §8.5); reporter is **inert without `MAINNET_KEY`** (empty key ⇒ enqueues/sends nothing),
  stated as a key-gate alongside the existing self-IP fail-safe.
- **D3** — Added §4.7 "Sensor identity": a per-install UUID generated once and persisted to the
  `honeypot_wp_sensor_id` WP option, sent as `sensor_id` on every report; not a hardware id. Source IP
  stays `REMOTE_ADDR` by default with trusted-proxy-only XFF (§4.4). Added the option to §5 and the
  `sensor_id` field to the A1 report body (§4.5, §9).
- **D7** — §4.4 now states `REMOTE_ADDR`-by-default + trusted-proxy-only XFF explicitly as a **v1
  requirement** and names it as the reference posture piece E mirrors.
- **M8** — Renamed the bridge class `MainnetReporter` → **`WpReporterBridge`** so it does not shadow
  core's `Funnypot\Report\MainnetReporter`, and fixed the `enqueue` signature to match core **exactly**:
  `enqueue(string $ip, string $comment, string $categories = '21')` (was arg-swapped
  `($ip, $categories, $comment)`, which would corrupt reports). §4.5, §9.
- **M15** — Replaced the "modeled on core's `buildConfig` (named args)" guidance in §4.3. Now:
  **prefer** consuming core's 7.3-callable `Config` array/builder factory (tracked as a C task); the
  **fallback** is an explicit positional recipe passing params 1..17 in order with core defaults for
  unmapped params, explicitly flagging **`pathScope` (pos 3)** and **`personaBreadth` (pos 5)** — which
  the §4.3 table omits — and the silent-misassignment risk of positional construction.
- **Nit** — §9's C-dependency PHP-8 construct list trimmed to the real blockers: **constructor
  promotion + 7.4 typed properties / arrow functions / `??=`**; removed the overstated "named args" and
  "union-type reads" (C found 0 of each).
- **F — mainnet-client dependency + reputation check/block.** Per decision F, D now depends on
  `metrictower/mainnet-client` **transitively via core** (core `require`s and re-exports it), added to
  the header and §9. Added **§4.8 "Reputation check + reputation-block"**: an off-by-default,
  key-gated, **fail-open** IP-reputation first-gate over F's `Funnypot\Mainnet\ReputationGate` — the
  interceptor consults `decide(REMOTE_ADDR)` (D7 source IP) ahead of the deception path and rejects a
  `block` verdict with a plain app-chosen `403`; a `WpCache` transient/object-cache adapter backs F's
  `Funnypot\Mainnet\Cache` seam for `cache_ttl_hours`; `fail_mode=closed` is an opt-in. Added the
  `check_enabled` (default off) / `block_threshold` (75) / `cache_ttl_hours` (24) / `fail_mode` (open)
  settings to §5 (reusing the shared `MAINNET_KEY`), a scope bullet to §2, security invariant §6.7,
  key decision §8.9, a §7 unit-test line (fake-gate driven), and noted in §9 that F relocates B's
  reporter into `Funnypot\Mainnet\Reporter` inside the same package (D's existing reporter/bridge
  scope, §4.5, otherwise unchanged). *(The `block_threshold` (75) score knob added here was superseded
  by the verdict-first re-apply — see the K + re-review + L subsection below.)*

## Review resolutions applied — K + re-review + L (2026-08-19)

- **Program envelope convention.** Every `/v1` response is a top-level `{ "data": ... }` envelope;
  `check` is `{ "data": { verdict, score, ... } }`; blacklist keeps `{ "meta": {...}, "data": [...] }`.
  Native snake_case field names only — **no** AbuseIPDB parity names. D consumes F's `CheckResult` /
  `ReputationGate` (which already speak the native verdict-first model), so this is a naming invariant D
  inherits rather than a wire D parses directly.
- **Re-review #2 — verdict-first reputation gate (re-applied).** The reputation-block config previously
  wired the **deleted** score `block_threshold` (a score). Replaced everywhere with the verdict-first
  **`block_verdicts`** (default `['malicious','critical']`) + optional **`min_block_score`** (default
  `null`), matching F's `ReputationGate` `Config` (canonical §F). Fixed §4.8 (block logic — blocks when
  the verdict is in `block_verdicts`, and, if `min_block_score` is set, `score` ≥ that floor; no
  score-only threshold), §5 (the settings sub-shape now lists `block_verdicts` + `min_block_score`, not
  `block_threshold`), and the plan's Config read-back test (Phase 6b / Phase 1). `cache_ttl_hours`
  default stays `24` for the WP host (§16 note: E/F default 12; the WP default is deliberately higher).
- **Re-review #6 — reporter rebind (mainnet-client, not core).** The WP reporter/engine wiring must
  bind the **relocated** `Funnypot\Mainnet\Reporter` and `Funnypot\Mainnet\Report\ReportQueue` (in
  `metrictower/mainnet-client`, transitive via core), **not** any `Funnypot\Report\*` tree in core (which
  F removed). §4.9 / §9 (post-M renumber) bind `Funnypot\Mainnet\*`; the residual `Funnypot\Report\*` references in
  this doc are historical (they explain what F relocated *out* of core), and the plan's Phase 6 fork
  ("if B landed, core ships `Funnypot\Report\*`") is dropped — F's reporter is always present
  transitively (see the plan changelog).
- **L6 — consumer decision overlay (reserved).** Added the overlay (now §4.12 after the M renumber): a
  reserved (not-built-in-v1) local
  allow/deny overlay with a defined precedence (local allow > local deny > mainnet verdict), a
  verdict-floor knob (`min_block_score` is its v1 seed), scoped per-path/per-role exceptions, a log-only
  (dry-run) mode, and a verified-good-bot field. The F `context` struct it reads is kept **extensible**
  (an open, growable map, not a fixed 5-key contract). Reserved as an additive settings sub-shape in §5;
  v1 ships only the `honeypot_wp/reputation_decision` filter escape hatch.

## Review resolutions applied — M re-point onto `funnypot-policy` (2026-08-19)

Decision **M** re-points D from a bespoke funnypot-core responder onto the new `funnypot-policy` package
via a **thin WordPress adapter**. funnypot-core becomes the position-blind two-phase `classify()` +
`synthesize()` engine (M2), held by the policy behind `EvaluatorInterface`; the policy owns POSITION,
the cheapest-first precedence, learn-then-enforce, pin/TTL, and report suppression; D keeps only the
five §12 adapter responsibilities. D's **deception/engine scope and the C hard-dependency are retained**
(the fakes are unchanged — they move under `synthesize()`). Surgical edits:

- **Header / §9 dependencies** — added `metrictower/funnypot-policy` as the **primary** consumed package;
  funnypot-core is now consumed *transitively via the policy* (behind `EvaluatorInterface`, plus
  `ResponseEmitter` to emit the fake); the C prerequisite now also covers the **M2 two-phase split**, not
  only the 7.3 re-floor. mainnet-client is consumed behind the policy's `ReputationInterface` (reputation)
  and via `WpReporterBridge` (reporting). Dropped all direct `Honeypot::respond()`/`detect()` /
  respond-mode-`Config`-closure consumption.
- **§1 What this is / §2 Scope / §3 Architecture** — reframed as: normalize request → `RequestEvidence`
  + `WpSiteProfile` → `PolicyEngine::evaluate()` → execute the `Decision` (allow/log/deceive/block).
  Introduced the **two positions** (BEFORE middleware + FALLBACK 404 hook) as a config/posture choice
  (M4). Added a non-goal: **D never reimplements any policy logic** (policy §12).
- **§4.1** — `Interceptor` now has `runBefore()` + `runFallback()` (each idempotent, config/`is_404()`-gated),
  factoring one shared normalize→evaluate→execute body.
- **§4.2** — the genuine-WP-surface allowlist becomes **`WpSiteProfile`** (`routeExists` oracle +
  `isSacrificialPath` set) — the policy's FP-safety input data, not a bespoke skip-list. `SurfaceAllowlist`
  is retired as a standalone class.
- **§4.3** — `EngineFactory` (which called `respond()`) becomes **`PolicyFactory::forPosition()`**, the one
  wiring point that injects the five ports + the §8 `PolicyConfig` array.
- **§4.4** — `RequestFactory` now builds the policy's neutral **`RequestEvidence`** (not core's
  `RequestContext`, which the evaluator builds internally); `clientIp()` (REMOTE_ADDR / trusted-proxy XFF,
  D7) is unchanged and becomes the policy's actor id.
- **§4.5** — the `\Funnypot\Observer` `HitObserver` is replaced by a **`DecisionExecutor`** that performs
  the effect of each `Decision.action` and honors `pinTtl` / `report`; observation is now the `log`
  action + the `Logger` port.
- **§4.6 (new)** — **`WpStateStore implements StateStoreInterface`**: pins/TTL, learn-then-enforce rule
  state, the suppression ledger, per-actor counters — all logic in the policy, D only maps to WP storage.
- **§4.7 (new)** — the **core-backed evaluator + STYLE/engine knobs**: the retained response-style /
  severity / attack-emulation / nuclei-reflection / catalog-exclude settings feed core's `synthesize()`
  via the evaluator's `Config`; the M15 positional-`Config` recipe moved here; the gate/probeSignature/
  killSwitch closures are dropped (WHEN/WHETHER is the policy's, not a core-`Config` closure).
- **§4.8** — reputation is now a **policy config knob + `WpCache` backing**, not a bespoke first-gate;
  cache-first (no sync request-path call, M5), fail-open, modifier-only; the block is a `Decision.action`
  the adapter executes. `ReputationGateFactory` + the interceptor "step 0" gate are retired.
- **§4.9 (new heading)** — reporting is driven by the policy's suppression-vetted **`Decision.report`**
  intent; `WpReporterBridge` gains `enqueueIntent()` and keeps the AbuseIpdb-shaped transport guards as a
  backstop. The **4-layer suppression logic left D and lives in the policy** (§9).
- **§4.10 WP-CLI** — added `promote` / `shadow` (learn-then-enforce controls); `status` reports posture /
  position / rule phases. **§4.11** — sensor identity unchanged (renumbered). **§4.12** — the L6 overlay
  stays reserved (renumbered).
- **§5** — the settings option now renders the **§8 policy config array** (posture / position / per-band
  actions / learn / suppression / allowlist / self_ips / reputation) **plus** the STYLE/engine knobs;
  added the `WpStateStore` policy-state backing; the bundle now carries policy + transitive core +
  mainnet-client.
- **§6 invariants / §7 testing / §8 key decisions** — restated by delegation to the policy (deception
  governing rule, opaque signal handle, fail-safe-to-allow, reputation-as-modifier); tests now drive a
  **fake `PolicyEngine`** and cover the adapter seams only (no policy logic re-tested here).
- **Ambiguity note:** at the BEFORE position WP's main query has not run, so `WpSiteProfile.routeExists`
  covers the static reserved-prefix set only; the policy's matched-only `classify()` + precedence keep a
  real content path from being deceived there. The permalink-aware pre-check remains a documented
  belt-and-suspenders open item (§8, plan Risk 4), now expressed as a SiteProfile refinement rather than a
  separate allowlist step.

## Review resolutions applied — N/O + future-proofing (2026-08-19)

Applies decisions **N** (global fail-open cooldown) and **O** (fleet-read: local-mirror-lite + sensor
tier), plus the future-proofing-review items scoped to D (`2026-08-19-futureproofing-review.md`):
**SF-4**, **SF-6**, **O1**, **O2**, **RS-10**, and the **runtime position self-check** (Wordfence gap a).

- **SF-4 — degrade-safe mu-plugin loader shim.** §4.1 now specs the shim as fail-safe on the load path:
  it never fatals on a missing plugin bootstrap (`if (!file_exists($bootstrap)) return;`), tolerates
  shim/plugin version skew via one stable versioned entry file + a guarded static (`function_exists`/
  `class_exists` + `try/catch`), self-heals a stale/missing shim on normal load, and self-removes/no-ops
  when the plugin is gone. Reinforced invariant §6.2 (the one path that runs before the interceptor's
  `try/catch` cannot take the site down). §7 adds the takedown test: **shim present + plugin dir removed
  → request serves normally.** This is the path where the WAF could take down the site it protects.
- **Runtime position self-check (Wordfence gap a).** §4.1 records **which BEFORE hook actually fired**
  (`muplugins_loaded` | `plugins_loaded` | none, persisted to a short-TTL marker, §5); §4.10 has
  `wp honeypot status` report the **verified mount** — `mu-plugin` | `plugins_loaded (degraded)` |
  `not running` — not the configured intent, and raise an **admin notice** when the effective position
  is degraded below the configured one. §7 adds the mount-marker test.
- **SF-6 — outage-bounded drain + specced v1 warmer.** §4.9 gives `drain()` a per-tick wall-clock budget
  (10 s), an early abort after 3 consecutive transport failures that **writes the shared decision-N
  marker** (N6), 429-class branching (`duplicate_report` drop vs `quota_exhausted` park per the retry
  headers), and re-queue max-attempts/max-age + a hard `queue_cap` (oldest dropped first). The reputation
  **warmer is promoted from an open item to a v1 deliverable** (§4.8): the interceptor enqueues uncached,
  not-on-mirror actor IPs; a cron tick drains them through F's `check`, breaker-guarded and bounded per
  tick — never an inline request-path check. Added the WP-Cron low-traffic caveat + a real-cron
  recommendation. §7 adds the drain-bounds tests.
- **O1 — local-mirror-lite is the PRIMARY fresh-read.** New §4.13 `BlacklistMirror`: a cron-driven,
  `ETag`/`304`-conditional pull of A1's **thin blacklist artifact** (`GET /v1/blacklist`, `variant=thin`)
  into `WpStateStore` (new `putMirror`/`mirrorVerdict`/`mirrorMeta` methods, §4.6). §4.8's request-path
  read is now **mirror-first → F's cache → fail-open**; per-IP `check` is the **escalation path for
  uncertain (off-mirror) IPs only**, via the warmer. Fleet growth becomes CDN egress, not origin QPS, and
  the G3 artifact finally has a consumer. Added the `wp honeypot mirror-pull` command (§4.10), the mirror
  store + `mirror_enabled`/`mirror_pull_interval_secs` settings (§5), and §7 mirror tests.
- **O2 — `sensor`-tier key; D-vs-F contradiction reconciled.** §4.8 + §9 state D/E hold a single mainnet
  **`sensor`**-tier key carrying **report rights + an escalation-check quota**, metered per-install
  (`sensor_id`/`source_ip`), not per shared key — superseding the earlier F §8 read-only-`service`-key
  claim (which cannot report) and the D §5 "shared with reporting" ambiguity. One key does both jobs; the
  A1 tier model must expose the `sensor` tier.
- **RS-10 — selectable local-state backend.** §4.6 + §5 add `local_state_backend` (`object-cache|file`,
  **default `object-cache`**); the port contract is backend-independent, and **the default works where
  the plugin dir is not writable** (never a file write into the plugin dir). §7 adds the both-backends
  round-trip test.
- **N — drain-side marker.** The SF-6 drain and the §4.8 warmer/check path share the decision-N
  `mnc:breaker` marker (§5): the drain writes it on repeated transport failure and both consult it to
  fast-skip while OPEN — one outage-discovery record across the report and check paths. Canonical N
  numbers (threshold, cooldown, budget, limit) are cited; the WP `cache_ttl_hours=24` remains an explicit
  per-piece deviation.

## Review resolutions applied — P/Q/R entity+geo (2026-08-19)

Applies decisions **P** (IPv6 hardening), **Q** (range/CIDR/ASN reputation — block ranges, not many IPs),
and **R** (country policy via LOCAL GeoIP) as scoped to D — the WP-adapter-visible pieces of the
entity + geo work. Everything not implicated (the N/O + future-proofing edits, M re-point, K/re-review/L)
is preserved.

- **P2 / Q2 (inherited) — the local mirror carries range/ASN rows, matched by containment.** §4.8, §4.13,
  and §5 now state the O1 thin-blacklist mirror rows may be **CIDR** (IPv4 `/24`, IPv6 `/64` per P2) or
  **ASN** (per Q2) entries, and the request-path mirror lookup + reputation gate match the visitor IP by
  **CIDR-containment / ASN-lookup, not exact IP** — the containment matching is **provided by
  `funnypot-policy`** (the mirror-lookup / reputation seam), never reimplemented in D. One `/24` row blocks
  256 addresses, keeping the mirror small; the client normalises an IPv6 to its `/64` `score_key` before a
  mirror lookup (P2). No new D build beyond consuming the policy's containment matcher.
- **R1 / R3 — country policy in the WP admin (a policy-ladder cheap-static gate).** New **§4.14**: the
  admin settings produce a **`country`** config block (deny-list OR allow-list posture; action
  `block|deceive|score-modifier`, **default `score-modifier`** per R3) rendered into the §8 policy array by
  `Settings::toPolicyConfig`. The country check itself is the policy's (M5 ladder — after allowlist/pin,
  before reputation/content); D authors no country decision logic. Default = **modifier** (raise
  scrutiny); a hard `block` / the allow-list posture is an **explicit opt-in** — a country block in the
  honeypot posture is a tell (§6.1), deceiving a mis-geolocated legit user is silent corruption (M6), and
  country-blocking is FP-blunt (R4), so the blunt options are never the default. Added the `country` block
  to §5 and the §4.3 ports table entry.
- **R2 — `WpGeoIp` local adapter + local-DB distribution / refresh.** Added **`WpGeoIp implements
  \Funnypot\Policy\Port\GeoIpInterface`** (§4.14) — an **optional sixth port**, wired only when country
  policy is enabled — that resolves a country from the **local GeoIP DB** (**DB-IP Lite**, reused from the
  dashboard + A1 enrichment; GeoLite2 alternative), **never a network call** (M5), IPv4 + IPv6. Added the
  **local-GeoIP-DB distribution + refresh** concern (§4.14 / §5): the plugin ships/references the local DB
  and refreshes it on cron via `src/Geo/GeoIpRefresh` / `wp honeypot geoip-refresh` (§4.10) — the same
  data-distribution / freshness seam the O1 blacklist mirror rides — a bundled asset refreshed in place; a
  stale/missing DB makes `country()` return null (fail-open).
