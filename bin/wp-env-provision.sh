#!/usr/bin/env bash
#
# Idempotent wp-env provisioning for the live integration suite. Two preconditions the plugin
# needs before its request-time behavior is observable over HTTP:
#
#   1. Pretty permalinks — so an unknown URL is routed into WordPress (index.php) and reaches
#      template_redirect, where the honeypot's FALLBACK position lives. With the default plain
#      permalinks, Apache 404s an unknown path before WordPress ever runs.
#   2. The plugin enabled in honeypot posture — it ships INERT by default (enabled=false).
#
# Safe to run repeatedly; every step is best-effort so a partially-provisioned site self-heals.

set -uo pipefail
cd "$(dirname "$0")/.."

run() { npx --no-install wp-env run cli "$@" >/dev/null 2>&1; }

run wp rewrite structure '/%postname%/' --hard || true
run wp rewrite flush --hard || true
run wp option update honeypot_wp_settings --format=json '{"enabled":true,"posture":"honeypot"}' || true

echo "wp-env provisioned: pretty permalinks + honeypot plugin enabled (honeypot posture)."
