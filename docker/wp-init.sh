#!/usr/bin/env bash
# FP-0497 — one-shot provisioner for the local docker harness. Idempotent: safe to re-run.
# Waits for the WordPress files + DB, installs core, creates the dev admin, activates the plugin.
# LOCAL-ONLY dev conveniences — never for a real site.
set -euo pipefail

WP_URL="http://localhost:8919"
ADMIN_USER="admin"
ADMIN_PASS="funnypot"          # operator-chosen, LOCAL-ONLY, not a secret
ADMIN_EMAIL="admin@example.test"
SITE_TITLE="funnypot dev"
PLUGIN_SLUG="funnypot-wordpress"

cd /var/www/html

echo "[wp-init] waiting for WordPress core files + database..."
tries=0
until wp core is-installed >/dev/null 2>&1 || wp db check >/dev/null 2>&1; do
  tries=$((tries+1))
  # `wp db check` fails until the WP image has copied core + the DB is reachable; keep waiting.
  if [ "$tries" -gt 60 ]; then
    # Core files may exist but WP not installed yet — that's fine, fall through to install.
    [ -f wp-load.php ] && break
    echo "[wp-init] still waiting (attempt $tries)..."
  fi
  sleep 3
  [ -f wp-load.php ] && wp db check >/dev/null 2>&1 && break || true
done

if ! wp core is-installed >/dev/null 2>&1; then
  echo "[wp-init] installing WordPress core..."
  wp core install \
    --url="$WP_URL" \
    --title="$SITE_TITLE" \
    --admin_user="$ADMIN_USER" \
    --admin_password="$ADMIN_PASS" \
    --admin_email="$ADMIN_EMAIL" \
    --skip-email
else
  echo "[wp-init] WordPress already installed — ensuring the dev admin exists..."
  if ! wp user get "$ADMIN_USER" >/dev/null 2>&1; then
    wp user create "$ADMIN_USER" "$ADMIN_EMAIL" --role=administrator --user_pass="$ADMIN_PASS"
  fi
fi

echo "[wp-init] activating $PLUGIN_SLUG..."
if wp plugin activate "$PLUGIN_SLUG"; then
  echo "[wp-init] plugin active."
else
  echo "[wp-init] WARN: plugin activation failed (is vendor/ present in the mounted tree? run 'composer install' in the repo, then 'docker compose restart wpcli')." >&2
fi

# FP-0125 demo: arm the fake-panel tier so GET /phpmyadmin, /grafana, /kibana, /wp-login.php etc. render
# the RICH per-deploy decoy panels (attack_emulation), and arm the decoy session so a mock-login reveals
# the seeded breach panel. LOCAL demo box ONLY — the shipped plugin stays inert-by-default (this just
# flips the box's own settings so a human can browse the panels).
#
# actions.attack_class MUST be "deceive" (the shipped default is "block"): phpMyAdmin/pgAdmin panels
# classify as attack-class, and the plugin only runs the decoy-session gate on a DECEIVE decision — a
# block emits the 403 page and the gate never renders. scanner_probe already defaults to deceive (that
# is why /grafana works out of the box). This is a demo posture; a real deployment chooses its own bands.
echo "[wp-init] enabling fake-panel demo settings (attack_emulation + decoy session + attack_class=deceive)..."
wp option update honeypot_wp_settings '{"enabled":true,"posture":"honeypot","response_mode":"realistic","attack_emulation":true,"decoy_wp_login":true,"decoy_session_key":"funnypot-demo-decoy-session-key-0123456789abcdef","actions":{"clean":"allow","suspicious":"log","attack_class":"deceive","scanner_probe":"deceive"}}' --format=json >/dev/null 2>&1 \
  && echo "[wp-init] fake-panel demo settings applied." \
  || echo "[wp-init] WARN: could not apply demo settings." >&2

# The plugin's hit-store table is created on activation. A first-run activation can land before the DB
# is fully ready and skip the table create; capture then has no table to write to. Verify it exists and
# re-activate once if not. Idempotent and non-fatal — a persistent miss just logs a warning.
hits_table_exists() {
  local prefix
  prefix="$(wp config get table_prefix 2>/dev/null || echo wp_)"
  # A non-empty SHOW TABLES result means the table is present.
  [ -n "$(wp db query "SHOW TABLES LIKE '${prefix}honeypot_wp_hits'" --skip-column-names 2>/dev/null || true)" ]
}

if hits_table_exists; then
  echo "[wp-init] hits table present."
else
  echo "[wp-init] hits table missing after activation — re-activating once to force schema create..."
  wp plugin deactivate "$PLUGIN_SLUG" >/dev/null 2>&1 || true
  wp plugin activate "$PLUGIN_SLUG" >/dev/null 2>&1 || true
  if hits_table_exists; then
    echo "[wp-init] hits table present after re-activation."
  else
    echo "[wp-init] WARN: hits table still missing after re-activation — capture will degrade to a silent no-op until it exists." >&2
  fi
fi

echo "[wp-init] status:"
wp plugin list --fields=name,status,version 2>/dev/null | grep -i funnypot || true

echo ""
echo "[wp-init] READY -> $WP_URL/wp-admin/   (login: $ADMIN_USER / $ADMIN_PASS)"
echo "[wp-init] Funnypot settings: $WP_URL/wp-admin/options-general.php?page=honeypot-wp"
echo "[wp-init] Honeypot Intel:    Settings -> Honeypot -> Intel submenu"
