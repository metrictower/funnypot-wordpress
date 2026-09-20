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

echo "[wp-init] status:"
wp plugin list --fields=name,status,version 2>/dev/null | grep -i funnypot || true

echo ""
echo "[wp-init] READY -> $WP_URL/wp-admin/   (login: $ADMIN_USER / $ADMIN_PASS)"
echo "[wp-init] Funnypot settings: $WP_URL/wp-admin/options-general.php?page=honeypot-wp"
echo "[wp-init] Honeypot Intel:    Settings -> Honeypot -> Intel submenu"
