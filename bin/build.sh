#!/usr/bin/env bash
# Build a self-contained plugin zip: composer install --no-dev with policy + core + funnypot-mainnet-client
# resolved from the path repos (or published VCS repos), then zip the plugin with vendor/ bundled.
# funnypot-core must stay resolvable anonymously (a public repo) for a token-free build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
STAGE="$BUILD/funnypot-wordpress"

echo "==> clean"
rm -rf "$BUILD"
mkdir -p "$STAGE"

echo "==> composer install (no dev)"
cd "$ROOT"
composer install --no-dev --optimize-autoloader --no-interaction

echo "==> stage plugin files"
cp -R \
  "$ROOT/funnypot-wordpress.php" \
  "$ROOT/mu-entry.php" \
  "$ROOT/README.md" \
  "$ROOT/composer.json" \
  "$ROOT/src" \
  "$STAGE/"
# Dereference the path-repo symlinks so the bundled vendor/ carries real files (distributable).
cp -RL "$ROOT/vendor" "$STAGE/vendor"

echo "==> sanity: bundled dependency packages present"
for pkg in funnypot-policy funnypot-core funnypot-mainnet-client; do
  if [ ! -d "$STAGE/vendor/metrictower/$pkg" ]; then
    echo "ERROR: vendor/metrictower/$pkg missing from the bundle" >&2
    exit 1
  fi
done
if ! ls "$STAGE"/vendor/metrictower/funnypot-core/resources/compiled/*.php >/dev/null 2>&1; then
  echo "WARNING: core rules artifact not found in the bundle" >&2
fi

echo "==> zip"
cd "$BUILD"
zip -qr "funnypot-wordpress.zip" "funnypot-wordpress"
echo "==> built $BUILD/funnypot-wordpress.zip"

echo "==> restore dev dependencies"
cd "$ROOT"
composer install --no-interaction >/dev/null 2>&1 || true
