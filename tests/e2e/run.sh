#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/tests/e2e"
RUNTIME="$(mktemp -d "${TMPDIR:-/tmp}/dxs-laravel-auth-e2e.XXXXXX")"
PACKAGE="$RUNTIME/package"

cleanup() {
  rm -rf "$RUNTIME"
}
trap cleanup EXIT

mkdir -p "$PACKAGE"
git -C "$ROOT" archive HEAD | tar -C "$PACKAGE" -xf -
cp -R "$PACKAGE/tests/e2e/fixtures/downstream-a" "$RUNTIME/downstream-a"
cp -R "$PACKAGE/tests/e2e/fixtures/downstream-b" "$RUNTIME/downstream-b"

for consumer in downstream-a downstream-b; do
  app="$RUNTIME/$consumer"
  cp "$app/.env.e2e" "$app/.env"
  sed -i.bak "s|__PACKAGE_ROOT__|$PACKAGE|g" "$app/composer.json"
  rm "$app/composer.json.bak"
  mkdir -p "$app/storage/framework/cache/data" "$app/storage/framework/sessions" "$app/storage/framework/views" "$app/storage/logs" "$app/bootstrap/cache"
  composer install --working-dir="$app" --no-interaction --prefer-dist --no-progress
done

npm install --prefix "$E2E" --no-audit --no-fund
npx --prefix "$E2E" playwright install chromium
E2E_FIXTURES_DIR="$RUNTIME" npm test --prefix "$E2E"
