#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/tests/e2e"

for consumer in downstream-a downstream-b; do
  app="$E2E/fixtures/$consumer"
  cp "$app/.env.e2e" "$app/.env"
  mkdir -p "$app/storage/framework/cache/data" "$app/storage/framework/sessions" "$app/storage/framework/views" "$app/storage/logs" "$app/bootstrap/cache"
  composer install --working-dir="$app" --no-interaction --prefer-dist --no-progress
  composer reinstall dxs/laravel-auth --working-dir="$app" --no-interaction --prefer-dist --no-progress
done

npm install --prefix "$E2E" --no-audit --no-fund
npx --prefix "$E2E" playwright install chromium
npm test --prefix "$E2E"
