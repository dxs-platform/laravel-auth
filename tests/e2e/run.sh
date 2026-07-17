#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/tests/e2e"
RUNTIME="$(mktemp -d "${TMPDIR:-/tmp}/dxs-laravel-auth-e2e.XXXXXX")"
PACKAGE="$RUNTIME/package"
ARTIFACTS="$RUNTIME/artifacts"

cleanup() {
  rm -rf "$RUNTIME"
}
trap cleanup EXIT

mkdir -p "$PACKAGE"
git -C "$ROOT" archive HEAD | tar -C "$PACKAGE" -xf -
mkdir -p "$ARTIFACTS"
php -r '$path=$argv[1]; $data=json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR); $data["version"]="0.2.0"; file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES).PHP_EOL);' "$PACKAGE/composer.json"
(cd "$PACKAGE" && zip -q -r "$ARTIFACTS/dxs-laravel-auth-0.2.0.zip" .)
ARTIFACT_SHA="$(shasum -a 256 "$ARTIFACTS/dxs-laravel-auth-0.2.0.zip" | cut -d' ' -f1)"
cp -R "$PACKAGE/tests/e2e/fixtures/downstream-a" "$RUNTIME/downstream-a"
cp -R "$PACKAGE/tests/e2e/fixtures/downstream-b" "$RUNTIME/downstream-b"

for consumer in downstream-a downstream-b; do
  app="$RUNTIME/$consumer"
  cp "$app/.env.e2e" "$app/.env"
  sed -i.bak "s|__PACKAGE_ARTIFACTS__|$ARTIFACTS|g" "$app/composer.json"
  rm "$app/composer.json.bak"
  mkdir -p "$app/storage/framework/cache/data" "$app/storage/framework/sessions" "$app/storage/framework/views" "$app/storage/logs" "$app/bootstrap/cache"
  composer install --working-dir="$app" --no-interaction --prefer-dist --no-progress
  composer show --working-dir="$app" dxs/laravel-auth --locked | grep -F 'versions : * 0.2.0'
done

echo "Immutable package artifact sha256: $ARTIFACT_SHA"

npm install --prefix "$E2E" --no-audit --no-fund
npx --prefix "$E2E" playwright install chromium
E2E_FIXTURES_DIR="$RUNTIME" npm test --prefix "$E2E" -- "$@"
