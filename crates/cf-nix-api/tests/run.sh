#!/usr/bin/env bash
# Runs the integration tests: starts the Worker under `wrangler dev`, on a port
# and with local storage of its own, so a `wrangler dev` you're running is left
# alone; puts a throwaway signing key in its local Secrets Store; runs the
# tests against it; and stops it. Every key and token is made up and thrown
# away afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8789
URL=http://127.0.0.1:$PORT
STORE=00000000000000000000000000000000
PERSIST=.wrangler/integration
LOG=${CF_NIX_API_LOG:-$PWD/.wrangler/integration.log}
trap '[ -n "${DEV:-}" ] && kill "$DEV" 2>/dev/null; wait 2>/dev/null || true' EXIT

rm -rf "$PERSIST" && mkdir -p "$PERSIST"
# --value= keeps the key off a prompt; it's a throwaway, in a throwaway store.
wrangler secrets-store secret create "$STORE" --name signing-key --scopes workers \
  --value="$(nix key generate-secret --key-name cf-nix-test)" --persist-to "$PERSIST" >/dev/null

# The tests' issuer, as wrangler.toml trusts it, for the audience on this port.
PROVIDERS='[{"issuer":"http://127.0.0.1:8788","audience":"'"$URL"'","claims":[{"repository_owner_id":"100000001","ref":"refs/heads/main"}]}]'
wrangler dev --port "$PORT" --persist-to "$PERSIST" --var "CF_NIX_API_OIDC_PROVIDERS:$PROVIDERS" >"$LOG" 2>&1 &
DEV=$!
for _ in $(seq 120); do
  curl -s -o /dev/null "$URL/health/live" && break
  kill -0 "$DEV" 2>/dev/null || { cat "$LOG"; exit 1; }
  sleep 1
done

CF_NIX_API_URL="$URL" cargo test --features integration --test integration "$@"
