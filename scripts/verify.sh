#!/usr/bin/env bash
# Runs every gate of this repo. The last stdout line is
#   VERIFY {"verdict":"pass","gates":N}   or   VERIFY {"verdict":"fail","failed":"<step>"}
set -uo pipefail
cd "$(dirname "$0")/.."
gates=0
fail() { echo "VERIFY {\"verdict\":\"fail\",\"failed\":\"$1\"}"; exit 1; }
step() { # name, command...
  local name="$1"; shift
  echo "== $name"
  if "$@"; then gates=$((gates + 1)); else echo "step failed: $name" >&2; fail "$name"; fi
}
fmt_clean() { test -z "$(gofmt -l .)" || { gofmt -l . >&2; return 1; }; }

command -v go >/dev/null || fail "install: go not found"
step install   go mod download
step build     go build -o bin/gate-kit ./cmd/gate-kit
step vet       go vet ./...
step gofmt     fmt_clean
step test      go test -count=1 ./...
step selftest-secrets   ./bin/gate-kit secrets --selftest
step selftest-leak      ./bin/gate-kit leak --selftest
step selftest-token-url ./bin/gate-kit token-url --selftest
step mutants   scripts/mutants.sh
echo "VERIFY {\"verdict\":\"pass\",\"gates\":$gates}"
