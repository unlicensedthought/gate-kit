#!/usr/bin/env bash
# Mutation check: apply each mutant in scripts/mutants.json to a scratch copy and
# require `go test ./...` to FAIL. A mutant the tests do not notice is a gap.
# Last line: MUTANTS {"killed":K,"total":N}. Exit 1 if any mutant survives or cannot be applied.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
n=$(python3 -I -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$root/scripts/mutants.json")
killed=0
bad=0
for i in $(seq 0 $((n - 1))); do
  rm -rf "$work/src" && mkdir "$work/src"
  (cd "$root" && tar --exclude=.git -cf - .) | tar -xf - -C "$work/src"
  id=$(python3 -I - "$root/scripts/mutants.json" "$work/src" "$i" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1]))[int(sys.argv[3])]
p = sys.argv[2] + "/" + spec["file"]
s = open(p).read()
if s.count(spec["old"]) != 1:
    print("UNAPPLICABLE " + spec["id"]); sys.exit(3)
open(p, "w").write(s.replace(spec["old"], spec["new"]))
print(spec["id"])
PY
  )
  rc=$?
  if [ $rc -ne 0 ]; then echo "mutant $id: pattern not found exactly once"; bad=$((bad + 1)); continue; fi
  if ! (cd "$work/src" && go build ./... >/dev/null 2>&1); then echo "mutant $id: does not compile (invalid mutant)"; bad=$((bad + 1)); continue; fi
  if (cd "$work/src" && go test ./... >/dev/null 2>&1); then
    echo "SURVIVED  $id"; bad=$((bad + 1))
  else
    echo "killed    $id"; killed=$((killed + 1))
  fi
done
echo "MUTANTS {\"killed\":$killed,\"total\":$n}"
[ "$bad" -eq 0 ]
