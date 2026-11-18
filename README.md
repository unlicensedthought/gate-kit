# gate-kit

Three commit-time gates in Go, each shipped with the evidence that it can fail.

| Gate | Refuses |
|---|---|
| `secrets` | credential literals: cloud access key ids, GitHub and Slack tokens, PEM private key headers, `sk-` keys, a token in a URL's userinfo, a long `Authorization: Bearer` literal |
| `leak` | a repo's own private terms (from a word list you supply) and PII shapes: email, US phone number, SSN |
| `token-url` | a git credential written into a script or doc: token in a remote URL, shell credential helpers, `http.extraHeader` Authorization |

A gate that has never been seen to fail is a guess. This repo keeps four kinds of evidence:

- **Selftests.** `gate-kit <gate> --selftest` feeds each gate known-bad and known-good input and exits non-zero if either verdict is wrong.
- **Golden files.** `cmd/gate-kit/testdata/golden/` holds the exit code and output of 40 end-to-end cases. Each one builds a throwaway git repository, stages the input and runs the real entry point.
- **A recorded evasion corpus.** `internal/tokenurl/testdata/evasions.json` lists evasions that beat an earlier version of the token-URL scanner. The selftest fails if a recorded catch is lost *or* a recorded miss starts being caught, so the list of known blind spots cannot drift.
- **Mutants.** `scripts/mutants.json` lists 33 small breakages of the gate code. `scripts/mutants.sh` applies each to a scratch copy and requires the test suite to fail.

## Quick start

Needs Go 1.25+ and git. `scripts/mutants.sh` also needs python3.

```sh
go build -o bin/gate-kit ./cmd/gate-kit

# pre-commit hook
printf '#!/bin/sh\nexec gate-kit run --staged\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# pre-push hook (reads git's pre-push stdin; scans every unpushed commit)
printf '#!/bin/sh\nexec gate-kit run --pre-push\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push

gate-kit secrets --tree        # audit every tracked file
gate-kit token-url --staged    # one gate
```

Modes: `--staged` (default), `--pre-push`, `--tree [rev]`, `--selftest`.
Exit codes: `0` clean, `1` findings, `2` could not run. A gate that cannot run never reports a pass.

### Configuring `leak`

`leak` needs `.gate-kit/leak.json` in the repo, read from the commit being checked (not the working tree), so loosening it is itself a reviewed diff:

```json
{
  "terms_file": ".gate-kit/terms.txt",
  "detectors": ["email", "us-phone", "ssn"],
  "detector_exempt": ["testdata/"]
}
```

`terms.txt` holds one private term per line (`#` comments). Terms match case-insensitively as whole alphanumeric runs unless `"substring": true`. A finding names the term by its position in the list (`private-term #2`) and never prints it, so a refusal cannot spread what it refuses. If a file's *path* holds a term, the path is withheld (`<path withheld>`) on every finding for that file and in error messages, not only on the `term-in-path` finding. A repo's own `terms_file` must be a regular file of at most 1 MiB inside the repo: in the working tree it is resolved through symlinks and refused if it lands outside the repo top; read from the index or a commit, a symlink or submodule entry is refused. With no config, or a config that enables nothing, `leak` exits 2.

Escape hatches, deliberately narrow: a line containing `gate:allow-line` is exempt from the PII shapes (never from the word list); a line containing `token-url:allow` is skipped by `token-url`. `secrets` has no allowlist at all.

## How it works

`internal/scansrc` is the one place that decides what to read (index blobs are addressed as `:0:<path>`, so a staged file named like `1:a.txt` is not reparsed by git as a stage number; a listed path that cannot be read is exit 2, never "missing"): the index, every unpushed commit of a pre-push (not just the tip, because a secret added and then removed inside one push is still in the history being pushed), or a revision's tree. Gates supply only a per-file verdict.

- **secrets**: seven strict regex rules with no exemptions (a token-shaped literal is refused even on a line that mentions `sha256`), plus two line rules (`Bearer` literal, `sk-` key) that skip checksum lines and placeholder or shell-expansion values. Go's RE2 has no lookbehind, so boundaries are checked by hand on the neighbouring bytes.
- **leak**: word list plus three PII shapes. An email passes if its domain is a reserved documentation domain, `users.noreply.github.com`, or its local part is `noreply`; `git@host:path` remotes are not emails. The phone check is the regex plus three guards (see below).
- **token-url**: joins backslash continuations, normalises shell substitutions, follows one hop of variable taint, and classifies a URL by the shape of its userinfo. A refusal prints only the file, line and rule, never the line itself, so a credential is not echoed into a terminal or a CI log. The leak gate also withholds a path that contains a private term, and a repo's own config may only name a word list inside the repo.

### The phone false positive

The first phone regex matched `308.064 1000` in SVG path data. `phoneHit` now accepts a match only when its two separators agree, nothing numeric or `.` precedes it, and no `.digit` follows it. `TestPhoneHitSkipsDecimalCoordinates` holds the coordinates that must pass and the real formats that must still be caught. `TestRawPhoneRegexMatchesCoordinates` pins that the raw regex still matches the coordinates, so the guards cannot become dead code unnoticed.

## Limits

- `token-url` is a speed-bump, not a boundary. It reads text. See `internal/tokenurl/doc.go` and the four recorded misses in `testdata/evasions.json`. The real control is a credential helper that feeds git the secret on stdin.
- `secrets` matches shapes. A secret with no recognisable shape, or one split across lines or encoded, is not seen.
- `leak` is only as good as your word list, and its PII shapes are US-centric.
- Gates read files as text; binary files (a NUL byte) are skipped by `leak`, and `secrets` skips lines over 4000 characters in its line rules (strict rules still run). `secrets` skips only true binaries (a NUL in the first 8000 bytes); text that is not valid UTF-8 is decoded with replacement and scanned.
- Anyone who runs `git commit --no-verify` skips all of it. Run the same command in CI.

## Tests

```sh
scripts/verify.sh        # install, build, vet, gofmt, tests, three selftests, mutants
go test ./...            # tests only
GATE_KIT_UPDATE=1 go test ./cmd/...   # rewrite golden files; read the diff before committing
```

`scripts/verify.sh` prints `VERIFY {"verdict":"pass","gates":N}` as its last line, or `VERIFY {"verdict":"fail","failed":"<step>"}`.

Most credential-shaped fixtures are composed at runtime. Not all: the `token-url` selftest and evasion corpus hold the banned shapes verbatim, and the selftests hold PII-shaped text, so running these gates over this repository's own tree reports findings in those files (checked: `secrets --tree` 4, `leak --tree` 34, with the example config used in the check). If you vendor this repo, exempt those paths.

## License

Apache-2.0. Copyright 2026 Adam Scheurer.
