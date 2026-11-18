package tokenurl

// selftest.go: --selftest. Inline known-bad / known-good fixtures and the
// honesty ratchet over the embedded evasion corpus.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

//go:embed testdata/evasions.json
var corpusJSON []byte

// knownBad: every one of the reproduced bypasses is a permanent known-bad. If a
// future edit reopens one, --selftest goes red in pre-commit before the commit
// lands.
var knownBad = []string{
	// v1 fixtures (must stay caught)
	"git push https://x-access-token:$(vault get DEPLOY_TOKEN)@github.com/o/r.git",               // token-url:allow
	"git clone https://${GITHUB_TOKEN}@github.com/o/r.git",                                       // token-url:allow
	`git remote set-url origin "https://x-access-token:ghp_deadbeefdeadbeef@github.com/o/r.git"`, // token-url:allow gate:allow-line: test fixture
	`git -c http.extraHeader="Authorization: Basic eHl6" push origin main`,                       // token-url:allow token-in-url-gate:allow
	"git fetch https://user:`vault get TOK`@github.com/o/r",                                      // token-url:allow
	// BYPASS 1 — variable indirection across lines
	"URL=\"https://x-access-token:$(vault get DEPLOY_TOKEN)@github.com/o/r.git\"\ngit push \"$URL\" HEAD:refs/heads/wt/x", // token-url:allow
	// BYPASS 1b — the push is written BEFORE the assignment (order-independence)
	"git push \"$PUSH_URL\" HEAD:main\nPUSH_URL=\"https://x-access-token:${TOK}@github.com/o/r.git\"", // token-url:allow
	// BYPASS 2 — inline shell credential helper
	`git -c credential.helper='!f(){ echo password=$(vault get DEPLOY_TOKEN); };f' push origin HEAD`, // token-url:allow token-in-url-gate:allow
	`git config credential.helper "!echo password=$TOKEN"`,                                           // token-url:allow token-in-url-gate:allow
	`git -c CREDENTIAL.HELPER="!f(){ :; };f" fetch`,                                                  // token-url:allow token-in-url-gate:allow
	// ROUND-3 BYPASS — an ABSOLUTE-PATH / interpreter helper value, no '!' at all
	`git -c credential.helper='/bin/sh -c "echo password=$(vault get DEPLOY_TOKEN)"' push origin HEAD`, // token-url:allow token-in-url-gate:allow
	`git -c credential.helper="/usr/bin/env sh -c 'echo password=$TOK'" push origin HEAD`,              // token-url:allow token-in-url-gate:allow
	`git config credential.helper "/usr/bin/python3 /tmp/vend.py"`,                                     // token-url:allow token-in-url-gate:allow
	// an absolute-path helper with arguments that is not a named interpreter
	`git config credential.helper "/opt/tools/helper.sh --store"`, // token-url:allow token-in-url-gate:allow
	// ROUND-3 BYPASS — leading whitespace before the Authorization field name
	`git -c http.extraHeader=' Authorization: Basic eHl6' push origin main`, // token-url:allow token-in-url-gate:allow
	// BYPASS 3 — case
	`git -c http.extraheader="AUTHORIZATION: Basic eHl6" push origin main`,     // token-url:allow token-in-url-gate:allow
	`git -c HTTP.EXTRAHEADER="authorization: bearer x" push`,                   // token-url:allow token-in-url-gate:allow
	`git -c http.https://github.com.extraheader="Authorization: Basic x" push`, // token-url:allow token-in-url-gate:allow
	// BYPASS 4 — bare-token userinfo, no x-access-token username. Assembled at
	// run time so no whole token-shaped literal sits in this file.
	"git clone https://" + "ghp_" + "deadbeefdeadbeefdeadbeefdeadbeefdead" + "@github.com/o/r.git", // token-url:allow
	"git clone https://" + "github_pat_" + "11ABCDEFG0aBcDeFgHiJkL" + "@github.com/o/r.git",        // token-url:allow
	// BYPASS 5 — line-continuation split
	"git push \\\n  \"https://x-access-token:ghp_aaaabbbbccccddddeeeeffff@github.com/o/r.git\" \\\n  HEAD:main", // token-url:allow gate:allow-line: test fixture
	// continuation + indirection together
	"U=\"https://x-access-token:$(vault get T)@github.com/o/r.git\"\ngit \\\n  push \\\n  \"$U\"", // token-url:allow
}

var knownGood = []string{
	"git push -u origin wt/my-branch-123",
	`git clone -q "$MIRROR" "$dir"`,
	`git remote set-url origin "https://github.com/example-org/widgets.git"`,
	"bash scripts/install-credential-helper.sh",
	"run `git clone https://x-access-token:<GITHUB_TOKEN>@github.com/o/r.git`", // prose stand-in
	// the same stand-in outside backticks: the stand-in rule has to carry it, not the quoting
	"git clone https://x-access-" + "token:<GITHUB_TOKEN>@github.com/o/r.git",
	// the SANCTIONED wiring — a PATH-valued helper, not a shell snippet
	`git config --add "credential.https://github.com.helper" "$HELPER"`,
	"git config --global credential.https://github.com.helper /path/to/git-credential-store-helper.sh",
	// a bare path helper passed on the command line — sanctioned, no arguments
	"git -c credential.helper=/opt/tools/git-credential-store-helper.sh push origin HEAD",
	`git config --local "credential.https://github.com.helper" "$HELPER"`,
	// ordinary URLs with no userinfo
	"curl -fsSL https://github.com/o/r/releases/latest",
	"REPO_URL=\"https://github.com/example-org/widgets.git\"\ngit clone \"$REPO_URL\"",
	// an '@' in the PATH must not be read as userinfo
	"git clone https://github.com/o/r@v1.git", // gate:allow-line: test fixture
	// backslash continuation with nothing sensitive
	"git push \\\n  -u origin \\\n  wt/plain-branch",
	// extraHeader that is not Authorization
	`git -c http.extraHeader="X-Trace-Id: abc" push origin main`,
}

type corpusFile struct {
	Fixtures []struct {
		ID              string   `json:"id"`
		Shell           []string `json:"shell"`
		ScannerExpected string   `json:"scanner_expected"`
	} `json:"fixtures"`
}

func selftest(stdout, stderr io.Writer) int {
	var failures []string
	oneLine := func(s string) string { return strings.ReplaceAll(s, "\n", " <NL> ") }

	// 1. Inline fixtures: must stay caught / stay clean.
	for _, s := range knownBad {
		if len(hits(s)) == 0 {
			failures = append(failures, "KNOWN-BAD NOT CAUGHT: "+oneLine(s))
		}
	}
	for _, s := range knownGood {
		if h := hits(s); len(h) > 0 {
			failures = append(failures, fmt.Sprintf("KNOWN-GOOD FALSELY FLAGGED [%s]: %s", h[0].rule, oneLine(s)))
		}
	}

	// 2. THE HONESTY RATCHET. The permanent corpus records, per fixture,
	// whether THIS SCANNER catches it. Both directions are enforced:
	//   caught -> missed   a real regression; the scanner silently got weaker.
	//   missed -> caught   the scanner got better, but the corpus (and therefore
	//                      the documented coverage) now understates it.
	var corpus corpusFile
	if err := json.Unmarshal(corpusJSON, &corpus); err != nil {
		fmt.Fprintf(stderr, "[token-url] SELFTEST FAILED: the embedded evasion corpus does not parse: %v\n", err)
		return 1
	}
	caught, missed := 0, 0
	for _, fx := range corpus.Fixtures {
		body := strings.Join(fx.Shell, "")
		if body == "" {
			continue
		}
		actual := "missed"
		if len(hits(body)) > 0 {
			actual = "caught"
			caught++
		} else {
			missed++
		}
		if actual != fx.ScannerExpected {
			failures = append(failures, fmt.Sprintf(
				"CORPUS DRIFT %s: recorded scanner_expected=%s but this scanner "+
					"%s it. Fix the scanner, or update testdata/evasions.json in this same commit.",
				fx.ID, fx.ScannerExpected, strings.ToUpper(actual)))
		}
	}

	if len(failures) > 0 {
		fmt.Fprintln(stderr, "[token-url] SELFTEST FAILED")
		for _, f := range failures {
			fmt.Fprintln(stderr, "  "+f)
		}
		return 1
	}
	fmt.Fprintf(stdout, "[token-url] selftest OK (SPEED-BUMP): %d inline known-bad caught, "+
		"%d known-good clean.\n", len(knownBad), len(knownGood))
	total := caught + missed
	fmt.Fprintf(stdout, "[token-url] evasion corpus: %d/%d caught, %d recorded as KNOWN MISSES.\n", caught, total, missed)
	return 0
}
