// Package tokenurl is `gate-kit token-url`: refuse a git credential written
// into source text. It is a speed-bump, not a boundary: it pattern-matches the
// shape of an embedded credential so the bad pattern is not committed and then
// copy-pasted onward. doc.go lists what it catches and what it cannot.
//
// Modes: --staged (default; the index), --pre-push (every unpushed commit),
// --tree [rev], --selftest. Exit: 0 clean, 1 violation(s) or selftest failure,
// 2 could not run or unknown mode.
package tokenurl

import (
	"fmt"
	"io"
	"strings"

	"github.com/unlicensedthought/gate-kit/internal/scansrc"
)

var skipExt = []string{".png", ".jpg", ".gif", ".pdf", ".lock", ".ico", ".woff", ".woff2"}

func hasAnySuffix(s string, ps []string) bool {
	for _, p := range ps {
		if strings.HasSuffix(s, p) {
			return true
		}
	}
	return false
}

// Main is the `gate-kit token-url` entry point; it returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	mode, rev := "--staged", ""
	if len(args) > 0 && args[0] != "" {
		mode = args[0]
		if mode == "--tree" && len(args) > 1 {
			rev = args[1]
		}
	}
	g := scansrc.Git{}
	var snaps []scansrc.Snapshot
	var err error
	switch mode {
	case "--selftest":
		return selftest(stdout, stderr)
	case "--staged":
		var s scansrc.Snapshot
		s, err = g.Staged()
		snaps = []scansrc.Snapshot{s}
	case "--pre-push":
		snaps, err = g.PrePush(stdin)
	case "--tree":
		var s scansrc.Snapshot
		s, err = g.Tree(rev)
		snaps = []scansrc.Snapshot{s}
	default:
		fmt.Fprintf(stderr, "[token-url] FATAL: unknown mode %s (expected --staged|--pre-push|--tree|--selftest)\n", pyRepr(mode))
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "[token-url] COULD NOT RUN: %v\n", err)
		return 2
	}
	return scan(mode, snaps, stdout, stderr)
}

func scan(mode string, snaps []scansrc.Snapshot, stdout, stderr io.Writer) int {
	found, nfiles := 0, 0
	for _, s := range snaps {
		for _, f := range s.Paths {
			if hasAnySuffix(f, skipExt) {
				continue
			}
			raw, err := s.Read(f)
			if err != nil {
				fmt.Fprintf(stderr, "[token-url] COULD NOT RUN: cannot read %s: %v\n", f, err)
				return 2
			}
			nfiles++
			for _, h := range hits(pyDecode(raw)) {
				found++
				fmt.Fprintf(stderr, "[token-url] %s%s:%d [%s] %s\n", s.Label, f, h.ln, h.rule, rulesDoc[h.rule])
			}
		}
	}
	if found > 0 {
		fmt.Fprintf(stderr, "\n[token-url] FAIL: %d occurrence(s) of a shell-routed git credential pattern.\n", found)
		fmt.Fprintln(stderr, "[token-url] Fix: use a credential helper that reads the secret on stdin, and a clean remote URL.")
		return 1
	}
	fmt.Fprintf(stdout, "[token-url] OK (%s): %d file(s) scanned, no shell-routed git credential patterns.\n", mode, nfiles)
	return 0
}
