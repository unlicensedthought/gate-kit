// Package secrets is `gate-kit secrets`: credential literals must not enter
// the tree. Two layers:
//
//   - strict rules (strict.go): well-known token shapes (cloud access key ids,
//     GitHub and Slack tokens, PEM private key headers, sk- keys, a token in a
//     URL's userinfo), refused with no exemption at all;
//   - line rules (scan.go): an `Authorization: Bearer <40+ chars>` literal and
//     `sk-` provider keys, exempt when the line is a checksum or object-id line
//     or the value is a placeholder or shell expansion.
//
// There is no path allowlist: an allowlist is a hole a real secret can be parked
// in. Fixtures in tests are composed at runtime for that reason.
// A finding prints path:line, the rule and its description, never the value.
//
// Modes: --staged (default), --pre-push, --tree [rev], --selftest.
// Exit: 0 clean, 1 literal(s) found, 2 could not run or selftest failed.
package secrets

import (
	"fmt"
	"io"
	"strings"

	"github.com/unlicensedthought/gate-kit/internal/scansrc"
)

const tag = "[secrets]"

// Main is the `gate-kit secrets` entry point; it returns the process exit code.
func Main(args []string, stdin io.Reader, stderr io.Writer) int {
	mode, rev := "--staged", ""
	if len(args) > 0 {
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
		return selftest(stderr)
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
		fmt.Fprintln(stderr, tag+" usage: secrets [--staged|--pre-push|--tree [rev]|--selftest]")
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s COULD NOT RUN: cannot enumerate files (%s mode): %s\n", tag, mode, strings.TrimSpace(err.Error()))
		return 2
	}

	var all []hit
	nfiles := 0
	for _, snap := range snaps {
		for _, p := range snap.Paths {
			raw, err := snap.Read(p)
			if err != nil {
				fmt.Fprintf(stderr, "%s COULD NOT RUN: cannot read %s: %v\n", tag, p, err)
				return 2
			}
			nfiles++
			all = append(all, scanFile(snap.Label, p, raw)...)
		}
	}
	if len(all) > 0 {
		fmt.Fprintf(stderr, "\nERROR %s: credential literal(s) detected.\n\n", tag)
		for _, h := range all {
			fmt.Fprintf(stderr, "  %s:%d: %s: %s\n", h.path, h.line, h.rule, h.desc)
		}
		fmt.Fprintln(stderr, "\n  Reference secrets by name from a secret store; never as a literal in the tree.")
		fmt.Fprintln(stderr, "  If the value is already committed, rotate it: removing the line does not un-leak it.")
		fmt.Fprintf(stderr, "\n%s FAIL: %d hit(s) in %s mode\n", tag, len(all), mode)
		return 1
	}
	fmt.Fprintf(stderr, "%s OK: no credential literals (%s, %d file(s))\n", tag, mode, nfiles)
	return 0
}
