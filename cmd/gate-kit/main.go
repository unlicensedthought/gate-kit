// gate-kit: three commit-time gates and the proof that each can fail.
//
//	gate-kit run [--staged|--pre-push|--tree [rev]]   all three gates
//	gate-kit secrets   [--staged|--pre-push|--tree [rev]|--selftest]
//	gate-kit leak      [--staged|--pre-push|--tree [rev]|--selftest]
//	gate-kit token-url [--staged|--pre-push|--tree [rev]|--selftest]
//
// Exit: 0 clean, 1 findings, 2 could not run (never a pass).
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/unlicensedthought/gate-kit/internal/leak"
	"github.com/unlicensedthought/gate-kit/internal/secrets"
	"github.com/unlicensedthought/gate-kit/internal/tokenurl"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

type gate struct {
	name string
	main func(args []string, stdin io.Reader, stdout, stderr io.Writer) int
}

var gates = []gate{
	{"secrets", func(a []string, in io.Reader, _, e io.Writer) int { return secrets.Main(a, in, e) }},
	{"leak", leak.Main},
	{"token-url", tokenurl.Main},
}

func usage(w io.Writer) int {
	fmt.Fprintln(w, "usage: gate-kit run [--staged|--pre-push|--tree [rev]]\n       gate-kit <secrets|leak|token-url> [--staged|--pre-push|--tree [rev]|--selftest]")
	return 2
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	if args[0] == "run" {
		return runAll(args[1:], stdin, stdout, stderr)
	}
	for _, g := range gates {
		if g.name == args[0] {
			return g.main(args[1:], stdin, stdout, stderr)
		}
	}
	return usage(stderr)
}

// runAll runs every gate over the same input. The worst exit wins: 2 over 1
// over 0, so a gate that could not run is never hidden by one that passed.
func runAll(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var in []byte
	if len(args) > 0 && args[0] == "--pre-push" {
		in, _ = io.ReadAll(stdin)
	}
	worst := 0
	for _, g := range gates {
		rc := g.main(args, bytes.NewReader(in), stdout, stderr)
		fmt.Fprintf(stderr, "gate-kit: %s exit %d\n", g.name, rc)
		if rc == 2 || (rc == 1 && worst == 0) {
			worst = rc
		}
	}
	return worst
}
