// Package leak is `gate-kit leak`: refuse content that carries a repo's own
// private identifiers.
//
// Two detectors, both per repo and both read from the commit being checked
// (`.gate-kit/leak.json`):
//
//   - a WORD LIST (`terms_file`, one term per line, `#` comments): the repo's
//     private names, matched case-insensitively and, unless `substring` is set,
//     only as whole alphanumeric runs. The list lives in the repo that owns it;
//     a finding names the term by its position in the list and NEVER prints the
//     term, so a refusal cannot itself spread what it refuses.
//   - PII SHAPES (`detectors`: email, us-phone, ssn), an email passes when its domain is an RFC 2606
//     documentation host or users.noreply.github.com, or its local part is
//     noreply / no-reply; a line carrying `gate:allow-line` is exempt from the
//     PII shapes (a reviewed fixture), never from the word list.
//
// With no config, or a config that enables nothing, the command exits 2: a
// leak gate with nothing to look for must not report a pass.
//
// Modes: --staged (the index), --pre-push (every unpushed commit's delta),
// --tree [rev], --selftest. Binary files (a NUL byte) are skipped. Exit 0
// clean, 1 findings, 2 could not run.
package leak

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/unlicensedthought/gate-kit/internal/scansrc"
)

// ConfigPath is the per-repo config, relative to the repository root.
const ConfigPath = ".gate-kit/leak.json"

// maxTermsBytes caps a word list a repo config names.
const maxTermsBytes = 1 << 20

const allowPragma = "gate:allow-line"

type config struct {
	TermsFile  string   `json:"terms_file"`
	Substring  bool     `json:"substring"`
	Detectors  []string `json:"detectors"`
	ExemptPath []string `json:"detector_exempt"` // path prefixes whose PII shapes are skipped (fixtures)
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})`)
	phoneRe = regexp.MustCompile(`(\(\d{3}\)\s?|\b\d{3}[-. ])\d{3}[-. ]\d{4}\b`)

	ssnRe = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
)

// sshRemote reports the scp-style or ssh:// git remote form, git@host:owner/repo or
// git@host/owner/repo: "git" there is the protocol's fixed login, not a mailbox. A bare
// git@host with no path after it is still reported.
func sshRemote(local, rest string) bool {
	return local == "git" && (strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "/")) && len(rest) > 1 && rest[1] != ' '
}

func reservedDomain(host string) bool {
	h := strings.ToLower(host)
	switch {
	case h == "example.com" || h == "example.org" || h == "example.net":
		return true
	case strings.HasSuffix(h, ".example"), strings.HasSuffix(h, ".invalid"), strings.HasSuffix(h, ".test"):
		return true
	case h == "users.noreply.github.com":
		return true
	}
	return false
}

type finding struct {
	path string
	line int
	rule string
	// pathTerm: the path itself holds a listed term, so no finding may print it.
	pathTerm bool
}

// Engine is the loaded detector set: the word list plus the enabled PII shapes.
type Engine = engine

// Hit is one finding. Line 0 is a whole-path finding.
type Hit struct {
	Path string
	Line int
	Rule string
	// WithholdPath is set when the path holds a private term; Report then never prints it.
	WithholdPath bool
}

type engine struct {
	cfg   config
	terms []string // lowercased
	pii   map[string]bool
}

func loadEngine(s scansrc.Snapshot) (*engine, error) {
	b, ok, err := s.Config(ConfigPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no %s at %s: a leak gate with nothing configured must not report a pass", ConfigPath, label(s))
	}
	return newEngine(s, b, false)
}

// NewEngine builds the engine from config bytes read elsewhere (a --config path);
// the word list is still read through s.
func NewEngine(s scansrc.Snapshot, cfg []byte) (*Engine, error) { return newEngine(s, cfg, true) }

// LoadEngine builds the engine from the repo's own .gate-kit/leak.json at s.
func LoadEngine(s scansrc.Snapshot) (*Engine, error) { return loadEngine(s) }

// trusted is true only for a config the operator supplied (--config). A config read from the
// repo being scanned may only name a word list inside that repo, never a path on the host.
func newEngine(s scansrc.Snapshot, b []byte, trusted bool) (*engine, error) {
	var c config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %v", ConfigPath, err)
	}
	e := &engine{cfg: c, pii: map[string]bool{}}
	for _, d := range c.Detectors {
		if d != "email" && d != "us-phone" && d != "ssn" {
			return nil, fmt.Errorf("%s: unknown detector %q", ConfigPath, d)
		}
		e.pii[d] = true
	}
	if c.TermsFile != "" {
		var tb []byte
		var ok bool
		var err error
		if !trusted && (filepath.IsAbs(c.TermsFile) || slices.Contains(strings.Split(filepath.ToSlash(c.TermsFile), "/"), "..")) {
			return nil, fmt.Errorf("%s: terms_file %q must be a path inside the repo (absolute paths and .. are accepted only from --config)", ConfigPath, c.TermsFile)
		}
		if filepath.IsAbs(c.TermsFile) {
			// A word list kept outside the repo (a 0600 temp file) is read as given: joining it
			// under the snapshot root looked for a path that never exists.
			tb, err = os.ReadFile(c.TermsFile)
			ok = err == nil
			if os.IsNotExist(err) {
				err = nil
			}
		} else {
			ok = true
			if trusted {
				tb, ok, err = s.Config(c.TermsFile)
			} else {
				tb, err = s.ReadRegular(c.TermsFile, maxTermsBytes)
			}
		}
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("terms_file %s not found at %s", c.TermsFile, label(s))
		}
		sc := bufio.NewScanner(bytes.NewReader(tb))
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if t != "" && !strings.HasPrefix(t, "#") {
				e.terms = append(e.terms, strings.ToLower(t))
			}
		}
	}
	if len(e.terms) == 0 && len(e.pii) == 0 {
		return nil, fmt.Errorf("%s enables no word list and no detector: nothing to look for", ConfigPath)
	}
	return e, nil
}

func label(s scansrc.Snapshot) string {
	switch s.Rev {
	case "":
		return "the index"
	case scansrc.Worktree:
		return "the working tree"
	}
	return s.Rev
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

// termIndex returns the 1-based index of the first listed term found in line.
func (e *engine) termIndex(line string) int {
	low := strings.ToLower(line)
	for i, t := range e.terms {
		from := 0
		for {
			at := strings.Index(low[from:], t)
			if at < 0 {
				break
			}
			at += from
			end := at + len(t)
			if e.cfg.Substring || ((at == 0 || !isAlnum(low[at-1])) && (end >= len(low) || !isAlnum(low[end]))) {
				return i + 1
			}
			from = at + 1
		}
	}
	return 0
}

func (e *engine) scan(p string, raw []byte) []finding {
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil
	}
	exempt := false
	for _, pre := range e.cfg.ExemptPath {
		exempt = exempt || strings.HasPrefix(p, pre)
	}
	var out []finding
	pathTerm := e.termIndex(p) > 0
	if pathTerm { // the path is committed content too
		out = append(out, finding{p, 0, fmt.Sprintf("term-in-path #%d", e.termIndex(p)), true})
	}
	for i, line := range strings.Split(string(raw), "\n") {
		n := i + 1
		if t := e.termIndex(line); t > 0 {
			out = append(out, finding{p, n, fmt.Sprintf("private-term #%d", t), pathTerm})
		}
		if exempt || strings.Contains(line, allowPragma) {
			continue
		}
		if e.pii["email"] {
			for _, ix := range emailRe.FindAllStringSubmatchIndex(line, -1) {
				local := strings.ToLower(strings.SplitN(line[ix[0]:ix[1]], "@", 2)[0])
				if reservedDomain(line[ix[2]:ix[3]]) || local == "noreply" || local == "no-reply" || sshRemote(local, line[ix[1]:]) {
					continue
				}
				out = append(out, finding{p, n, "PII: email address", pathTerm})
				break
			}
		}
		if e.pii["us-phone"] && phoneHit(line) {
			out = append(out, finding{p, n, "PII: US phone number", pathTerm})
		}
		if e.pii["ssn"] && ssnRe.MatchString(line) {
			out = append(out, finding{p, n, "PII: SSN-shaped number", pathTerm})
		}
	}
	return out
}

// Scan is the detector run over one file's bytes; a binary file yields nothing
// (callers that refuse binaries do so before this).
func (e *engine) Scan(p string, raw []byte) []Hit {
	var out []Hit
	for _, f := range e.scan(p, raw) {
		out = append(out, Hit{f.path, f.line, f.rule, f.pathTerm})
	}
	return out
}

// Report prints findings in the format every leak mode uses, then the summary line.
// A path that holds a private term is never printed, on any finding for that file.
func Report(stderr io.Writer, hits []Hit) {
	for _, f := range hits {
		path := f.Path
		if f.WithholdPath || strings.HasPrefix(f.Rule, "term-in-path") {
			path = "<path withheld>"
		}
		if f.Line > 0 {
			fmt.Fprintf(stderr, "gate-kit leak: BLOCK %s:%d: %s\n", path, f.Line, f.Rule)
		} else {
			fmt.Fprintf(stderr, "gate-kit leak: BLOCK %s: %s\n", path, f.Rule)
		}
	}
	fmt.Fprintf(stderr, "gate-kit leak: %d finding(s). Private terms are never printed; #N is the term's position in the repo's list.\n", len(hits))
}

// Main is the `gate-kit leak` entry point; it returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	mode, rev := "--staged", ""
	if len(args) > 0 {
		mode = args[0]
		if mode == "--tree" && len(args) > 1 {
			rev = args[1]
		}
	}
	if mode == "--selftest" {
		return selftest(stderr)
	}
	g := scansrc.Git{}
	var snaps []scansrc.Snapshot
	var err error
	switch mode {
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
		fmt.Fprintln(stderr, "usage: gate-kit leak [--staged|--pre-push|--tree [rev]|--selftest]")
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "gate-kit leak: COULD NOT RUN: %v\n", err)
		return 2
	}
	var all []finding
	files := 0
	for _, s := range snaps {
		if len(s.Paths) == 0 {
			continue // nothing in this snapshot to judge; config is only needed when there is
		}
		e, err := loadEngine(s)
		if err != nil {
			fmt.Fprintf(stderr, "gate-kit leak: COULD NOT RUN: %v\n", err)
			return 2
		}
		for _, p := range s.Paths {
			raw, err := s.Read(p)
			if err != nil {
				msg := err.Error()
				if e.termIndex(p) > 0 {
					msg = strings.ReplaceAll(msg, p, "<path withheld>")
				}
				fmt.Fprintf(stderr, "gate-kit leak: COULD NOT RUN: %s\n", msg)
				return 2
			}
			files++
			for _, f := range e.scan(p, raw) {
				f.path = s.Label + f.path
				all = append(all, f)
			}
		}
	}
	if len(all) == 0 {
		fmt.Fprintf(stderr, "gate-kit leak: OK (%s, %d file(s))\n", mode, files)
		return 0
	}
	hits := make([]Hit, len(all))
	for i, f := range all {
		hits[i] = Hit{f.path, f.line, f.rule, f.pathTerm}
	}
	Report(stderr, hits)
	return 1
}

// phoneHit reports a US phone number on the line. phoneRe alone also matched runs of decimal
// coordinates ("308.064 " + "1000" in SVG path data of a logo file). A match
// counts only when its two separators agree (the parenthesised form has one) and it is not part
// of a longer number: no digit or "." before it, and no "." followed by a digit after it.
func phoneHit(line string) bool {
	for _, ix := range phoneRe.FindAllStringIndex(line, -1) {
		m := line[ix[0]:ix[1]]
		if m[0] != '(' && m[3] != m[7] {
			continue
		}
		if ix[0] > 0 {
			if c := line[ix[0]-1]; c == '.' || (c >= '0' && c <= '9') {
				continue
			}
		}
		if ix[1]+1 < len(line) && line[ix[1]] == '.' && line[ix[1]+1] >= '0' && line[ix[1]+1] <= '9' {
			continue
		}
		return true
	}
	return false
}
