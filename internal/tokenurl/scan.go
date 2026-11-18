package tokenurl

// scan.go: the matcher. hits(text) returns every violation in one file's text.
//
// Each pattern is the original python3 `re` pattern with three mechanical
// rewrites, because RE2 is not Python `re`:
//   - `\s` / `\S` become pyWSClass / its negation (Python's is Unicode).
//   - under re.I, Python folds 'i' to I, U+0130 and U+0131; Go's (?i) folds it
//     to I only, so every 'i' in a case-insensitive pattern is spelled
//     [iİı]. ('k' and 's' fold identically in both: K/U+212A, S/U+017F.)
//   - the two patterns that need `\b` (RX_ASSIGN, the taint-use pattern) are
//     hand-written matchers below, since RE2 has no Unicode `\b`.
// Go's leftmost-first matching returns the same match a backtracking engine
// would, so capture groups agree with Python's for the regex-backed patterns.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	allowMarker = "token-url:allow"
	interpMark  = "INTERPOLATIONMARK"
	ws          = pyWSClass
	fi          = "[iİı]" // Python re.I's fold set for 'i'
)

var (
	rxSubst = regexp.MustCompile(`\$\([^()\n]*\)|` + "`[^`\\n]*`" + `|\$\{[^}\n]*\}`)

	rxInterp      = regexp.MustCompile(`(?:\$\(|\$\{|\$[A-Za-z_]|` + "`" + `|` + interpMark + `)`)
	rxToken       = regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{10,}|glpat-[A-Za-z0-9_\-]{8,}|xox[abposr]-[A-Za-z0-9\-]{8,})`)
	rxURLUserinfo = regexp.MustCompile(`(?i)https?://([^` + ws + `'"/@]{1,256})@`)
	rxGitCmd      = regexp.MustCompile(`(?i)(?:^|[` + ws + `;&|(){}` + "`" + `]|\$\()g` + fi + `t(?:[` + ws + `]|$)`)
	rxStandIn     = regexp.MustCompile(`<[^>]*>`)

	rxExtraHeader = regexp.MustCompile(`(?i)http\.(?:[^` + ws + `=]*\.)?extraheader[` + ws + `]*=[` + ws + `]*["']?[` + ws + `]*author` + fi + `zat` + fi + `on`)

	credHelperKey     = `(?i)credent` + fi + `al\.(?:[^` + ws + `=]*\.)?helper["']?[` + ws + `]*(?:=[` + ws + `]*|[` + ws + `]+)`
	rxShellCredHelper = regexp.MustCompile(credHelperKey + `["']?[` + ws + `]*!`)
	rxCredHelperValue = regexp.MustCompile(credHelperKey + `(?:'([^']*)'|"([^"]*)"|([^` + ws + `]+))`)
	rxInterpreter     = regexp.MustCompile(`(?:^|/)(?:sh|bash|zsh|dash|ksh|env|python3?|perl|ruby|node|awk)(?:[` + ws + `]|$)`)
	rxAnyWS           = regexp.MustCompile(`[` + ws + `]`)
)

func normalize(text string) string { return rxSubst.ReplaceAllLiteralString(text, interpMark) }

// credHelperValueIsShell: true when this credential.helper VALUE is executed
// as a shell command.
func credHelperValueIsShell(val string) bool {
	val = pyStrip(val)
	if val == "" {
		return false
	}
	if strings.HasPrefix(val, "!") {
		return true
	}
	if rxInterpreter.MatchString(val) {
		return true
	}
	// an absolute path carrying ARGUMENTS is a command line, not a helper path
	return strings.HasPrefix(val, "/") && rxAnyWS.MatchString(val)
}

// userinfoIsCredential: does this URL userinfo carry credential material?
// A documentation stand-in (<TOKEN>) is not.
func userinfoIsCredential(ui string) bool {
	if rxStandIn.MatchString(ui) {
		return false
	}
	if rxInterp.MatchString(ui) || rxToken.MatchString(ui) {
		return true
	}
	if i := strings.IndexByte(ui, ':'); i >= 0 {
		return pyStrip(ui[i+1:]) != ""
	}
	return false
}

func anyURLCredential(text string) bool {
	for _, m := range rxURLUserinfo.FindAllStringSubmatch(text, -1) {
		if userinfoIsCredential(m[1]) {
			return true
		}
	}
	return false
}

// assignSearch is re.search of
//
//	(?:^|[;&|(]|\bexport\s+|\blocal\s+|\bdeclare\s+(?:-\w+\s+)*)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$
//
// returning group 1 and group 2 of the first match. Given where the prefix
// ends, the tail has exactly one way to match (the identifier must be maximal,
// since an identifier char is neither \s nor '='), and every quantifier in the
// prefix is forced greedy for the same reason, so trying start positions in
// order and the alternatives in order reproduces Python's first match.
func assignSearch(s string) (name, rest string, ok bool) {
	r := []rune(s)
	n := len(r)
	skipWS := func(p int) int {
		for p < n && isPyWS(r[p]) {
			p++
		}
		return p
	}
	tail := func(p int) (string, string, bool) {
		p = skipWS(p)
		if p >= n || !isIdentStart(r[p]) {
			return "", "", false
		}
		q := p + 1
		for q < n && isIdentChar(r[q]) {
			q++
		}
		e := skipWS(q)
		if e >= n || r[e] != '=' {
			return "", "", false
		}
		return string(r[p:q]), string(r[e+1:]), true
	}
	keyword := func(st int, kw string) int { // \bkw\s+ ; -1 when absent
		if st > 0 && isPyWord(r[st-1]) {
			return -1
		}
		k := []rune(kw)
		if st+len(k) > n || string(r[st:st+len(k)]) != kw {
			return -1
		}
		p := st + len(k)
		if p >= n || !isPyWS(r[p]) {
			return -1
		}
		return skipWS(p)
	}
	for st := 0; st <= n; st++ {
		if st == 0 {
			if a, b, ok := tail(0); ok {
				return a, b, true
			}
		}
		if st < n && strings.ContainsRune(";&|(", r[st]) {
			if a, b, ok := tail(st + 1); ok {
				return a, b, true
			}
		}
		for _, kw := range []string{"export", "local"} {
			if p := keyword(st, kw); p >= 0 {
				if a, b, ok := tail(p); ok {
					return a, b, true
				}
			}
		}
		if p := keyword(st, "declare"); p >= 0 {
			for p+1 < n && r[p] == '-' && isPyWord(r[p+1]) { // (?:-\w+\s+)*
				q := p + 1
				for q < n && isPyWord(r[q]) {
					q++
				}
				if q >= n || !isPyWS(r[q]) {
					break
				}
				p = skipWS(q)
			}
			if a, b, ok := tail(p); ok {
				return a, b, true
			}
		}
	}
	return "", "", false
}

func isIdentStart(r rune) bool { return r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }
func isIdentChar(r rune) bool  { return isIdentStart(r) || r >= '0' && r <= '9' }

// taintedUse is re.search of `\$\{?(?:NAME1|NAME2|...)\b`: a '$', an optional
// '{', one tainted name, then a Unicode word boundary.
func taintedUse(text string, names []string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] != '$' {
			continue
		}
		p := i + 1
		if p < len(text) && text[p] == '{' {
			p++
		}
		for _, nm := range names {
			if !strings.HasPrefix(text[p:], nm) {
				continue
			}
			after := text[p+len(nm):]
			if after == "" {
				return true
			}
			if r, _ := utf8.DecodeRuneInString(after); !isPyWord(r) {
				return true
			}
		}
	}
	return false
}

type logicalLine struct {
	ln        int
	raw, norm string
	allowed   bool
}

// logicalLines joins backslash continuations. allowed is true if the allow
// marker appeared on ANY constituent raw line.
func logicalLines(text string) []logicalLine {
	var out []logicalLine
	buf, start, allowed := "", 0, false
	for i, line := range pySplitlines(text) {
		if start == 0 {
			start, buf, allowed = i+1, "", false
		}
		if strings.Contains(line, allowMarker) {
			allowed = true
		}
		stripped := pyRStrip(line)
		if strings.HasSuffix(stripped, `\`) && !strings.HasSuffix(stripped, `\\`) {
			buf += stripped[:len(stripped)-1] + " "
			continue
		}
		buf += line
		out = append(out, logicalLine{start, buf, "", allowed})
		start = 0
	}
	if start != 0 {
		out = append(out, logicalLine{start, buf, "", allowed})
	}
	for i := range out {
		out[i].norm = normalize(out[i].raw)
	}
	return out
}

const (
	ruleInline    = "git-cmd-with-inline-credential"
	ruleAssigned  = "credential-url-assigned-to-variable"
	ruleTainted   = "git-cmd-with-tainted-variable"
	ruleShellHelp = "git-inline-shell-credential-helper" // token-url:allow (rule name)
	ruleExtraHdr  = "http-extraheader-authorization"
)

var rulesDoc = map[string]string{
	ruleInline: "git invoked with credential material in the remote URL — the secret " +
		"lands in argv (ps/pgrep-readable).",
	ruleAssigned: "a variable is assigned a URL carrying credential material; the moment " +
		"it reaches a git remote it is in argv. Use a stdin-fed credential helper.",
	ruleTainted: "git invoked with a variable that was assigned a credential-bearing " +
		"URL in this file — the shell expands it into argv.",
	ruleShellHelp: "an inline shell credential helper (credential.helper=!<shell>) — the " + // token-url:allow token-in-url-gate:allow
		"snippet, and the secret-fetch inside it, sit in argv. Use the " +
		"path-valued helper that reads the secret on stdin.",
	ruleExtraHdr: "http.extraHeader puts the Authorization value in argv — equally leaky, " +
		"explicitly rejected. Use a stdin-fed credential helper.",
}

type hit struct {
	ln            int
	rule, snippet string
}

// hits returns every violation in one file's text, in line order.
func hits(text string) []hit {
	lls := logicalLines(text)
	tainted := map[string]int{} // varname -> lineno of the tainting assignment
	var names []string

	// Pass 1 — tainting assignments, whole-file and order-independent.
	for _, l := range lls {
		if l.allowed {
			continue
		}
		if nm, rest, ok := assignSearch(l.norm); ok && anyURLCredential(rest) {
			if _, seen := tainted[nm]; !seen {
				tainted[nm] = l.ln
				names = append(names, nm)
			}
		}
	}

	// Pass 2 — rules.
	var out []hit
	for _, l := range lls {
		if l.allowed {
			continue
		}
		rule := ""
		helperShell := false
		if m := rxCredHelperValue.FindStringSubmatchIndex(l.raw); m != nil {
			for g := 1; g <= 3; g++ {
				if m[2*g] >= 0 {
					helperShell = credHelperValueIsShell(l.raw[m[2*g]:m[2*g+1]])
					break
				}
			}
		}
		switch {
		case rxShellCredHelper.MatchString(l.raw) || helperShell:
			rule = ruleShellHelp
		case rxExtraHeader.MatchString(l.raw):
			rule = ruleExtraHdr
		case rxGitCmd.MatchString(l.norm) && anyURLCredential(l.norm):
			rule = ruleInline
		case len(names) > 0 && rxGitCmd.MatchString(l.raw) && taintedUse(l.raw, names):
			rule = ruleTainted
		default:
			if nm, _, ok := assignSearch(l.norm); ok {
				if at, seen := tainted[nm]; seen && at == l.ln {
					rule = ruleAssigned
				}
			}
		}
		if rule != "" {
			out = append(out, hit{l.ln, rule, pyStrip(l.raw)})
		}
	}
	return out
}
