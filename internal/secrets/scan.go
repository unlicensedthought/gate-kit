// The line rules and the per-file scan. Go's regexp is RE2: it has no lookbehind,
// lookahead or Unicode \b, so every boundary the rules need is checked by hand
// on the neighbouring bytes/runes of a candidate match (see findFirst). A
// candidate that fails its boundary is retried one rune later, which yields the
// same leftmost match Python's backtracking search returns.
package secrets

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// hit is one finding: path:line rule — description.
type hit struct {
	path string
	line int
	rule string
	desc string
}

var lockfileNames = map[string]bool{
	"pnpm-lock.yaml": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "bun.lock": true, "bun.lockb": true, "Cargo.lock": true, "poetry.lock": true,
	"uv.lock": true, "Pipfile.lock": true, "composer.lock": true, "go.sum": true,
}

var (
	// HASH_CONTEXT, the half without \b. A line carrying any of these is a
	// checksum / integrity / object-id line, not a credential.
	reHashPlain = regexp.MustCompile(`(?i)(?:` + strings.Join([]string{
		"sha1", "sha256", "sha384", "sha512", "md5", "blake[23]",
		exemptLit("integrity"), "checksum", exemptLit("digest"),
		"resolved" + pyWS + "*[:=]", exemptLit("BUILD_COMMIT"), exemptLit("Content-MD5"),
	}, "|") + `)`)
	// HASH_CONTEXT, the \b-delimited words. Group 1 is `commit`, whose optional
	// _?sha / _?id suffix is resolved in hashWordAt.
	reHashWord = regexp.MustCompile(`(?i)(` + exemptLit("commit") + `)|(?:hash|etag|` +
		exemptLit("git") + `[_-]?sha|` + exemptLit("revision") + `|blob|tree)`)
	reCommitSuffix = regexp.MustCompile(`^(?i)(?:_?sha|_?` + exemptLit("id") + `)`)

	// EXPANSION: a value that is an expansion / template / placeholder.
	reExpansion = regexp.MustCompile(`(?:\$\{?[A-Za-z_(]|\$\(|%[A-Za-z_]+%|\{\{|<[A-Za-z_]|` +
		`REDACTED|PLACEHOLDER|EXAMPLE|YOUR[_-]|CHANGEME|FAKE|DUMMY|` +
		`\*\*\*|xxxx|XXXX|\.\.\.|…)`)

	// Bearer: 40+ chars of credential alphabet. `$`/`{`/`<` are NOT in the
	// class, so `Bearer $TOKEN`, `Bearer ${X}`, `Bearer $(bf get Y)` cannot
	// reach 40 chars.
	reBearer = regexp.MustCompile(`Authorization` + pyWS + `*[:=]` + pyWS + `*['"]?Bearer` + pyWS +
		`+([A-Za-z0-9_\-\.=+/]{40,})`)
	// sk-: Python's (?<![A-Za-z0-9]) is checked in skStart.
	reSK = regexp.MustCompile(`sk-(?:ant-|proj-|or-|live-|test-)?[A-Za-z0-9_\-]{20,}`)
)

// exemptLit quotes an ASCII literal for the hash-context exemption under (?i).
// The exemption must not be wider than what tools/verify/secrets.go (Go's own
// case folding) granted: Python's i/U+0130/U+0131 equivalence would let a line
// carrying a dotless-i "digest" hide a credential, so it is deliberately not
// applied here, whereas the refusal rules keep the wider pyFoldI.
func exemptLit(lit string) string { return regexp.QuoteMeta(lit) }

func isASCIIAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// findFirst returns the leftmost match of re in s whose span passes ok, as a
// submatch index slice in s's coordinates, or nil.
func findFirst(re *regexp.Regexp, s string, ok func(loc []int) bool) []int {
	for pos := 0; pos <= len(s); {
		loc := re.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			return nil
		}
		for k := range loc {
			if loc[k] >= 0 {
				loc[k] += pos
			}
		}
		if ok == nil || ok(loc) {
			return loc
		}
		_, w := utf8.DecodeRuneInString(s[loc[0]:])
		if w == 0 {
			w = 1
		}
		pos = loc[0] + w
	}
	return nil
}

func wordBefore(s string, i int) bool {
	if i == 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return isPyWord(r)
}

func wordAfter(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return isPyWord(r)
}

// hashWordAt is Python's \b(...)\b for the candidate at loc: Unicode word
// boundary on both sides, and for `commit` any of its suffixes may end it.
func hashWordAt(s string, loc []int) bool {
	if wordBefore(s, loc[0]) {
		return false
	}
	ends := []int{loc[1]}
	if loc[2] >= 0 { // commit(_?sha|_?id)?
		if m := reCommitSuffix.FindStringIndex(s[loc[1]:]); m != nil {
			ends = append([]int{loc[1] + m[1]}, ends...)
		}
	}
	for _, e := range ends {
		if !wordAfter(s, e) {
			return true
		}
	}
	return false
}

// hashStems: every HASH_CONTEXT alternative contains one of these after
// pyFold, so a line containing none cannot match and skips the regexes. This
// is a prefilter only (Go's regexp has no DFA; the case-folded alternation
// costs ~70% of a tree scan without it). It never changes a verdict.
var hashStems = []string{
	"sha", "md5", "blake", "integrity", "checksum", "digest", "resolved",
	"build_commit", "hash", "etag", "commit", "revision", "blob", "tree",
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func hashContext(line string) bool {
	if !containsAny(pyFold(line), hashStems) {
		return false
	}
	if reHashPlain.MatchString(line) {
		return true
	}
	return findFirst(reHashWord, line, func(loc []int) bool { return hashWordAt(line, loc) }) != nil
}

// lineRule is one single-line rule. match returns the value Python's
// `m.group(1) if m.groups() else m.group(0)` yields for the first match, and
// whether there was one.
type lineRule struct {
	id, desc string
	match    func(line string) (string, bool)
}

func valueOf(line string, loc []int, group int) (string, bool) {
	if loc == nil {
		return "", false
	}
	return line[loc[2*group]:loc[2*group+1]], true
}

var lineRules = []lineRule{
	{"bearer-literal", "Authorization: Bearer <40+ char literal>", func(l string) (string, bool) {
		if !strings.Contains(l, "Authorization") {
			return "", false
		}
		return valueOf(l, findFirst(reBearer, l, nil), 1)
	}},
	{"provider-api-key", "sk- prefixed provider API key", func(l string) (string, bool) {
		if !strings.Contains(l, "sk-") {
			return "", false
		}
		return valueOf(l, findFirst(reSK, l, func(loc []int) bool {
			return loc[0] == 0 || !isASCIIAlnum(l[loc[0]-1])
		}), 0)
	}},
}

func isLockfile(p string) bool {
	base := p[strings.LastIndexByte(p, '/')+1:] // os.path.basename
	return lockfileNames[base] || strings.HasSuffix(base, ".lock")
}

// scanText runs the line rules over every line of one text file.
func scanText(p, text string) []hit {
	var hits []hit
	lines := splitLines(text)
	lock := isLockfile(p)

	for i, line := range lines {
		if utf8.RuneCountInString(line) > 4000 { // minified bundles: skip, not credentials
			continue
		}
		if hashContext(line) {
			continue
		}
		for _, r := range lineRules {
			if lock && r.id != "provider-api-key" {
				continue
			}
			val, ok := r.match(line)
			if !ok || reExpansion.MatchString(val) {
				continue
			}
			hits = append(hits, hit{p, i + 1, r.id, r.desc})
		}
	}

	return hits
}

// scanFile is every secrets rule over one file: the strict rules (no exemption,
// so a NUL byte cannot hide a literal from them), then the line rules over text.
func scanFile(label, p string, raw []byte) []hit {
	out := scanStrict(label, p, raw)
	if isBinaryProbe(raw) {
		return out
	}
	// Text that is not UTF-8 (Latin-1, say) is decoded with replacement and scanned,
	// not skipped: an accented byte must not turn the line rules off.
	return append(out, scanText(label+p, strings.ToValidUTF8(string(raw), "\uFFFD"))...)
}
