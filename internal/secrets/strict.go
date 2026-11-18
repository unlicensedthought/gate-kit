// Strict literal rules: well-known credential shapes. Unlike the line rules in
// scan.go they carry NO exemption: no hash-context skip, no placeholder skip,
// no length skip, lockfiles included. A token-shaped literal is refused even on
// a line that mentions "sha256". Every value is composed at runtime in tests,
// so this file holds no credential-shaped literal.
package secrets

import (
	"bytes"
	"regexp"
	"strings"
)

type strictRule struct {
	id, desc string
	re       *regexp.Regexp
}

var strictRules = []strictRule{
	{"aws-access-key", "AWS access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github-token", "GitHub token (gh[pousr]_)", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"github-fine-grained-token", "GitHub fine-grained token", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`)},
	{"sk-secret-key", "sk- API secret key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)},
	{"slack-token", "Slack token", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"private-key-block", "PEM private key header", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"x-access-token-url", "x-access-token userinfo in a URL", regexp.MustCompile(`x-access-token:[^@\s]{8,}@`)},
}

// scanStrict returns the strict-rule hits for one file's raw bytes. Lines are
// split on \n only.
func scanStrict(label, p string, raw []byte) []hit {
	var hits []hit
	for i, line := range strings.Split(string(raw), "\n") {
		for _, r := range strictRules {
			if r.re.MatchString(line) {
				hits = append(hits, hit{label + p, i + 1, r.id, r.desc})
			}
		}
	}
	return hits
}

// isBinaryProbe is the scan-skip test: a NUL in the first 8000 bytes.
func isBinaryProbe(raw []byte) bool { return bytes.IndexByte(raw[:min(len(raw), 8000)], 0) >= 0 }
