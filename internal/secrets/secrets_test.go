package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func rep(s string, n int) string { return strings.Repeat(s, n) }

// Every strict rule has a known-bad it must refuse and a near-miss it must pass.
// Values are composed at runtime, so this file holds no credential-shaped literal.
func TestStrictRules(t *testing.T) {
	xat := "x-access-" + "token:"
	cases := []struct {
		rule      string
		bad, good string
	}{
		{"aws-access-key", "AKIA" + rep("Q", 16), "AKIA" + rep("Q", 15)},
		{"github-token", "gh" + "p_" + rep("a", 36), "gh" + "p_" + rep("a", 35)},
		{"github-fine-grained-token", "github_" + "pat_" + rep("A1", 15), "github_" + "pat_short"},
		{"sk-secret-key", "sk-" + rep("Zq7", 10), "task-" + rep("Zq7", 10)},
		{"slack-token", "xox" + "b-" + rep("1", 12), "xox" + "b-" + rep("1", 9)},
		{"private-key-block", "-----BEGIN RSA PRIVATE" + " KEY-----", "-----BEGIN PUBLIC" + " KEY-----"},
		{"x-access-token-url", "https://" + xat + rep("q", 12) + "@h/o", "https://" + xat + "short" + "@h/o"},
	}
	if len(cases) != len(strictRules) {
		t.Fatalf("%d cases for %d strict rules: every rule needs a bad and a good fixture", len(cases), len(strictRules))
	}
	for _, c := range cases {
		if !has(scanStrict("", "f.txt", []byte(c.bad+"\n")), c.rule) {
			t.Errorf("%s: known-bad not refused", c.rule)
		}
		if h := scanStrict("", "f.txt", []byte(c.good+"\n")); len(h) != 0 {
			t.Errorf("%s: near-miss flagged: %+v", c.rule, h)
		}
	}
}

func has(hs []hit, rule string) bool {
	for _, h := range hs {
		if h.rule == rule {
			return true
		}
	}
	return false
}

// Strict rules have no exemption: a hash-context word, a lockfile name or a NUL
// byte elsewhere in the file does not hide a literal.
func TestStrictRulesHaveNoExemption(t *testing.T) {
	key := "AKIA" + rep("Q", 16)
	for name, raw := range map[string]string{
		"hash-context-line": "sha256 integrity checksum " + key,
		"binary-file":       "\x00\x00" + key,
	} {
		if !has(scanFile("", "package-lock.json", []byte(raw)), "aws-access-key") {
			t.Errorf("%s hid a literal from the strict rules", name)
		}
	}
}

func TestBearerLengthBoundary(t *testing.T) {
	line := func(n int) string { return "Authorization: Bearer " + rep("A", n) + "\n" }
	if !has(scanText("a.sh", line(40)), "bearer-literal") {
		t.Error("40-char bearer literal not refused")
	}
	if has(scanText("a.sh", line(39)), "bearer-literal") {
		t.Error("39-char bearer value refused")
	}
}

func TestLineRuleExemptions(t *testing.T) {
	long := rep("A1b2C3d4", 6)
	exempt := []string{
		"Authorization: Bearer $TOKEN_" + long,
		"Authorization: Bearer REDACTED" + long,
		"checksum Authorization: Bearer " + long,
		"Authorization: Bearer EXAMPLE" + long,
	}
	for _, l := range exempt {
		if h := scanText("a.sh", l+"\n"); len(h) != 0 {
			t.Errorf("exempt line flagged %+v: %q", h, l)
		}
	}
	// lockfiles are skipped by every line rule except provider-api-key
	if h := scanText("package-lock.json", "Authorization: Bearer "+long+"\n"); len(h) != 0 {
		t.Errorf("bearer rule ran on a lockfile: %+v", h)
	}
	if !has(scanText("package-lock.json", "k = sk-"+rep("Zq7", 10)+"\n"), "provider-api-key") {
		t.Error("provider key rule skipped a lockfile")
	}
}

func TestSelftestPasses(t *testing.T) {
	var b bytes.Buffer
	if rc := selftest(&b); rc != 0 {
		t.Fatalf("rc=%d: %s", rc, b.String())
	}
}

// A file that is not valid UTF-8 (Latin-1 text) is still scanned: a line-rule
// credential in it must not pass because of an unrelated accented byte.
func TestNonUTF8TextIsStillScanned(t *testing.T) {
	line := "Authorization: Bearer " + rep("A1b2C3d4", 6) + "\n"
	utf8Text := "café\n" + line
	latin1 := "caf\xe9\n" + line
	if !has(scanFile("", "n.txt", []byte(utf8Text)), "bearer-literal") {
		t.Fatal("control: the UTF-8 form is not caught")
	}
	if !has(scanFile("", "n.txt", []byte(latin1)), "bearer-literal") {
		t.Error("the Latin-1 form slipped past the line rules")
	}
	if h := scanFile("", "n.bin", []byte("\x00caf\xe9\n"+line)); has(h, "bearer-literal") {
		t.Error("a true binary (NUL) file is no longer skipped")
	}
}
