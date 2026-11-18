package tokenurl

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// userinfo is composed at runtime so no credential-in-URL literal sits in this file.
func userinfo(secret string) string { return "x-access-" + "token:" + secret + "@" }

// TestFixtures: every known-bad yields a hit, every known-good yields none.
func TestFixtures(t *testing.T) {
	for _, s := range knownBad {
		if len(hits(s)) == 0 {
			t.Errorf("known-bad not caught: %q", s)
		}
	}
	for _, s := range knownGood {
		if h := hits(s); len(h) != 0 {
			t.Errorf("known-good flagged [%s]: %q", h[0].rule, s)
		}
	}
}

// TestRules pins the rule each shape is attributed to and its line number.
func TestRules(t *testing.T) {
	cases := []struct {
		in   string
		ln   int
		rule string
	}{
		{"git push https://" + userinfo("$(vault get T)") + "github.com/o/r.git", 1, ruleInline},
		{"x=1\nURL=\"https://u:${T}@h/o/r\"\ngit push \"$URL\"", 2, ruleAssigned},
		{"git push \"$URL\"\nURL=\"https://u:${T}@h/o/r\"", 1, ruleTainted},
		{"git config credential.helper \"!echo x\"", 1, ruleShellHelp},
		{"git -c http.extraHeader=\"Authorization: x\" push", 1, ruleExtraHdr},
		{"export U=\"https://u:$T@h/o\"", 1, ruleAssigned},                     // token-in-url-gate:allow
		{"declare -x -r U=\"https://u:$T@h/o\"", 1, ruleAssigned},              // token-in-url-gate:allow
		{"git -c http.extraHeader=\"AUTHORİZATION: x\" push", 1, ruleExtraHdr}, // re.I folds İ to i
		{"git push \\\n  \"https://u:$(vault get T)@h/o\"", 1, ruleInline},
	}
	for _, c := range cases {
		h := hits(c.in)
		if len(h) == 0 || h[0].ln != c.ln || h[0].rule != c.rule {
			t.Errorf("%q: got %+v, want line %d [%s]", c.in, h, c.ln, c.rule)
		}
	}
	if h := hits("git push \\\n \"https://u:$T@h/o\" # " + allowMarker); len(h) != 0 {
		t.Errorf("allow marker on a continuation line was not honoured: %+v", h)
	}
	// a tainted name followed by a word char is not a use of that name
	if h := hits("URL=\"https://u:$T@h/o\" # " + allowMarker + "\ngit push \"$URLX\""); len(h) != 0 {
		t.Errorf("$URLX treated as a use of URL: %+v", h)
	}
}

func TestPyText(t *testing.T) {
	if got := pySplitlines("a\r\nb\x0bc\u2028d\n"); !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
		t.Errorf("splitlines: %q", got)
	}
	if got := pyDecode([]byte("a\xe2\x82b\xffc\r\nd\re")); got != "a�b�c\nd\ne" {
		t.Errorf("decode: %q", got)
	}
	if got := pyStrip("　 x "); got != "x" {
		t.Errorf("strip: %q", got)
	}
}

// TestSelftest drives the real --selftest, including the corpus ratchet.
func TestSelftest(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := selftest(&out, &errb); rc != 0 {
		t.Fatalf("selftest exit %d\n%s%s", rc, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "evasion corpus: 8/12 caught, 4 recorded as KNOWN MISSES") {
		t.Fatalf("unexpected selftest output:\n%s", out.String())
	}
}

func TestUnknownMode(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := Main([]string{"--bogus"}, strings.NewReader(""), &out, &errb); rc != 2 ||
		!strings.Contains(errb.String(), "unknown mode '--bogus'") {
		t.Fatalf("rc=%d stderr=%s", rc, errb.String())
	}
}

// The corpus ratchet works in both directions: a recorded 'caught' that stops
// being caught, and a recorded 'missed' that starts being caught, are both failures.
func TestCorpusDriftIsAFailure(t *testing.T) {
	old := corpusJSON
	defer func() { corpusJSON = old }()
	corpusJSON = bytes.Replace(old, []byte(`"scanner_expected": "missed"`), []byte(`"scanner_expected": "caught"`), 1)
	var out, errb bytes.Buffer
	if rc := selftest(&out, &errb); rc != 1 || !strings.Contains(errb.String(), "CORPUS DRIFT") {
		t.Fatalf("a missed->caught flip was not reported: rc=%d %s", rc, errb.String())
	}
	corpusJSON = bytes.Replace(old, []byte(`"scanner_expected": "caught"`), []byte(`"scanner_expected": "missed"`), 1)
	out.Reset()
	errb.Reset()
	if rc := selftest(&out, &errb); rc != 1 || !strings.Contains(errb.String(), "CORPUS DRIFT") {
		t.Fatalf("a caught->missed flip was not reported: rc=%d %s", rc, errb.String())
	}
}
