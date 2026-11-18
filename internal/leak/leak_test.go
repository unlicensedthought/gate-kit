package leak

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unlicensedthought/gate-kit/internal/scansrc"
)

func eng(substring bool, terms ...string) *engine {
	e := &engine{terms: terms, pii: map[string]bool{"email": true, "us-phone": true, "ssn": true}}
	e.cfg.Substring = substring
	return e
}

func rules(e *engine, p, text string) []string {
	var out []string
	for _, f := range e.scan(p, []byte(text)) {
		out = append(out, f.rule)
	}
	return out
}

// Each row is one input and the exact rules it must raise. Known-bad and known-good
// sit side by side so a loosened rule and a tightened one both change a row.
func TestDetectors(t *testing.T) {
	gm := "jane.roe" + "@gmail.com"
	cases := []struct {
		name, text string
		want       []string
	}{
		{"term", "we met with Zorblax today\n", []string{"private-term #1"}},
		{"term second in list", "ask Quuxington\n", []string{"private-term #2"}},
		{"term needs whole run", "zorblaxian and xzorblax\n", nil},
		{"term at line edges", "zorblax\n", []string{"private-term #1"}},
		{"email", "mail " + gm + " now\n", []string{"PII: email address"}},
		{"email example.com", "a@example.com\n", nil},
		{"email example.org uppercase", "a@Example.ORG\n", nil},
		{"email .example", "a@corp.example\n", nil},
		{"email .invalid", "a@corp.invalid\n", nil},
		{"email .test", "a@x.test\n", nil},
		{"email github noreply host", "<1+u@users.noreply.github.com>\n", nil}, // gate:allow-line: test fixture
		{"email noreply local", "from noreply@vendor.io\n", nil},
		{"email No-Reply local", "from No-Reply@vendor.io\n", nil},
		{"git ssh remote", "git clone git@github.com:o/r.git\n", nil},                     // gate:allow-line: test fixture
		{"bare git@host", "contact git@github.com now\n", []string{"PII: email address"}}, // gate:allow-line: test fixture
		{"phone parens", "call (555) 123-" + "4567\n", []string{"PII: US phone number"}},
		{"phone dashes", "call 555-123-" + "4567\n", []string{"PII: US phone number"}},
		{"phone dots", "call 555.123." + "4567\n", []string{"PII: US phone number"}},
		{"phone spaces", "call 555 123 " + "4567\n", []string{"PII: US phone number"}},
		{"phone too short", "call 123-4567\n", nil},
		{"ssn", "id 123-45-6789\n", []string{"PII: SSN-shaped number"}}, // gate:allow-line: test fixture
		{"ssn inside longer digits", "id 9123-45-67890\n", nil},
		{"pragma exempts PII", "id 123-45-6789 gate:allow-line\n", nil},
		{"pragma never exempts a term", "Zorblax gate:allow-line\n", []string{"private-term #1"}},
		{"second line", "fine\nfine\ncall 555-123-" + "4567\n", []string{"PII: US phone number"}},
	}
	e := eng(false, "zorblax", "quuxington")
	for _, c := range cases {
		got := rules(e, "x.txt", c.text)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSubstringOption(t *testing.T) {
	if got := rules(eng(true, "zorblax"), "x.txt", "zorblaxian\n"); len(got) != 1 {
		t.Errorf("substring mode missed an embedded term: %v", got)
	}
}

func TestPathAndBinary(t *testing.T) {
	e := eng(false, "zorblax")
	if got := rules(e, "docs/zorblax-plan.md", "ok\n"); len(got) != 1 || !strings.HasPrefix(got[0], "term-in-path") {
		t.Errorf("term in path: %v", got)
	}
	if got := rules(e, "x.bin", "\x00 zorblax\n"); len(got) != 0 {
		t.Errorf("binary file scanned: %v", got)
	}
}

func TestExemptPathSkipsPIIButNotTerms(t *testing.T) {
	e := eng(false, "zorblax")
	e.cfg.ExemptPath = []string{"fixtures/"}
	if got := rules(e, "fixtures/a.txt", "call 555-123-"+"4567\nZorblax\n"); len(got) != 1 || got[0] != "private-term #1" {
		t.Errorf("exempt path: %v", got)
	}
}

func TestSelftestPasses(t *testing.T) {
	var b strings.Builder
	if rc := selftest(&b); rc != 0 {
		t.Fatalf("rc=%d %s", rc, b.String())
	}
}

// A repo's own config may only name a word list inside the repo.
func TestRepoConfigCannotNameAHostPath(t *testing.T) {
	for _, tf := range []string{"/etc/passwd", "../outside.txt", "a/../../b"} {
		cfg := []byte(`{"terms_file":"` + tf + `"}`)
		if _, err := newEngine(scansrc.Snapshot{}, cfg, false); err == nil || !strings.Contains(err.Error(), "inside the repo") {
			t.Errorf("repo config with terms_file %q was accepted (err=%v)", tf, err)
		}
	}
	if _, err := newEngine(scansrc.Snapshot{}, []byte(`{"terms_file":"/nonexistent/terms"}`), true); err != nil && strings.Contains(err.Error(), "inside the repo") {
		t.Errorf("an operator-supplied absolute terms_file was refused as a repo path: %v", err)
	}
}

// A term in a file path must not be printed by way of the path.
func TestTermInPathReportWithholdsThePath(t *testing.T) {
	var b bytes.Buffer
	Report(&b, []Hit{{Path: "docs/zorblax-notes.md", Rule: "term-in-path #1"}, {Path: "a.txt", Line: 3, Rule: "private-term #1"}})
	if strings.Contains(b.String(), "zorblax") {
		t.Fatalf("report printed the term through the path:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "a.txt:3") {
		t.Fatalf("an ordinary finding lost its path:\n%s", b.String())
	}
}

// A path that holds a term is withheld on EVERY finding for the file, not only the
// term-in-path one: a phone shape in the content must not print the path.
func TestPathWithTermIsWithheldOnEveryFinding(t *testing.T) {
	e := eng(false, "zorblax")
	hits := e.Scan("docs/zorblax-notes.md", []byte("call (555) 123-"+"4567\nZorblax again\n"))
	if len(hits) < 3 {
		t.Fatalf("want term-in-path, phone and term hits, got %+v", hits)
	}
	var b bytes.Buffer
	Report(&b, hits)
	if strings.Contains(strings.ToLower(b.String()), "zorblax") {
		t.Fatalf("a finding printed the term through the path:\n%s", b.String())
	}
}

func repo(t *testing.T) (string, func(args ...string)) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	return dir, run
}

// The path that cannot be read must not be named with its term in the error.
func TestUnreadablePathErrorWithholdsTheTerm(t *testing.T) {
	dir, run := repo(t)
	if err := os.WriteFile(filepath.Join(dir, "terms.txt"), []byte("zorblax\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".gate-kit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gate-kit/leak.json"), []byte(`{"terms_file":"terms.txt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "zorblax.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	// Unreadable, not deleted: a file deleted from the working tree is left out.
	unreadable := filepath.Join(dir, "zorblax.txt")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o644) })
	if _, err := os.ReadFile(unreadable); err == nil {
		t.Skip("file mode 0 is still readable here (running as root?)")
	}
	t.Chdir(dir)
	var out, errb bytes.Buffer
	rc := Main([]string{"--tree"}, strings.NewReader(""), &out, &errb)
	if rc != 2 {
		t.Errorf("rc=%d, want 2 (could not run)\n%s", rc, errb.String())
	}
	if strings.Contains(strings.ToLower(errb.String()), "zorblax") {
		t.Errorf("the error printed the term through the path:\n%s", errb.String())
	}
}

// A repo config's relative terms_file may not reach a host file through a symlink,
// in the working tree or as a symlink blob in the index or a commit.
func TestTermsFileSymlinkOutsideTheRepoIsRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("hostsecretword\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Dir(outside)
	dir, run := repo(t)
	if err := os.Symlink(outside, filepath.Join(dir, "terms.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outDir, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`{"terms_file":"terms.txt"}`)
	g := scansrc.Git{Dir: dir}
	wt := scansrc.Snapshot{G: g, Rev: scansrc.Worktree}
	if _, err := newEngine(wt, cfg, false); err == nil {
		t.Error("worktree: a symlinked terms_file pointing outside the repo was accepted")
	}
	if _, err := newEngine(wt, []byte(`{"terms_file":"linkdir/outside.txt"}`), false); err == nil {
		t.Error("worktree: a terms_file under a symlinked directory pointing outside was accepted")
	}
	run("add", "terms.txt")
	idx, err := g.Staged()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newEngine(idx, cfg, false); err == nil {
		t.Error("index: a symlink blob as terms_file was accepted")
	}
	run("commit", "-q", "-m", "x")
	tree, err := g.Tree("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newEngine(tree, cfg, false); err == nil {
		t.Error("tree: a symlink blob as terms_file was accepted")
	}
}

func TestTermsFileOverOneMiBIsRefused(t *testing.T) {
	dir, _ := repo(t)
	big := bytes.Repeat([]byte("a\n"), (1<<20)/2+1)
	if err := os.WriteFile(filepath.Join(dir, "terms.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	wt := scansrc.Snapshot{G: scansrc.Git{Dir: dir}, Rev: scansrc.Worktree}
	if _, err := newEngine(wt, []byte(`{"terms_file":"terms.txt"}`), false); err == nil {
		t.Error("a terms_file over 1 MiB was read")
	}
	if err := os.WriteFile(filepath.Join(dir, "terms.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newEngine(wt, []byte(`{"terms_file":"terms.txt"}`), false); err != nil {
		t.Errorf("an ordinary in-repo terms_file was refused: %v", err)
	}
}
