package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every case builds a throwaway git repository, stages known-bad or known-good
// content, runs the real gate entry point and compares exit code and output with a
// golden file in testdata/golden. Regenerate with GATE_KIT_UPDATE=1, then read the diff.
// Fixture credentials are composed at runtime, so no token-shaped literal is in this
// file and the golden files hold only paths, line numbers and rule names.

const leakCfg = `{"terms_file":"terms.txt","detectors":["email","us-phone","ssn"]}`

func fx() map[string]string {
	rep := func(s string, n int) string { return strings.Repeat(s, n) }
	return map[string]string{
		"aws":     "key_id = AKIA" + rep("Q", 16) + "\n",
		"github":  "token: gh" + "p_" + rep("a", 36) + "\n",
		"pem":     "-----BEGIN RSA PRIVATE" + " KEY-----\n",
		"sk":      "api = 'sk-" + rep("Zq7", 10) + "'\n",
		"slack":   "hook = xox" + "b-" + rep("1", 12) + "\n",
		"bearer":  "curl -H 'Authorization: Bearer " + rep("A1b2C3d4", 6) + "' https://api.example.com\n",
		"urltok":  "remote = https://x-access-token:" + rep("q", 12) + "@github.com/o/r.git\n",
		"sha":     "sha256: " + rep("b", 64) + "\nintegrity: sha512-" + rep("f", 64) + "\n",
		"envrefs": "Authorization: Bearer $DEPLOY_TOKEN\nAuthorization: Bearer ${DEPLOY_TOKEN}\nOPENAI_API_KEY=sk-${SUFFIX}\n",
		"svg":     `<path d="M308.064 1000C318.837 1074 308.805 1071 289.787 1059 scale 0.666667 0.666992 263.423 1164.5"/>` + "\n",
	}
}

type tc struct {
	name  string
	args  []string
	files map[string]string // staged in the commit under test
	base  map[string]string // committed first (config, word list)
	setup func(t *testing.T)
	stdin func(t *testing.T) string
	want  int
}

func cases() []tc {
	f := fx()
	terms := map[string]string{"terms.txt": "# synthetic list\nzorblax\nquuxington\n", ".gate-kit/leak.json": leakCfg}
	return []tc{
		{name: "secrets-bad-aws", args: []string{"secrets", "--staged"}, files: map[string]string{"cfg/aws.txt": f["aws"]}, want: 1},
		{name: "secrets-bad-github", args: []string{"secrets", "--staged"}, files: map[string]string{"ci/gh.yml": f["github"]}, want: 1},
		{name: "secrets-bad-pem", args: []string{"secrets", "--staged"}, files: map[string]string{"keys/id.pem": f["pem"]}, want: 1},
		{name: "secrets-bad-sk", args: []string{"secrets", "--staged"}, files: map[string]string{"app/conf.py": f["sk"]}, want: 1},
		{name: "secrets-bad-slack", args: []string{"secrets", "--staged"}, files: map[string]string{"notify.sh": f["slack"]}, want: 1},
		{name: "secrets-bad-bearer", args: []string{"secrets", "--staged"}, files: map[string]string{"call.sh": f["bearer"]}, want: 1},
		{name: "secrets-bad-url-userinfo", args: []string{"secrets", "--staged"}, files: map[string]string{"git.cfg": f["urltok"]}, want: 1},
		{name: "secrets-bad-in-lockfile", args: []string{"secrets", "--staged"}, files: map[string]string{"package-lock.json": f["github"]}, want: 1},
		{name: "secrets-bad-on-checksum-line", args: []string{"secrets", "--staged"}, files: map[string]string{"x.txt": "sha256 " + f["aws"]}, want: 1},
		{name: "secrets-good-hashes", args: []string{"secrets", "--staged"}, files: map[string]string{"pkg.lock.txt": f["sha"]}, want: 0},
		{name: "secrets-good-env-references", args: []string{"secrets", "--staged"}, files: map[string]string{"deploy.sh": f["envrefs"]}, want: 0},
		{name: "secrets-bad-tree-after-commit", args: []string{"secrets", "--tree"}, base: map[string]string{"cfg/aws.txt": f["aws"]}, want: 1},
		{name: "secrets-bad-added-then-removed-pre-push", args: []string{"secrets", "--pre-push"}, setup: addThenRemove(f["github"]), stdin: prePushLine, want: 1},
		{name: "secrets-good-pre-push", args: []string{"secrets", "--pre-push"}, setup: addThenRemove("nothing here\n"), stdin: prePushLine, want: 0},

		{name: "leak-bad-term", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"notes.md": "met with Zorblax today\n"}, want: 1},
		{name: "leak-bad-term-in-path", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"quuxington-plan.md": "plain text\n"}, want: 1},
		{name: "leak-bad-email", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "mail jane.roe" + "@gmail.com now\n"}, want: 1},
		{name: "leak-bad-phone", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "call (555) 123-" + "4567\n"}, want: 1},
		{name: "leak-bad-ssn", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "id 123-45-6789\n"}, want: 1}, // gate:allow-line: test fixture
		{name: "leak-bad-pragma-does-not-hide-term", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "Zorblax gate:allow-line\n"}, want: 1},
		{name: "leak-good-reserved-and-noreply", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "ops@example.com\nfrom noreply@corp.invalid\nclone git@github.com:o/r.git\n"}, want: 0}, // gate:allow-line: test fixture
		{name: "leak-good-whole-word-only", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "zorblaxian is not the term\n"}, want: 0},
		{name: "leak-good-svg-coordinates", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"logo.svg": f["svg"]}, want: 0},
		{name: "leak-good-pragma-line", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"c.md": "fixture 123-45-6789 gate:allow-line\n"}, want: 0},
		{name: "leak-cannot-run-without-config", args: []string{"leak", "--staged"}, files: map[string]string{"c.md": "hello\n"}, want: 2},
		{name: "leak-cannot-run-with-empty-config", args: []string{"leak", "--staged"}, base: map[string]string{".gate-kit/leak.json": "{}"}, files: map[string]string{"c.md": "hello\n"}, want: 2},

		{name: "secrets-bad-path-looks-like-stage-number", args: []string{"secrets", "--staged"}, files: map[string]string{"1:a.txt": f["aws"]}, want: 1},
		{name: "leak-bad-term-in-file-named-like-stage-number", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"1:a.txt": "met with Zorblax today\n"}, want: 1},
		{name: "leak-bad-phone-in-file-whose-path-holds-a-term", args: []string{"leak", "--staged"}, base: terms, files: map[string]string{"quuxington-call.md": "call (555) 123-" + "4567\n"}, want: 1},

		{name: "token-url-bad-inline-userinfo", args: []string{"token-url", "--staged"}, files: map[string]string{"push.sh": "git push https://x-access-token:$(vault get T)@github.com/o/r.git\n"}, want: 1},
		{name: "token-url-bad-variable-indirection", args: []string{"token-url", "--staged"}, files: map[string]string{"push.sh": "U=\"https://u:${T}@h/o/r\"\ngit push \"$U\" HEAD\n"}, want: 1},
		{name: "token-url-bad-shell-helper", args: []string{"token-url", "--staged"}, files: map[string]string{"setup.sh": "git config credential.helper \"!echo password=$T\"\n"}, want: 1},
		{name: "token-url-bad-extra-header", args: []string{"token-url", "--staged"}, files: map[string]string{"ci.sh": "git -c http.extraHeader=\"Authorization: Basic eHl6\" push\n"}, want: 1},
		{name: "token-url-bad-line-continuation", args: []string{"token-url", "--staged"}, files: map[string]string{"ci.sh": "git push \\\n  \"https://u:$T@h/o\" \\\n  HEAD\n"}, want: 1},
		{name: "token-url-good-clean-remote", args: []string{"token-url", "--staged"}, files: map[string]string{"ci.sh": "git push -u origin my-branch\ngit clone https://github.com/o/r@v1.git\n"}, want: 0}, // gate:allow-line: test fixture
		{name: "token-url-good-path-helper", args: []string{"token-url", "--staged"}, files: map[string]string{"ci.sh": "git -c credential.helper=/opt/tools/helper.sh push origin HEAD\n"}, want: 0},
		{name: "token-url-good-allow-marker", args: []string{"token-url", "--staged"}, files: map[string]string{"doc.md": "git clone https://u:pw@h/o/r # token-url:allow\n"}, want: 0},

		{name: "run-all-gates-one-bad-file", args: []string{"run", "--staged"}, base: terms, files: map[string]string{"x.sh": f["aws"] + "git push https://u:pw@h/o/r\ncall 555-123-" + "4567\n"}, want: 1},
		{name: "run-all-gates-clean", args: []string{"run", "--staged"}, base: terms, files: map[string]string{"x.sh": "echo hello\n"}, want: 0},
		{name: "run-all-gates-cannot-run-is-not-a-pass", args: []string{"run", "--staged"}, files: map[string]string{"x.sh": "echo hello\n"}, want: 2},
	}
}

func addThenRemove(content string) func(t *testing.T) {
	return func(t *testing.T) {
		write(t, "leaked.txt", content)
		git(t, "add", "-A")
		git(t, "commit", "-q", "-m", "add")
		git(t, "rm", "-q", "leaked.txt")
		git(t, "commit", "-q", "-m", "remove")
	}
}

func prePushLine(t *testing.T) string {
	head := strings.TrimSpace(git(t, "rev-parse", "HEAD"))
	return fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", head, strings.Repeat("0", 40))
}

func git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(cleanEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

var sha12 = regexp.MustCompile(`\b[0-9a-f]{12}\b`)

func TestGolden(t *testing.T) {
	for _, c := range cases() {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range os.Environ() {
				if strings.HasPrefix(k, "GIT_") {
					name, _, _ := strings.Cut(k, "=")
					t.Setenv(name, "")
					os.Unsetenv(name)
				}
			}
			t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			t.Chdir(t.TempDir())
			git(t, "init", "-q", "-b", "main")
			for p, b := range c.base {
				write(t, p, b)
			}
			if len(c.base) > 0 {
				git(t, "add", "-A")
				git(t, "commit", "-q", "-m", "base")
			}
			if c.setup != nil {
				c.setup(t)
			}
			for p, b := range c.files {
				write(t, p, b)
			}
			git(t, "add", "-A")
			stdin := ""
			if c.stdin != nil {
				stdin = c.stdin(t)
			}
			var out, errb bytes.Buffer
			rc := run(c.args, strings.NewReader(stdin), &out, &errb)
			got := fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", rc, out.String(), errb.String())
			got = sha12.ReplaceAllString(got, "<sha>")
			if rc != c.want {
				t.Fatalf("exit %d, want %d\n%s", rc, c.want, got)
			}
			if strings.HasPrefix(c.name, "token-url-bad") {
				for _, body := range c.files {
					for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
						if l := strings.TrimSpace(line); l != "" && strings.Contains(errb.String(), l) {
							t.Fatalf("the refusal echoed the line it refused: %q", l)
						}
					}
				}
			}
			gp := filepath.Join(wdTestdata(t), c.name+".golden")
			if os.Getenv("GATE_KIT_UPDATE") == "1" {
				if err := os.WriteFile(gp, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(gp)
			if err != nil {
				t.Fatalf("no golden file %s (GATE_KIT_UPDATE=1 to create): %v", gp, err)
			}
			if string(want) != got {
				t.Fatalf("output differs from %s\n--- want\n%s\n--- got\n%s", gp, want, got)
			}
		})
	}
}

var testdataDir string

func init() {
	wd, _ := os.Getwd()
	testdataDir = filepath.Join(wd, "testdata", "golden")
	_ = os.MkdirAll(testdataDir, 0o755)
}

func wdTestdata(t *testing.T) string { return testdataDir }
