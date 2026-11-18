// Package scansrc is the one place every gatekit check learns WHAT to read:
// the staged index (--staged), every unpushed commit of a git pre-push
// (--pre-push), a revision's tree, or the working tree. A check supplies only
// the per-file verdict; it never shells out to git itself, so "what a commit
// contains" cannot be answered two ways.
//
// A Snapshot is one point in history. Its Rev is "" for the index and a commit
// id otherwise. A check reads its own per-repo config THROUGH the snapshot
// (Snapshot.Config), never from the working tree: a commit is judged by the
// config that commit carries, so loosening a config is itself a reviewed diff
// and an old commit is not re-judged by today's config.
//
// git runs with the inherited environment: in a hook, GIT_DIR / GIT_INDEX_FILE
// are exactly what --staged must read (git points GIT_INDEX_FILE at a
// temporary index for `commit -a`). Callers that scan a tree and not the
// index set Git.Clean to drop them.
package scansrc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ZeroSHA is the all-zero object id git prints for "no such ref".
const ZeroSHA = "0000000000000000000000000000000000000000"

// Git runs git in Dir ("" = the process cwd).
type Git struct {
	Dir   string
	Clean bool // strip GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE
}

// Run returns git's stdout; on failure the error carries git's stderr.
func (g Git) Run(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Dir
	if g.Clean {
		var env []string
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "GIT_DIR=") || strings.HasPrefix(kv, "GIT_WORK_TREE=") || strings.HasPrefix(kv, "GIT_INDEX_FILE=") {
				continue
			}
			env = append(env, kv)
		}
		cmd.Env = env
	}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(e.String()))
	}
	return o.Bytes(), nil
}

// Top is the repository's toplevel directory.
func (g Git) Top() (string, error) {
	out, err := g.Run("rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SplitNUL splits git's -z output, dropping empty fields.
func SplitNUL(b []byte) []string {
	var out []string
	for _, f := range bytes.Split(b, []byte{0}) {
		if len(f) > 0 {
			out = append(out, string(f))
		}
	}
	return out
}

// Snapshot is one readable point: the index, a commit, or the working tree.
type Snapshot struct {
	G     Git
	Rev   string   // "" index; commit id; "WORKTREE" for the working tree
	Label string   // prefix for printed paths ("" or "abc123def456 ")
	Paths []string // the files this snapshot asks a check to examine
}

// Worktree is the Rev of a working-tree snapshot.
const Worktree = "WORKTREE"

// spec names a blob for git. The index form carries an explicit stage: ":" + p
// would let a staged path such as "1:a.txt" be reparsed as stage 1 of "a.txt".
func (s Snapshot) spec(p string) string {
	if s.Rev == "" {
		return ":0:" + p
	}
	return s.Rev + ":" + p
}

// Read returns a path's bytes at this snapshot. A path the snapshot lists but
// that cannot be read is an error, never "missing".
func (s Snapshot) Read(p string) ([]byte, error) {
	b, ok, err := s.read(p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("cannot read %s: listed by %s but not readable there", p, s.where())
	}
	return b, nil
}

func (s Snapshot) where() string {
	switch s.Rev {
	case "":
		return "the index"
	case Worktree:
		return "the working tree"
	}
	return s.Rev
}

// read is Read where absence is not an error (ok false); other failures are.
func (s Snapshot) read(p string) ([]byte, bool, error) {
	if s.Rev == Worktree {
		top := s.G.Dir
		full := filepath.Join(top, p)
		// A tracked symlink's content is its target path, exactly as git stores the
		// blob; following it reads a directory (an error) or a file outside the tree.
		if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			t, err := os.Readlink(full)
			if err != nil {
				return nil, false, err
			}
			return []byte(t), true, nil
		}
		b, err := os.ReadFile(full)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		return b, true, nil
	}
	if _, err := s.G.Run("cat-file", "-e", s.spec(p)); err != nil {
		return nil, false, nil
	}
	b, err := s.G.Run("cat-file", "blob", s.spec(p))
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Config reads a per-repo config file at this snapshot; ok is false when absent.
func (s Snapshot) Config(p string) (b []byte, ok bool, err error) { return s.read(p) }

// ReadRegular reads a repo-relative file that a repo's own config names, for a
// caller that must not let the repo reach the host. At most max bytes; anything
// longer, or not a regular file, is an error. In the working tree the path is
// resolved through symlinks and must stay under the repo top. In the index or a
// commit it must be a regular blob (not a symlink or a submodule).
func (s Snapshot) ReadRegular(p string, max int64) ([]byte, error) {
	if s.Rev == Worktree {
		top, err := filepath.EvalSymlinks(s.G.Dir)
		if err != nil {
			return nil, err
		}
		full, err := filepath.EvalSymlinks(filepath.Join(top, p))
		if err != nil {
			return nil, fmt.Errorf("%s not readable in %s: %v", p, s.where(), err)
		}
		if rel, err := filepath.Rel(top, full); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%s resolves outside the repository", p)
		}
		f, err := os.Open(full)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		b, err := io.ReadAll(io.LimitReader(f, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > max {
			return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
		}
		return b, nil
	}
	mode, err := s.blobMode(p)
	if err != nil {
		return nil, err
	}
	if mode != "100644" && mode != "100755" {
		return nil, fmt.Errorf("%s is not a regular file in %s (mode %s)", p, s.where(), mode)
	}
	sz, err := s.G.Run("cat-file", "-s", s.spec(p))
	if err != nil {
		return nil, err
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(string(sz)), 10, 64); err != nil || n > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	return s.G.Run("cat-file", "blob", s.spec(p))
}

// blobMode is p's git mode at an index or commit snapshot.
func (s Snapshot) blobMode(p string) (string, error) {
	var out []byte
	var err error
	if s.Rev == "" {
		out, err = s.G.Run("ls-files", "-s", "-z")
	} else {
		out, err = s.G.Run("ls-tree", "-r", "-z", s.Rev)
	}
	if err != nil {
		return "", err
	}
	for _, rec := range SplitNUL(out) {
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok || path != p {
			continue
		}
		f := strings.Fields(meta)
		if s.Rev == "" && (len(f) < 3 || f[2] != "0") {
			continue
		}
		if len(f) > 0 {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", p, s.where())
}

// Staged is the index: every added, copied, modified, renamed or type-changed path.
func (g Git) Staged() (Snapshot, error) {
	out, err := g.Run("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{G: g, Rev: "", Paths: SplitNUL(out)}, nil
}

// Tree is every tracked file of rev, or of the working tree when rev is "".
func (g Git) Tree(rev string) (Snapshot, error) {
	if rev == "" {
		out, err := g.Run("ls-files", "-z")
		if err != nil {
			return Snapshot{}, err
		}
		top, err := g.Top()
		if err != nil {
			return Snapshot{}, err
		}
		g.Dir = top
		return Snapshot{G: g, Rev: Worktree, Paths: SplitNUL(out)}, nil
	}
	out, err := g.Run("ls-tree", "-r", "-z", "--name-only", rev)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{G: g, Rev: rev, Paths: SplitNUL(out)}, nil
}

// Commit is the delta of one commit: every path it adds or modifies, read at
// that commit. A merge commit contributes the paths that differ from EACH
// parent (-m), so a resolution that introduces content is not invisible.
func (g Git) Commit(c string) (Snapshot, error) {
	out, err := g.Run("diff-tree", "-r", "--root", "-m", "--no-commit-id", "--name-only", "-z", "--diff-filter=ACMRT", c)
	if err != nil {
		return Snapshot{}, err
	}
	seen := map[string]bool{}
	var paths []string
	for _, p := range SplitNUL(out) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return Snapshot{G: g, Rev: c, Label: c[:min(12, len(c))] + " ", Paths: paths}, nil
}

// PrePush reads git's pre-push stdin ("<local ref> <local sha> <remote ref> <remote sha>"
// per line) and returns one Snapshot per UNPUSHED commit, not just the tip: a
// file added and then removed inside the push is still in history and still
// gets pushed. A deleted ref is skipped. When the remote sha is unknown
// locally (a force push over history this clone never fetched) the commits are
// taken against every remote-tracking ref instead, which can only scan more.
func (g Git) PrePush(stdin io.Reader) ([]Snapshot, error) {
	var snaps []Snapshot
	seen := map[string]bool{}
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 {
			continue
		}
		local, remote := f[1], f[3]
		if strings.Trim(local, "0") == "" {
			continue
		}
		var revs []byte
		var err error
		if strings.Trim(remote, "0") != "" {
			revs, err = g.Run("rev-list", local, "--not", remote)
		}
		if strings.Trim(remote, "0") == "" || err != nil {
			revs, err = g.Run("rev-list", local, "--not", "--remotes")
			if err != nil {
				return nil, err
			}
		}
		for _, c := range strings.Fields(string(revs)) {
			if seen[c] {
				continue
			}
			seen[c] = true
			s, err := g.Commit(c)
			if err != nil {
				return nil, err
			}
			snaps = append(snaps, s)
		}
	}
	return snaps, sc.Err()
}
