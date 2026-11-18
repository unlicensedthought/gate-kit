package scansrc

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A tracked symlink to a directory reads as its
// target path, as git stores it, not as an error that stops every --tree scan.
func TestWorktreeReadOfTrackedSymlinkIsItsTarget(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	_ = os.MkdirAll(filepath.Join(dir, "real"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "real", "f.txt"), []byte("x\n"), 0o644)
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	s, err := Git{Dir: dir}.Tree("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Read("link")
	if err != nil || string(b) != "real" {
		t.Fatalf("Read(link) = %q, %v; want the target path", b, err)
	}
}

func gitRepo(t *testing.T) (string, func(args ...string)) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	return dir, run
}

// A staged path that reads as a stage number to git (":1:a.txt") must still read
// the blob that is staged under that literal name.
func TestIndexReadOfPathThatLooksLikeStageSpec(t *testing.T) {
	dir, run := gitRepo(t)
	for _, name := range []string{"1:a.txt", "0:x"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("planted "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	s, err := Git{Dir: dir}.Staged()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Paths) != 2 {
		t.Fatalf("paths = %q", s.Paths)
	}
	for _, name := range s.Paths {
		b, err := s.Read(name)
		if err != nil || string(b) != "planted "+name+"\n" {
			t.Errorf("Read(%q) = %q, %v; want the staged blob", name, b, err)
		}
	}
}

// A path the snapshot lists but cannot read is an error, never "missing".
func TestReadOfUnreadableListedPathIsAnError(t *testing.T) {
	dir, run := gitRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	s, err := Git{Dir: dir}.Staged()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("not-in-the-index.txt"); err == nil {
		t.Error("an unreadable index path read as absent without an error")
	}
	w := Snapshot{G: Git{Dir: dir}, Rev: Worktree}
	if _, err := w.Read("not-on-disk.txt"); err == nil {
		t.Error("an unreadable worktree path read as absent without an error")
	}
}

// A tracked file deleted from the working tree but not staged is left out of a
// working-tree scan, so every path the snapshot lists is still readable.
func TestWorktreeTreeLeavesOutUnstagedDeletions(t *testing.T) {
	dir, run := gitRepo(t)
	for _, name := range []string{"kept.txt", "gone.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	if err := os.Remove(filepath.Join(dir, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	s, err := Git{Dir: dir}.Tree("")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Paths) != 1 || s.Paths[0] != "kept.txt" {
		t.Fatalf("worktree paths = %q, want only kept.txt", s.Paths)
	}
	for _, p := range s.Paths {
		if _, err := s.Read(p); err != nil {
			t.Errorf("listed path %s did not read: %v", p, err)
		}
	}
}
