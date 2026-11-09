package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite_CreateAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := AtomicWrite(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want %q", data, "hello")
	}
}

func TestAtomicWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := AtomicWrite(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Errorf("content = %q, want %q", data, "second")
	}
}

func TestAtomicWrite_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := AtomicWrite(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}
}

func TestAtomicWrite_NoLeftoverTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := AtomicWrite(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= 5 && e.Name()[:5] == ".tmp-" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestAtomicWrite_MissingDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "file.txt")
	if err := AtomicWrite(path, []byte("x"), 0o644); err == nil {
		t.Error("expected error when parent dir does not exist")
	}
}

func TestResolveRelative(t *testing.T) {
	if got := ResolveRelative("/base", "file.txt"); got != "/base/file.txt" {
		t.Errorf("ResolveRelative relative = %q", got)
	}
	if got := ResolveRelative("/base", "/abs/file.txt"); got != "/abs/file.txt" {
		t.Errorf("ResolveRelative absolute = %q", got)
	}
}
