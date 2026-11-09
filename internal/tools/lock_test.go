package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	if err := AcquireLock(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("pid file must exist after acquire: %v", err)
	}
	ReleaseLock(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("pid file must be removed after release, stat err = %v", err)
	}
}

func TestAcquireTwice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := AcquireLock(path); err != nil {
		t.Fatal(err)
	}
	defer ReleaseLock(path)

	if err := AcquireLock(path); err == nil {
		t.Error("expected ErrAlreadyRunning on second acquire in same process")
	}
}

func TestReadRunningPID_NoFile(t *testing.T) {
	dir := t.TempDir()
	pid, err := ReadRunningPID(filepath.Join(dir, "missing.pid"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if pid != 0 {
		t.Errorf("expected 0 for missing file, got %d", pid)
	}
}

func TestReadRunningPID_CurrentProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := AcquireLock(path); err != nil {
		t.Fatal(err)
	}
	defer ReleaseLock(path)

	pid, err := ReadRunningPID(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Errorf("expected pid %d, got %d", os.Getpid(), pid)
	}
}

func TestReadRunningPID_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(path, []byte("not a pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRunningPID(path); err == nil {
		t.Error("expected error for malformed pid file")
	}
}

func TestReadRunningPID_WrongStarttime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stale.pid")
	// Write our own pid with a bogus starttime (guaranteed to differ).
	bogus := fmt.Sprintf("%d 1\n", os.Getpid())
	if err := os.WriteFile(path, []byte(bogus), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadRunningPID(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 0 {
		t.Errorf("expected 0 for PID with wrong starttime (PID reuse), got %d", pid)
	}
}
