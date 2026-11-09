package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildReguser(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "reguser")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build reguser: %v\n%s", err, out)
	}
	return bin
}

func runReguser(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %s: %v", bin, err)
		}
	}
	return out.String(), errOut.String(), code
}

func TestReguser_NoArgs_Help(t *testing.T) {
	bin := buildReguser(t)
	out, _, code := runReguser(t, bin)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "RegUser") {
		t.Errorf("help must contain banner, got %q", out)
	}
}

func TestReguser_HelpFlag(t *testing.T) {
	bin := buildReguser(t)
	out, _, code := runReguser(t, bin, "-h")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help must contain Usage, got %q", out)
	}
}

func TestReguser_UnknownCommand(t *testing.T) {
	bin := buildReguser(t)
	_, errOut, code := runReguser(t, bin, "nonsense")
	if code == 0 {
		t.Error("exit code must be non-zero")
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestReguser_Hash(t *testing.T) {
	bin := buildReguser(t)
	out, _, code := runReguser(t, bin, "hash", "-p", "secret")
	if code != 0 {
		t.Fatalf("hash failed with code %d", code)
	}
	hash := strings.TrimSpace(out)
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("hash = %q, want bcrypt", hash)
	}
}

func TestReguser_AddListDelLock(t *testing.T) {
	bin := buildReguser(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, code := runReguser(t, bin, "list", "-c", cfg); code != 0 {
		t.Fatalf("initial list failed")
	}
	if _, _, code := runReguser(t, bin, "add", "alice", "-p", "secret", "-c", cfg); code != 0 {
		t.Fatalf("add failed")
	}

	out, _, code := runReguser(t, bin, "list", "-c", cfg)
	if code != 0 {
		t.Fatalf("list failed")
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("list must contain alice, got %q", out)
	}
	if strings.Contains(out, "ANONYMOUS") {
		t.Errorf("list must not contain ANONYMOUS by default, got %q", out)
	}

	out, _, _ = runReguser(t, bin, "list", "-all", "-c", cfg)
	if !strings.Contains(out, "ANONYMOUS") {
		t.Errorf("list -all must contain ANONYMOUS, got %q", out)
	}

	out, _, _ = runReguser(t, bin, "list", "-count", "-c", cfg)
	if strings.TrimSpace(out) != "1" {
		t.Errorf("list -count = %q, want 1", strings.TrimSpace(out))
	}

	out, _, _ = runReguser(t, bin, "list", "-all", "-count", "-c", cfg)
	if strings.TrimSpace(out) != "2" {
		t.Errorf("list -all -count = %q, want 2", strings.TrimSpace(out))
	}

	if _, _, code := runReguser(t, bin, "lock", "alice", "-lock", "-c", cfg); code != 0 {
		t.Fatalf("lock failed")
	}
	out, _, _ = runReguser(t, bin, "list", "-all", "-c", cfg)
	if !strings.Contains(out, "yes") {
		t.Errorf("locked user must show yes in LOCKED column, got %q", out)
	}

	if _, _, code := runReguser(t, bin, "lock", "alice", "-unlock", "-c", cfg); code != 0 {
		t.Fatalf("unlock failed")
	}

	if _, _, code := runReguser(t, bin, "del", "alice", "-c", cfg); code != 0 {
		t.Fatalf("del failed")
	}
	out, _, _ = runReguser(t, bin, "list", "-c", cfg)
	if strings.Contains(out, "alice") {
		t.Errorf("deleted user must not be listed, got %q", out)
	}
}

func TestReguser_LockAnonymous_Forbidden(t *testing.T) {
	bin := buildReguser(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, code := runReguser(t, bin, "list", "-c", cfg); code != 0 {
		t.Fatalf("initial list failed")
	}
	_, errOut, code := runReguser(t, bin, "lock", "ANONYMOUS", "-lock", "-c", cfg)
	if code == 0 {
		t.Error("locking ANONYMOUS must fail")
	}
	if !strings.Contains(errOut, "ANONYMOUS") {
		t.Errorf("stderr must mention ANONYMOUS, got %q", errOut)
	}
}

func TestReguser_CleanRequiresConfirmation(t *testing.T) {
	bin := buildReguser(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, code := runReguser(t, bin, "list", "-c", cfg); code != 0 {
		t.Fatalf("initial list failed")
	}
	if _, _, code := runReguser(t, bin, "add", "alice", "-p", "secret", "-c", cfg); code != 0 {
		t.Fatalf("add failed")
	}
	out, _, code := runReguser(t, bin, "clean", "-c", cfg)
	if code != 0 {
		t.Errorf("clean without -f must not fail, got %d", code)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("expected aborted, got %q", out)
	}
	if _, _, code := runReguser(t, bin, "clean", "-f", "-c", cfg); code != 0 {
		t.Fatalf("clean -f failed")
	}
	out, _, _ = runReguser(t, bin, "list", "-all", "-c", cfg)
	if strings.Contains(out, "alice") {
		t.Errorf("clean -f must remove alice, got %q", out)
	}
}
