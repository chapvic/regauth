package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildRegauth(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "regauth")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build regauth: %v\n%s", err, out)
	}
	return bin
}

func runBinary(t *testing.T, bin string, args ...string) (string, string, int) {
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

func TestRegauth_NoArgs_Help(t *testing.T) {
	bin := buildRegauth(t)
	out, _, code := runBinary(t, bin)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "RegAuth") {
		t.Errorf("help must contain banner, got %q", out)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help must contain Usage, got %q", out)
	}
}

func TestRegauth_HelpFlag(t *testing.T) {
	bin := buildRegauth(t)
	out, _, code := runBinary(t, bin, "-h")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help must contain Usage, got %q", out)
	}
}

func TestRegauth_UnknownCommand(t *testing.T) {
	bin := buildRegauth(t)
	_, errOut, code := runBinary(t, bin, "nonsense")
	if code == 0 {
		t.Error("exit code must be non-zero for unknown command")
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Errorf("stderr must mention unknown command, got %q", errOut)
	}
}

func TestRegauth_Server_NoConfig_Help(t *testing.T) {
	bin := buildRegauth(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	_, _, code := runBinary(t, bin, "server", "-c", cfg)
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit code %d", code)
	}
}

func TestRegauth_Keystore_ListNoConfig(t *testing.T) {
	bin := buildRegauth(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	out, _, code := runBinary(t, bin, "keystore", "list", "-c", cfg)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "v2:") || !strings.Contains(out, "v3:") {
		t.Errorf("list output must contain v2: and v3:, got %q", out)
	}
}

func TestRegauth_Keystore_RotateV2(t *testing.T) {
	bin := buildRegauth(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, code := runBinary(t, bin, "keystore", "list", "-c", cfg); code != 0 {
		t.Fatalf("initial list failed with code %d", code)
	}
	out, _, code := runBinary(t, bin, "keystore", "rotate-v2", "-c", cfg)
	if code != 0 {
		t.Fatalf("rotate-v2 exit code = %d, output=%s", code, out)
	}
	if !strings.Contains(out, "rotated v2 signing key") {
		t.Errorf("rotate-v2 output = %q", out)
	}
}

func TestRegauth_ExecHookEnv(t *testing.T) {
	bin := buildRegauth(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, code := runBinary(t, bin, "keystore", "list", "-c", cfg); code != 0 {
		t.Fatalf("initial list failed")
	}
	marker := filepath.Join(dir, "hook.txt")
	configData := "server:\n  keystore:\n    rotate_v2:\n      - sh\n      - -c\n      - 'echo \"$REGAUTH_OPERATION $REGAUTH_KEY_VERSION\" > " + marker + "'\n"
	if err := os.WriteFile(cfg, []byte(configData), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runBinary(t, bin, "keystore", "rotate-v2", "-c", cfg); code != 0 {
		t.Fatalf("rotate-v2 failed")
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("hook output not written: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "rotate-v2 2" {
		t.Errorf("hook env = %q, want %q", got, "rotate-v2 2")
	}
}
