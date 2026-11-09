package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunCommand_Empty(t *testing.T) {
	if err := RunCommand(nil, nil); err != nil {
		t.Errorf("empty argv must be no-op, got %v", err)
	}
	if err := RunCommand([]string{}, nil); err != nil {
		t.Errorf("empty argv must be no-op, got %v", err)
	}
}

func TestRunCommand_Success(t *testing.T) {
	if err := RunCommand([]string{"true"}, nil); err != nil {
		t.Errorf("expected success, got %v", err)
	}
}

func TestRunCommand_NonZeroExit(t *testing.T) {
	if err := RunCommand([]string{"false"}, nil); err == nil {
		t.Error("expected error for non-zero exit")
	}
}

func TestRunCommand_MissingBinary(t *testing.T) {
	if err := RunCommand([]string{"definitely-not-a-real-binary-xyz"}, nil); err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestRunCommand_ExtraEnv(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	argv := []string{"sh", "-c", "echo \"$REGAUTH_TEST\" > " + out}
	env := []string{"REGAUTH_TEST=hello-from-test"}
	if err := RunCommand(argv, env); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "hello-from-test\n" {
		t.Errorf("output = %q, want %q", got, "hello-from-test\n")
	}
}
