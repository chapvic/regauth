package tools

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureOutput перехватывает os.Stdout/os.Stderr на время fn.
func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldOut := os.Stdout
	oldErr := os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wOut
	os.Stderr = wErr

	done := make(chan struct{})
	var outBuf, errBuf strings.Builder
	go func() {
		_, _ = io.Copy(&outBuf, rOut)
		close(done)
	}()
	errDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&errBuf, rErr)
		close(errDone)
	}()

	fn()

	_ = wOut.Close()
	_ = wErr.Close()
	<-done
	<-errDone
	os.Stdout = oldOut
	os.Stderr = oldErr
	_ = rOut.Close()
	_ = rErr.Close()
	return outBuf.String(), errBuf.String()
}

func TestPrintBanner(t *testing.T) {
	out, _ := captureOutput(t, func() {
		PrintBanner()
	})
	if !strings.Contains(out, "RegAuth") {
		t.Errorf("banner must contain RegAuth, got %q", out)
	}
	if !strings.Contains(out, "Copyright") {
		t.Errorf("banner must contain Copyright, got %q", out)
	}
}

func TestPrintStartupSummary_EmptyKid(t *testing.T) {
	_, errOut := captureOutput(t, func() {
		PrintStartupSummary("https://registry.tld", ":5100", false, false, "/run/regauth.pid", "")
	})
	if !strings.Contains(errOut, "https://registry.tld") {
		t.Errorf("summary must contain registry, got %q", errOut)
	}
	if !strings.Contains(errOut, ":5100") {
		t.Errorf("summary must contain addr, got %q", errOut)
	}
	if !strings.Contains(errOut, "http") {
		t.Errorf("summary must contain protocol, got %q", errOut)
	}
}

func TestPrintStartupSummary_TLSInsecure(t *testing.T) {
	_, errOut := captureOutput(t, func() {
		PrintStartupSummary("https://registry.tld", ":5100", true, true, "/run/regauth.pid", "kid1")
	})
	if !strings.Contains(errOut, "https") {
		t.Errorf("summary must contain https, got %q", errOut)
	}
	if !strings.Contains(errOut, "insecure") {
		t.Errorf("summary must contain insecure, got %q", errOut)
	}
	if !strings.Contains(errOut, "kid1") {
		t.Errorf("summary must contain kid, got %q", errOut)
	}
}
