package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_EmptyFileRecreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	emptyData := []byte("  \n\r\n\t  \n")
	if err := os.WriteFile(path, emptyData, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WasCreated() {
		t.Error("expected config to be created from empty file")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("file should not be empty after LoadConfig()")
	}

	if _, err := os.Stat(filepath.Join(dir, "keystore.yaml")); os.IsNotExist(err) {
		t.Error("keystore.yaml was not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "public-v2.key")); os.IsNotExist(err) {
		t.Error("public-v2.key was not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "public-v3.key")); os.IsNotExist(err) {
		t.Error("public-v3.key was not created")
	}
}

func TestLoadConfig_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WasCreated() {
		t.Error("expected config to be created from non-existent file")
	}
}

func TestConfig_SigningKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// v3 default.
	cfg.Server.KeysVersion = 3
	priv, kid, err := cfg.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil || kid == "" {
		t.Error("expected v3 key and kid")
	}
	if got := ComputeLibtrustKid(&priv.PublicKey); got != kid {
		t.Errorf("kid mismatch: %q vs %q", got, kid)
	}

	// v2.
	cfg.Server.KeysVersion = 2
	priv2, kid2, err := cfg.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv2 == nil || kid2 == "" {
		t.Error("expected v2 key and kid")
	}
	if got := ComputeLibtrustKid(&priv2.PublicKey); got != kid2 {
		t.Errorf("kid mismatch: %q vs %q", got, kid2)
	}
	if kid == kid2 {
		t.Error("v2 and v3 kids must differ")
	}

	// Invalid.
	cfg.Server.KeysVersion = 99
	if _, _, err := cfg.SigningKey(); err == nil {
		t.Error("expected error for invalid keys_version")
	}
}

func TestConfig_IsServiceAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// Empty list — allow all.
	cfg.Server.AllowedServices = nil
	if !cfg.IsServiceAllowed("anything") {
		t.Error("empty allowed_services must allow all")
	}

	// Non-empty — exact match only.
	cfg.Server.AllowedServices = []string{"registry.tld", "v2.registry.tld"}
	if !cfg.IsServiceAllowed("registry.tld") {
		t.Error("expected registry.tld to be allowed")
	}
	if !cfg.IsServiceAllowed("v2.registry.tld") {
		t.Error("expected v2.registry.tld to be allowed")
	}
	if cfg.IsServiceAllowed("other.tld") {
		t.Error("expected other.tld to be rejected")
	}
	if cfg.IsServiceAllowed("") {
		t.Error("expected empty service to be rejected")
	}
}

func TestConfig_RotateV3AndV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	_, kid0, err := cfg.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	kid1, err := cfg.RotateV3()
	if err != nil {
		t.Fatal(err)
	}
	if kid1 == kid0 {
		t.Error("rotate v3 must produce a new kid")
	}
	if _, kidNow, _ := cfg.SigningKey(); kidNow != kid1 {
		t.Errorf("current kid = %q, want %q", kidNow, kid1)
	}

	cfg.Server.KeysVersion = 2
	_, v2kid0, err := cfg.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.RotateV2(); err != nil {
		t.Fatal(err)
	}
	_, v2kid1, err := cfg.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if v2kid0 == v2kid1 {
		t.Error("rotate v2 must produce a new kid")
	}
}

func TestConfig_RevokeDeleteCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	oldKid, err := cfg.RotateV3()
	if err != nil {
		t.Fatal(err)
	}
	newKid, err := cfg.RotateV3()
	if err != nil {
		t.Fatal(err)
	}
	if oldKid == newKid {
		t.Fatal("kids must differ")
	}

	// Cannot revoke current.
	if err := cfg.RevokeV3(newKid); err == nil {
		t.Error("expected error revoking current key")
	}

	// Revoke old.
	if err := cfg.RevokeV3(oldKid); err != nil {
		t.Fatal(err)
	}

	// Delete revoked.
	if err := cfg.DeleteV3(oldKid); err != nil {
		t.Fatal(err)
	}

	// Delete non-revoked must fail (use current).
	if err := cfg.DeleteV3(newKid); err == nil {
		t.Error("expected error deleting non-revoked key")
	}

	// Cleanup with nothing to remove.
	n, err := cfg.CleanupV3()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("cleanup removed %d, want 0", n)
	}
}

func TestConfig_DerivedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// public-v2.key must be a certificate.
	data, err := os.ReadFile(cfg.PublicV2Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("public-v2.key is empty")
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Errorf("public-v2.key is not a certificate")
	}

	// public-v3.key must be JSON with "keys".
	data, err = os.ReadFile(cfg.PublicV3Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"keys"`) {
		t.Errorf("public-v3.key is not a JWKS")
	}
}
