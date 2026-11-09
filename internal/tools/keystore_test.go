package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestKeystore(t *testing.T) (*KeystoreFile, *rsa.PrivateKey) {
	t.Helper()
	ks := NewKeystore()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := ComputeLibtrustKid(&key.PublicKey)
	ks.AddCurrentV3(kid, key)
	return ks, key
}

func TestKeystore_AddCurrentV3_SingleCurrent(t *testing.T) {
	ks, key1 := newTestKeystore(t)
	if len(ks.V3.Keys) != 1 || !ks.V3.Keys[0].Current {
		t.Fatal("expected one current key")
	}
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2 := ComputeLibtrustKid(&key2.PublicKey)
	ks.AddCurrentV3(kid2, key2)
	if len(ks.V3.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(ks.V3.Keys))
	}
	current := 0
	for _, e := range ks.V3.Keys {
		if e.Current {
			current++
		}
	}
	if current != 1 {
		t.Errorf("expected exactly 1 current, got %d", current)
	}
	// key1 must be non-current now.
	if ks.V3.Keys[0].Current {
		t.Error("old key must not be current")
	}
	_ = key1
}

func TestKeystore_MarkRevokedV3_WipesPrivate(t *testing.T) {
	ks, key1 := newTestKeystore(t)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2 := ComputeLibtrustKid(&key2.PublicKey)
	ks.AddCurrentV3(kid2, key2)
	kid1 := ComputeLibtrustKid(&key1.PublicKey)

	if err := ks.MarkRevokedV3(kid1); err != nil {
		t.Fatal(err)
	}
	for _, e := range ks.V3.Keys {
		if e.KID == kid1 {
			if !e.Revoked {
				t.Error("expected revoked")
			}
			if e.Private != "" {
				t.Error("expected private wiped on revoke")
			}
		}
	}
}

func TestKeystore_MarkRevokedV3_CurrentFails(t *testing.T) {
	ks, key := newTestKeystore(t)
	kid := ComputeLibtrustKid(&key.PublicKey)
	if err := ks.MarkRevokedV3(kid); err != ErrCurrentKey {
		t.Errorf("expected ErrCurrentKey, got %v", err)
	}
}

func TestKeystore_MarkRevokedV3_NotFound(t *testing.T) {
	ks, _ := newTestKeystore(t)
	if err := ks.MarkRevokedV3("missing"); err == nil {
		t.Error("expected error for missing kid")
	}
}

func TestKeystore_DeleteV3_OnlyRevoked(t *testing.T) {
	ks, key1 := newTestKeystore(t)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2 := ComputeLibtrustKid(&key2.PublicKey)
	ks.AddCurrentV3(kid2, key2)
	kid1 := ComputeLibtrustKid(&key1.PublicKey)

	// Delete active non-current — must fail.
	if err := ks.DeleteV3(kid1); err != ErrKeyNotRevoked {
		t.Errorf("expected ErrKeyNotRevoked, got %v", err)
	}

	// Revoke then delete — must succeed.
	if err := ks.MarkRevokedV3(kid1); err != nil {
		t.Fatal(err)
	}
	if err := ks.DeleteV3(kid1); err != nil {
		t.Fatal(err)
	}
	if len(ks.V3.Keys) != 1 {
		t.Errorf("expected 1 key after delete, got %d", len(ks.V3.Keys))
	}
}

func TestKeystore_CleanupV3(t *testing.T) {
	ks, key1 := newTestKeystore(t)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2 := ComputeLibtrustKid(&key2.PublicKey)
	ks.AddCurrentV3(kid2, key2)
	kid1 := ComputeLibtrustKid(&key1.PublicKey)
	if err := ks.MarkRevokedV3(kid1); err != nil {
		t.Fatal(err)
	}
	n := ks.CleanupV3()
	if n != 1 {
		t.Errorf("expected 1 removed, got %d", n)
	}
	if len(ks.V3.Keys) != 1 {
		t.Errorf("expected 1 key after cleanup, got %d", len(ks.V3.Keys))
	}
}

func TestKeystore_ActiveV3(t *testing.T) {
	ks, key1 := newTestKeystore(t)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2 := ComputeLibtrustKid(&key2.PublicKey)
	ks.AddCurrentV3(kid2, key2)
	kid1 := ComputeLibtrustKid(&key1.PublicKey)
	if err := ks.MarkRevokedV3(kid1); err != nil {
		t.Fatal(err)
	}
	active := ks.ActiveV3()
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}
}

func TestKeystore_WritePublicV2_IsCertificate(t *testing.T) {
	ks, _ := newTestKeystore(t)
	// Добавляем v2-ключ, так как newTestKeystore создает только v3.
	v2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks.SetV2(v2Key)

	dir := t.TempDir()
	path := filepath.Join(dir, "public-v2.key")

	if err := ks.WritePublicV2(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected CERTIFICATE, got: %s", strings.SplitN(string(data), "\n", 2)[0])
	}
}
