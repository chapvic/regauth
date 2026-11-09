package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestComputeLibtrustKid_Format(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := ComputeLibtrustKid(&key.PublicKey)

	parts := strings.Split(kid, ":")
	if len(parts) != 12 {
		t.Fatalf("kid must have 12 groups, got %d (%q)", len(parts), kid)
	}
	for i, p := range parts {
		if len(p) != 4 {
			t.Errorf("group %d = %q, want 4 chars", i, p)
		}
		if p != strings.ToUpper(p) {
			t.Errorf("group %d = %q, want uppercase", i, p)
		}
	}
}

func TestComputeLibtrustKid_Stable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k1 := ComputeLibtrustKid(&key.PublicKey)
	k2 := ComputeLibtrustKid(&key.PublicKey)
	if k1 != k2 {
		t.Errorf("kid is not stable: %q vs %q", k1, k2)
	}
}

func TestComputeLibtrustKid_Different(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ComputeLibtrustKid(&k1.PublicKey) == ComputeLibtrustKid(&k2.PublicKey) {
		t.Error("kids for different keys must differ")
	}
}
