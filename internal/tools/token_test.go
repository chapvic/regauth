package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssuer_IssueAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := ComputeLibtrustKid(&key.PublicKey)
	issuer := NewIssuer(key, kid, "regauth", time.Minute)

	access := []AccessEntry{
		{Type: "repository", Name: "actions/x", Actions: []string{"pull"}},
		{Type: "registry", Name: "catalog", Actions: []string{"*"}},
	}
	tok, err := issuer.Issue("alice", "registry.example.com", access)
	if err != nil {
		t.Fatal(err)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tok, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatal("token is not valid")
	}

	if got, _ := parsed.Header["kid"].(string); got != kid {
		t.Errorf("kid = %q, want %q", got, kid)
	}
	if claims.Issuer != "regauth" {
		t.Errorf("iss = %q, want regauth", claims.Issuer)
	}
	if claims.Subject != "alice" {
		t.Errorf("sub = %q, want alice", claims.Subject)
	}
	if claims.Audience != "registry.example.com" {
		t.Errorf("aud = %q, want registry.example.com", claims.Audience)
	}
	if len(claims.Access) != 2 {
		t.Fatalf("access entries = %d, want 2", len(claims.Access))
	}
	if claims.Access[0].Name != "actions/x" || claims.Access[1].Name != "catalog" {
		t.Errorf("access = %+v", claims.Access)
	}
}

func TestIssuer_AudIsString(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := NewIssuer(key, "kid", "regauth", time.Minute)
	tok, err := issuer.Issue("alice", "registry.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	parser := jwt.NewParser()
	raw := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(tok, raw); err != nil {
		t.Fatal(err)
	}
	aud, ok := raw["aud"]
	if !ok {
		t.Fatal("aud claim is missing")
	}
	if _, isString := aud.(string); !isString {
		t.Errorf("aud must be a string, got %T (%v)", aud, aud)
	}
}

func TestIssuer_SubjectEmptyForAnonymous(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := NewIssuer(key, "kid", "regauth", time.Minute)
	tok, err := issuer.Issue("", "registry.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := &Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "" {
		t.Errorf("sub = %q, want empty", claims.Subject)
	}
}
