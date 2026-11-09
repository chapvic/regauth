package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func newTestHandler(t *testing.T, rules map[string][]Rule) *Handler {
	t.Helper()
	dir := t.TempDir()

	af := &AccountsFile{Users: map[string]*Account{
		Anonymous: {Rules: []Rule{{Pattern: "**", Actions: []string{"pull"}, Access: "allow"}}},
	}}
	for name, r := range rules {
		hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		af.Users[name] = &Account{Password: string(hash), Rules: r}
	}
	storePath := filepath.Join(dir, "accounts.yaml")
	data, err := yaml.Marshal(af)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(storePath)

	cfg := &Config{
		Server: ServerConfig{
			KeysVersion: 3,
		},
	}
	ks := NewKeystore()
	v2Key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks.SetV2(v2Key)
	v3Key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := ComputeLibtrustKid(&v3Key.PublicKey)
	ks.AddCurrentV3(kid, v3Key)

	ksPath := filepath.Join(dir, "keystore.yaml")
	if err := ks.Save(ksPath); err != nil {
		t.Fatal(err)
	}
	cfg.Paths.Keystore = ksPath

	jwksPath := filepath.Join(dir, "public-v3.key")
	if err := ks.WriteJWKS(jwksPath); err != nil {
		t.Fatal(err)
	}

	return NewHandler(store, cfg, true, jwksPath)
}

func TestHandler_Token_Anonymous(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == "" {
		t.Error("empty token")
	}
	claims := parseClaims(t, resp["token"])
	if len(claims.Access) != 1 {
		t.Fatalf("access entries = %d, want 1", len(claims.Access))
	}
	if claims.Access[0].Type != "repository" || claims.Access[0].Name != "actions/x" {
		t.Errorf("access[0] = %+v", claims.Access[0])
	}
	if len(claims.Access[0].Actions) != 1 || claims.Access[0].Actions[0] != "pull" {
		t.Errorf("actions = %v, want [pull]", claims.Access[0].Actions)
	}
}

func TestHandler_Token_AuthOK(t *testing.T) {
	h := newTestHandler(t, map[string][]Rule{
		"alice": {{Pattern: "actions/**", Actions: []string{"pull", "push"}, Access: "allow"}},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull,push", nil)
	req.SetBasicAuth("alice", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	claims := parseClaims(t, resp["token"])
	if len(claims.Access) != 1 || len(claims.Access[0].Actions) != 2 {
		t.Fatalf("access = %+v, want one entry with 2 actions", claims.Access)
	}
}

func TestHandler_Token_AuthFail(t *testing.T) {
	h := newTestHandler(t, map[string][]Rule{
		"alice": {{Pattern: "**", Actions: []string{"pull"}, Access: "allow"}},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull", nil)
	req.SetBasicAuth("alice", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestHandler_Token_AnonymousCredentialsIgnored(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull", nil)
	req.SetBasicAuth(Anonymous, "anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (ANONYMOUS creds ignored)", rr.Code)
	}
}

func TestHandler_Token_DeniedAction(t *testing.T) {
	h := newTestHandler(t, map[string][]Rule{
		"alice": {{Pattern: "actions/**", Actions: []string{"pull"}, Access: "allow"}},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull,push", nil)
	req.SetBasicAuth("alice", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	claims := parseClaims(t, resp["token"])
	if len(claims.Access) != 1 {
		t.Fatalf("access = %+v, want one entry", claims.Access)
	}
	if len(claims.Access[0].Actions) != 1 || claims.Access[0].Actions[0] != "pull" {
		t.Errorf("actions = %v, want [pull]", claims.Access[0].Actions)
	}
}

func TestHandler_Token_CatalogRequiresExplicitRule(t *testing.T) {
	h := newTestHandler(t, map[string][]Rule{
		"alice": {{Pattern: "**", Actions: []string{"pull"}, Access: "allow"}},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=registry:catalog:*", nil)
	req.SetBasicAuth("alice", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	claims := parseClaims(t, resp["token"])
	if len(claims.Access) != 0 {
		t.Errorf("access = %+v, want empty (catalog requires explicit rule)", claims.Access)
	}
}

func TestHandler_Token_CatalogExplicit(t *testing.T) {
	h := newTestHandler(t, map[string][]Rule{
		"alice": {
			{Pattern: "**", Actions: []string{"pull"}, Access: "allow"},
			{Pattern: "catalog", Actions: []string{"*"}, Access: "allow"},
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=registry:catalog:*", nil)
	req.SetBasicAuth("alice", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	claims := parseClaims(t, resp["token"])
	if len(claims.Access) != 1 || claims.Access[0].Type != "registry" {
		t.Errorf("access = %+v, want one registry entry", claims.Access)
	}
}

func TestHandler_Token_BadScope(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/token?service=registry.example.com&scope=bad", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandler_Token_ServiceRequired(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:actions/x:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (service is required)", rr.Code)
	}
}

func TestHandler_Token_ServiceNotAllowed(t *testing.T) {
	h := newTestHandler(t, nil)
	h.cfg.Server.AllowedServices = []string{"registry.example.com"}
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=other.example.com&scope=repository:actions/x:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (service not allowed)", rr.Code)
	}
}

func TestHandler_Token_ServiceAllowed(t *testing.T) {
	h := newTestHandler(t, nil)
	h.cfg.Server.AllowedServices = []string{"registry.example.com"}
	req := httptest.NewRequest(http.MethodGet,
		"/token?service=registry.example.com&scope=repository:actions/x:pull", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (service allowed)", rr.Code)
	}
}

func TestHandler_JWKS(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("invalid JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(jwks.Keys))
	}
	if jwks.Keys[0]["kid"] == "" {
		t.Error("kid missing in JWKS")
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func parseClaims(t *testing.T, tokenStr string) Claims {
	t.Helper()
	var claims Claims
	p := jwt.NewParser()
	if _, _, err := p.ParseUnverified(tokenStr, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
