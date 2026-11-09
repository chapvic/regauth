package tools

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Handler struct {
	mu       sync.RWMutex
	store    *Store
	cfg      *Config
	insecure bool
	jwksPath string
}

func NewHandler(store *Store, cfg *Config, insecure bool, jwksPath string) *Handler {
	return &Handler{store: store, cfg: cfg, insecure: insecure, jwksPath: jwksPath}
}

func (h *Handler) Reload(store *Store, cfg *Config, jwksPath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.store = store
	h.cfg = cfg
	h.jwksPath = jwksPath
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	cfg := h.cfg
	insecure := h.insecure
	jwksPath := h.jwksPath
	h.mu.RUnlock()

	if !insecure && !originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	if r.URL.Path == "/.well-known/jwks.json" {
		h.serveJWKS(w, r, jwksPath)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.serveToken(w, r, cfg)
}

func (h *Handler) serveJWKS(w http.ResponseWriter, r *http.Request, jwksPath string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile(jwksPath)
	if err != nil {
		slog.Error("jwks: read failed", "path", jwksPath, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (h *Handler) serveToken(w http.ResponseWriter, r *http.Request, cfg *Config) {
	h.mu.RLock()
	store := h.store
	h.mu.RUnlock()

	service := r.URL.Query().Get("service")
	if service == "" {
		http.Error(w, "service is required", http.StatusBadRequest)
		return
	}
	if !cfg.IsServiceAllowed(service) {
		slog.Warn("auth: service not allowed", "service", service, "remote", r.RemoteAddr)
		http.Error(w, "service not allowed", http.StatusBadRequest)
		return
	}

	scopes, err := ParseScope(r.URL.Query().Get("scope"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, password, hasAuth := basicAuth(r)
	var rules []Rule
	var subject string
	var actor string

	if hasAuth {
		u, isAnon, ok := store.Authenticate(user, password)
		if isAnon {
			if u != nil {
				rules = u.Rules
			}
			actor = "anonymous"
			slog.Info("auth: anonymous (ANONYMOUS credentials ignored)", "remote", r.RemoteAddr)
		} else if ok {
			rules = u.Rules
			subject = user
			actor = user
			slog.Info("auth: login ok", "user", user, "remote", r.RemoteAddr)
		} else {
			slog.Warn("auth: login failed", "user", user, "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		if f, err := store.Load(); err == nil {
			if anon, ok := f.Users[Anonymous]; ok && anon != nil {
				rules = anon.Rules
			}
		}
		actor = "anonymous"
		slog.Info("auth: anonymous (no credentials)", "remote", r.RemoteAddr)
	}

	var access []AccessEntry
	for _, sc := range scopes {
		if !IsKnownType(sc.Type) {
			slog.Info("policy: unknown scope type, denied",
				"actor", actor, "type", sc.Type, "name", sc.Name, "requested", sc.Actions)
			continue
		}
		granted := GrantedActions(rules, sc.Type, sc.Name, sc.Actions)
		if len(granted) > 0 {
			access = append(access, AccessEntry{Type: sc.Type, Name: sc.Name, Actions: granted})
			slog.Info("policy: granted",
				"actor", actor, "type", sc.Type, "name", sc.Name,
				"requested", sc.Actions, "granted", granted)
		} else {
			slog.Info("policy: denied",
				"actor", actor, "type", sc.Type, "name", sc.Name, "requested", sc.Actions)
		}
	}

	privKey, kid, err := cfg.SigningKey()
	if err != nil {
		slog.Error("token: signing key selection failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	issuer := NewIssuer(privKey, kid, "regauth", 5*time.Minute)
	jwtStr, err := issuer.Issue(subject, service, access)
	if err != nil {
		slog.Error("issue token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	slog.Info("token: issued", "actor", actor, "service", service, "entries", len(access))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": jwtStr})
}

func basicAuth(r *http.Request) (user, pass string, ok bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return origin == "https://"+r.Host || origin == "http://"+r.Host
}
