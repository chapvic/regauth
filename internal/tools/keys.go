package tools

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"strings"
)

func ComputeLibtrustKid(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:30])
	enc = strings.ToUpper(enc)
	var b strings.Builder
	for i := 0; i < len(enc); i += 4 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(enc[i : i+4])
	}
	return b.String()
}

// buildJWKS формирует JWKS из списка публичных ключей.
func buildJWKS(keys []*rsa.PublicKey) []byte {
	var entries []map[string]any
	for _, pub := range keys {
		kid := ComputeLibtrustKid(pub)
		entries = append(entries, jwkEntry(pub, kid))
	}
	jwks := map[string]any{"keys": entries}
	data, _ := json.MarshalIndent(jwks, "", "  ")
	return data
}

func jwkEntry(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64URLUInt(pub.N),
		"e":   base64URLUInt(big.NewInt(int64(pub.E))),
	}
}

func base64URLUInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// appendJWKS читает существующий JWKS-файл и добавляет в него новый ключ.
// Если файла нет или он битый — создаёт новый JWKS с одним ключом.
func appendJWKS(path string, newPub *rsa.PublicKey) error {
	var existing []map[string]any
	if data, err := os.ReadFile(path); err == nil {
		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		if json.Unmarshal(data, &jwks) == nil {
			existing = jwks.Keys
		}
	}
	newKid := ComputeLibtrustKid(newPub)
	for _, e := range existing {
		if e["kid"] == newKid {
			return nil
		}
	}
	existing = append(existing, jwkEntry(newPub, newKid))
	data, _ := json.MarshalIndent(map[string]any{"keys": existing}, "", "  ")
	return AtomicWrite(path, data, 0o644)
}
