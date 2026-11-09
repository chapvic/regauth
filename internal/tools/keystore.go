package tools

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// KeystoreFile — единый источник истины для ключей v2 и v3.
type KeystoreFile struct {
	V2 V2Key      `yaml:"v2"`
	V3 V3KeyStore `yaml:"v3"`
}

type V2Key struct {
	CreatedAt time.Time `yaml:"created_at"`
	Private   string    `yaml:"private"`
}

type V3KeyStore struct {
	Keys []V3Key `yaml:"keys"`
}

type V3Key struct {
	KID       string    `yaml:"kid"`
	CreatedAt time.Time `yaml:"created_at"`
	Current   bool      `yaml:"current"`
	Revoked   bool      `yaml:"revoked"`
	Private   string    `yaml:"private"`
}

var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrKeyNotRevoked = errors.New("key is not revoked")
	ErrCurrentKey    = errors.New("cannot revoke or delete the current signing key; run keystore rotate first")
	ErrV2NotAllowed  = errors.New("v2 key is not rotatable/revocable")
)

func NewKeystore() *KeystoreFile {
	return &KeystoreFile{V3: V3KeyStore{Keys: []V3Key{}}}
}

func LoadKeystore(path string) (*KeystoreFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewKeystore(), nil
	}
	if err != nil {
		return nil, err
	}
	// Если файл пустой (только пробелы, \n, \r\n) — считаем, что его нет.
	if strings.TrimSpace(string(data)) == "" {
		return NewKeystore(), nil
	}
	var ks KeystoreFile
	if err := yaml.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if ks.V3.Keys == nil {
		ks.V3.Keys = []V3Key{}
	}
	return &ks, nil
}

func (ks *KeystoreFile) Save(path string) error {
	data, err := yaml.Marshal(ks)
	if err != nil {
		return err
	}
	return AtomicWrite(path, data, 0o600)
}

func (ks *KeystoreFile) HasV2() bool { return ks.V2.Private != "" }

func (ks *KeystoreFile) SetV2(priv *rsa.PrivateKey) {
	ks.V2.CreatedAt = time.Now().UTC()
	ks.V2.Private = pemEncodePrivate(priv)
}

func (ks *KeystoreFile) V2Private() (*rsa.PrivateKey, error) {
	if ks.V2.Private == "" {
		return nil, errors.New("v2 key is missing")
	}
	return pemDecodePrivate(ks.V2.Private)
}

func (ks *KeystoreFile) AddCurrentV3(kid string, priv *rsa.PrivateKey) {
	for i := range ks.V3.Keys {
		ks.V3.Keys[i].Current = false
	}
	ks.V3.Keys = append(ks.V3.Keys, V3Key{
		KID:       kid,
		CreatedAt: time.Now().UTC(),
		Current:   true,
		Revoked:   false,
		Private:   pemEncodePrivate(priv),
	})
}

func (ks *KeystoreFile) CurrentV3() (V3Key, error) {
	for _, e := range ks.V3.Keys {
		if e.Current && !e.Revoked {
			return e, nil
		}
	}
	return V3Key{}, errors.New("keystore has no current v3 key")
}

func (ks *KeystoreFile) MarkRevokedV3(kid string) error {
	for i := range ks.V3.Keys {
		if ks.V3.Keys[i].KID == kid {
			if ks.V3.Keys[i].Current {
				return ErrCurrentKey
			}
			if ks.V3.Keys[i].Revoked {
				return nil
			}
			ks.V3.Keys[i].Revoked = true
			ks.V3.Keys[i].Private = ""
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
}

func (ks *KeystoreFile) DeleteV3(kid string) error {
	for i := range ks.V3.Keys {
		if ks.V3.Keys[i].KID == kid {
			if !ks.V3.Keys[i].Revoked {
				return ErrKeyNotRevoked
			}
			ks.V3.Keys = append(ks.V3.Keys[:i], ks.V3.Keys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
}

func (ks *KeystoreFile) CleanupV3() int {
	kept := ks.V3.Keys[:0]
	removed := 0
	for _, e := range ks.V3.Keys {
		if e.Revoked {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	ks.V3.Keys = kept
	return removed
}

func (ks *KeystoreFile) ActiveV3() []V3Key {
	out := make([]V3Key, 0, len(ks.V3.Keys))
	for _, e := range ks.V3.Keys {
		if !e.Revoked {
			out = append(out, e)
		}
	}
	return out
}

// WritePublicV2 пишет X.509 сертификат (CERTIFICATE) для distribution v2.
func (ks *KeystoreFile) WritePublicV2(path string) error {
	priv, err := ks.V2Private()
	if err != nil {
		return err
	}
	certPEM, err := pemEncodeSelfSignedCert(priv)
	if err != nil {
		return err
	}
	return AtomicWrite(path, certPEM, 0o644)
}

func (ks *KeystoreFile) WriteJWKS(path string) error {
	var entries []map[string]any
	for _, e := range ks.ActiveV3() {
		priv, err := pemDecodePrivate(e.Private)
		if err != nil {
			return fmt.Errorf("active key %s: parse private: %w", e.KID, err)
		}
		if ComputeLibtrustKid(&priv.PublicKey) != e.KID {
			return fmt.Errorf("active key %s: private key does not match kid", e.KID)
		}
		entries = append(entries, jwkEntry(&priv.PublicKey, e.KID))
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	data, err := json.MarshalIndent(map[string]any{"keys": entries}, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(path, data, 0o644)
}

func (ks *KeystoreFile) PrivateV3() (*rsa.PrivateKey, string, error) {
	cur, err := ks.CurrentV3()
	if err != nil {
		return nil, "", err
	}
	priv, err := pemDecodePrivate(cur.Private)
	if err != nil {
		return nil, "", fmt.Errorf("current v3 key: parse private: %w", err)
	}
	return priv, cur.KID, nil
}
