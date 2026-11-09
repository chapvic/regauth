package tools

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// Claims — кастомная структура, чтобы aud был строкой (требование distribution v2).
type Claims struct {
	Issuer    string        `json:"iss,omitempty"`
	Subject   string        `json:"sub,omitempty"`
	Audience  string        `json:"aud,omitempty"` // строка, не массив
	ExpiresAt int64         `json:"exp,omitempty"`
	NotBefore int64         `json:"nbf,omitempty"`
	IssuedAt  int64         `json:"iat,omitempty"`
	Access    []AccessEntry `json:"access"`
}

// Реализация интерфейса jwt.Claims (требуется в jwt/v5).
func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c Claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c Claims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

func (c Claims) GetID() (string, error) {
	return "", nil
}

type Issuer struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	ttl    time.Duration
}

func NewIssuer(key *rsa.PrivateKey, kid, issuer string, ttl time.Duration) *Issuer {
	return &Issuer{key: key, kid: kid, issuer: issuer, ttl: ttl}
}

func (i *Issuer) Issue(subject, audience string, access []AccessEntry) (string, error) {
	now := time.Now()
	claims := Claims{
		Issuer:    i.issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(i.ttl).Unix(),
		Access:    access,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = i.kid
	return t.SignedString(i.key)
}
