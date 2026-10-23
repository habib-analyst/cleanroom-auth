// Package jwtmini is a minimal RS256 JWT implementation on the Go standard
// library only: signing for the IdP, parsing and signature verification for
// resource servers. It intentionally supports exactly one algorithm.
package jwtmini

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func b64e(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// KeyID derives a stable key id from an RSA public key.
func KeyID(pub *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(pub)
	h := sha256.Sum256(der)
	return b64e(h[:9])
}

// GenerateKey creates a fresh RSA-2048 signing key. Keys are generated at
// runtime; no key material is ever committed to this repository.
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Sign produces a compact RS256 JWT for the given claims.
func Sign(priv *rsa.PrivateKey, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": KeyID(&priv.PublicKey)}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64e(hb) + "." + b64e(cb)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64e(sig), nil
}

// ParseUnverified splits a compact JWT into header and claims without any
// verification. Callers must pass the result through VerifyRS256.
func ParseUnverified(token string) (header, claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("jwt: malformed token")
	}
	hb, err := b64d(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("jwt: bad header encoding: %w", err)
	}
	cb, err := b64d(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("jwt: bad claims encoding: %w", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("jwt: bad header json: %w", err)
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, fmt.Errorf("jwt: bad claims json: %w", err)
	}
	return header, claims, nil
}

var ErrBadSignature = errors.New("jwt: signature verification failed")

// VerifyRS256 checks the RS256 signature of token against pub and returns
// the claims. It does not check exp/iss/aud — that is the caller's job,
// because the expected values differ per resource.
func VerifyRS256(pub *rsa.PublicKey, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: malformed token")
	}
	header, claims, err := ParseUnverified(token)
	if err != nil {
		return nil, err
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return nil, fmt.Errorf("jwt: unexpected alg %q", alg)
	}
	sig, err := b64d(parts[2])
	if err != nil {
		return nil, ErrBadSignature
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, ErrBadSignature
	}
	return claims, nil
}

// JWKS renders a public key as a one-key JWKS document.
func JWKS(pub *rsa.PublicKey) map[string]any {
	e := big.NewInt(int64(pub.E))
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": KeyID(pub),
			"n":   b64e(pub.N.Bytes()),
			"e":   b64e(e.Bytes()),
		}},
	}
}

// jwksWire is the typed wire form of a JWKS document. Parsing via JSON
// keeps behaviour identical whether the document arrived over HTTP or was
// built in-process as a map.
type jwksWire struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func parseJWKS(doc map[string]any) (jwksWire, error) {
	var wire jwksWire
	raw, err := json.Marshal(doc)
	if err != nil {
		return wire, err
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return wire, fmt.Errorf("jwks: bad document: %w", err)
	}
	return wire, nil
}

// PublicKeyFromJWKS extracts the key with the given kid from a JWKS document.
func PublicKeyFromJWKS(doc map[string]any, kid string) (*rsa.PublicKey, error) {
	wire, err := parseJWKS(doc)
	if err != nil {
		return nil, err
	}
	for _, k := range wire.Keys {
		if k.Kid != kid {
			continue
		}
		nb, err := b64d(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := b64d(k.E)
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eb)
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
	}
	return nil, fmt.Errorf("jwks: kid %q not found", kid)
}

// StringClaim / TimeClaim helpers for claim maps decoded from JSON.
func StringClaim(c map[string]any, name string) string {
	if v, ok := c[name].(string); ok {
		return v
	}
	return ""
}

func TimeClaim(c map[string]any, name string) int64 {
	if v, ok := c[name].(float64); ok {
		return int64(v)
	}
	return 0
}

// PublicKeysFromJWKS extracts every RSA public key in a JWKS document,
// keyed by kid.
func PublicKeysFromJWKS(doc map[string]any) map[string]*rsa.PublicKey {
	out := map[string]*rsa.PublicKey{}
	wire, err := parseJWKS(doc)
	if err != nil {
		return out
	}
	for _, k := range wire.Keys {
		if k.Kid == "" {
			continue
		}
		if pub, err := PublicKeyFromJWKS(doc, k.Kid); err == nil {
			out[k.Kid] = pub
		}
	}
	return out
}
