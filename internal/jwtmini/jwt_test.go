package jwtmini

import (
	"strings"
	"testing"
	"time"
)

func testClaims() map[string]any {
	return map[string]any{
		"iss": "http://issuer.example", "sub": "user-1", "aud": "records-api",
		"exp": time.Now().Add(time.Hour).Unix(), "scope": "records:read",
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Sign(key, testClaims())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyRS256(&key.PublicKey, tok)
	if err != nil {
		t.Fatal(err)
	}
	if StringClaim(claims, "sub") != "user-1" {
		t.Fatalf("sub = %q", StringClaim(claims, "sub"))
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	key, _ := GenerateKey()
	tok, _ := Sign(key, testClaims())
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	bad := parts[0] + "." + parts[1] + "." + string(sig)
	if _, err := VerifyRS256(&key.PublicKey, bad); err != ErrBadSignature {
		t.Fatalf("tampered token: err = %v, want ErrBadSignature", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	tok, _ := Sign(k1, testClaims())
	if _, err := VerifyRS256(&k2.PublicKey, tok); err != ErrBadSignature {
		t.Fatalf("wrong key: err = %v, want ErrBadSignature", err)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	key, _ := GenerateKey()
	tok, _ := Sign(key, testClaims())
	parts := strings.Split(tok, ".")
	// Swap in a payload claiming admin scope, keep the old signature.
	evil := `{"iss":"http://issuer.example","sub":"user-1","aud":"records-api","exp":9999999999,"scope":"records:write"}`
	bad := parts[0] + "." + b64e([]byte(evil)) + "." + parts[2]
	if _, err := VerifyRS256(&key.PublicKey, bad); err != ErrBadSignature {
		t.Fatalf("payload swap: err = %v, want ErrBadSignature", err)
	}
}

func TestJWKSRoundtrip(t *testing.T) {
	key, _ := GenerateKey()
	doc := JWKS(&key.PublicKey)
	keys := PublicKeysFromJWKS(doc)
	pub, ok := keys[KeyID(&key.PublicKey)]
	if !ok {
		t.Fatal("kid not found in JWKS roundtrip")
	}
	tok, _ := Sign(key, testClaims())
	if _, err := VerifyRS256(pub, tok); err != nil {
		t.Fatalf("verify with JWKS-extracted key: %v", err)
	}
}
