package jwks

import (
	"testing"
	"time"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(
		"test-key",
		time.Now().Add(time.Hour),
	)

	if err != nil {
		t.Fatalf("GenerateKey returned an error: %v", err)
	}

	if key.PrivateKey == nil {
		t.Error("expected private key to be generated")
	}

	if key.Kid != "test-key" {
		t.Errorf("expected kid test-key, got %s", key.Kid)
	}
}

func TestIsExpired(t *testing.T) {
	expiredKey, err := GenerateKey(
		"expired-test-key",
		time.Now().Add(-time.Hour),
	)

	if err != nil {
		t.Fatalf("GenerateKey returned an error: %v", err)
	}

	if !expiredKey.IsExpired() {
		t.Error("expected key to be expired")
	}
}

func TestIsNotExpired(t *testing.T) {
	validKey, err := GenerateKey(
		"valid-test-key",
		time.Now().Add(time.Hour),
	)

	if err != nil {
		t.Fatalf("GenerateKey returned an error: %v", err)
	}

	if validKey.IsExpired() {
		t.Error("expected key to be valid")
	}
}

func TestToJWK(t *testing.T) {
	key, err := GenerateKey(
		"test-key",
		time.Now().Add(time.Hour),
	)

	if err != nil {
		t.Fatalf("GenerateKey returned an error: %v", err)
	}

	jwk := key.ToJWK()

	if jwk.Kid != "test-key" {
		t.Errorf("expected kid test-key, got %s", jwk.Kid)
	}

	if jwk.Kty != "RSA" {
		t.Errorf("expected kty RSA, got %s", jwk.Kty)
	}

	if jwk.Use != "sig" {
		t.Errorf("expected use sig, got %s", jwk.Use)
	}

	if jwk.Alg != "RS256" {
		t.Errorf("expected alg RS256, got %s", jwk.Alg)
	}

	if jwk.N == "" {
		t.Error("expected modulus N to not be empty")
	}

	if jwk.E == "" {
		t.Error("expected exponent E to not be empty")
	}
}
