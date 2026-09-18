package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

// Key represents an RSA key pair and its metadata.
type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

// GenerateKey creates a new RSA key pair.
func GenerateKey(kid string, expiresAt time.Time) (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &Key{
		PrivateKey: privateKey,
		Kid:        kid,
		ExpiresAt:  expiresAt,
	}, nil
}

// IsExpired determines whether the key has expired.
func (k *Key) IsExpired() bool {
	return time.Now().After(k.ExpiresAt)
}

// JWK represents the public portion of an RSA key.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ToJWK converts the RSA public key into JWK format.
func (k *Key) ToJWK() JWK {
	exponent := big.NewInt(int64(k.PrivateKey.E))

	return JWK{
		Kid: k.Kid,
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(k.PrivateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponent.Bytes()),
	}
}
