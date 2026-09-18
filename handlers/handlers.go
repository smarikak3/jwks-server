package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/jwks"
)

// Server contains the keys used by the JWKS server.
type Server struct {
	ValidKey   *jwks.Key
	ExpiredKey *jwks.Key
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []jwks.JWK `json:"keys"`
}

// JWKSHandler serves public keys that have not expired.
func (s *Server) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := []jwks.JWK{}

	if !s.ValidKey.IsExpired() {
		keys = append(keys, s.ValidKey.ToJWK())
	}

	response := JWKS{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(response)
}

// AuthHandler issues a JWT.
func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := s.ValidKey

	// Check whether the expired query parameter is present.
	expired := false
	if _, exists := r.URL.Query()["expired"]; exists {
		expired = true
		key = s.ExpiredKey
	}

	// Normal JWTs expire in one hour.
	expiration := time.Now().Add(time.Hour)

	// Expired JWTs use an expiration time in the past.
	if expired {
		expiration = time.Now().Add(-time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Include the key ID in the JWT header.
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(
			w,
			"failed to sign token",
			http.StatusInternalServerError,
		)
		return
	}

	response := map[string]string{
		"token": signedToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(response)
}
