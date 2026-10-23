package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/jwks"
)

// Server retrieves signing keys from SQLite.
type Server struct {
	Store *jwks.Store
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []jwks.JWK `json:"keys"`
}

// JWKSHandler returns all unexpired public keys.
func (s *Server) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys, err := s.Store.ValidKeys()
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	response := JWKS{Keys: make([]jwks.JWK, 0, len(keys))}
	for _, key := range keys {
		response.Keys = append(response.Keys, key.ToJWK())
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// AuthHandler mocks authentication and signs a JWT using a stored key.
func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Any presence of this parameter selects an expired key.
	_, expired := r.URL.Query()["expired"]

	key, err := s.Store.GetKey(expired)
	if err != nil {
		http.Error(w, "failed to read signing key", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	expiration := now.Add(time.Hour)
	if expired {
		expiration = key.ExpiresAt
	} else if key.ExpiresAt.Before(expiration) {
		expiration = key.ExpiresAt
	}

	claims := jwt.MapClaims{
		"sub": "userABC",
		"iat": now.Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": signedToken,
	})
}
