package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/jwks"
)

func createTestServer(t *testing.T) *Server {
	t.Helper()

	store, err := jwks.OpenStore(
		filepath.Join(t.TempDir(), "test.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	for _, expiration := range []time.Time{
		time.Now().Add(2 * time.Hour),
		time.Now().Add(-time.Hour),
	} {
		key, err := jwks.GenerateKey("", expiration)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveKey(key); err != nil {
			t.Fatal(err)
		}
	}

	return &Server{Store: store}
}

func TestJWKSHandler(t *testing.T) {
	server := createTestServer(t)
	valid, err := server.Store.GetKey(false)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	server.JWKSHandler(recorder, httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Keys) != 1 {
		t.Fatalf("expected one valid key, got %d", len(response.Keys))
	}
	if response.Keys[0] != valid.ToJWK() {
		t.Error("JWKS did not match the stored public key")
	}
}

func TestAuthHandler(t *testing.T) {
	server := createTestServer(t)

	tests := []struct {
		name    string
		path    string
		basic   bool
		expired bool
	}{
		{"JSON credentials", "/auth", false, false},
		{"Basic credentials", "/auth", true, false},
		{"expired key", "/auth?expired=true", false, true},
		{"parameter presence", "/auth?expired=false", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				tt.path,
				strings.NewReader(
					`{"username":"userABC","password":"password123"}`,
				),
			)
			request.Header.Set("Content-Type", "application/json")
			if tt.basic {
				request.SetBasicAuth("userABC", "password123")
			}

			recorder := httptest.NewRecorder()
			server.AuthHandler(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", recorder.Code)
			}

			var response map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["token"] == "" {
				t.Fatal("missing token")
			}

			key, err := server.Store.GetKey(tt.expired)
			if err != nil {
				t.Fatal(err)
			}

			// Check signatures for both valid and expired JWTs.
			options := []jwt.ParserOption{
				jwt.WithValidMethods([]string{"RS256"}),
			}
			if tt.expired {
				options = append(options, jwt.WithoutClaimsValidation())
			}

			token, err := jwt.Parse(
				response["token"],
				func(token *jwt.Token) (interface{}, error) {
					return &key.PrivateKey.PublicKey, nil
				},
				options...,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !token.Valid {
				t.Fatal("invalid signature or claims")
			}
			if token.Header["kid"] != key.Kid {
				t.Error("JWT kid does not match stored key")
			}

			claims := token.Claims.(jwt.MapClaims)
			exp, err := claims.GetExpirationTime()
			if err != nil || exp == nil {
				t.Fatal("missing or invalid expiration")
			}
			if tt.expired && exp.Time.After(time.Now()) {
				t.Error("expected expired JWT")
			}
			if !tt.expired && !exp.Time.After(time.Now()) {
				t.Error("expected unexpired JWT")
			}
		})
	}
}

func TestHandlersRejectWrongMethod(t *testing.T) {
	server := createTestServer(t)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"JWKS", server.JWKSHandler, http.MethodPost},
		{"auth", server.AuthHandler, http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.handler(recorder, httptest.NewRequest(tt.method, "/", nil))
			if recorder.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d", recorder.Code)
			}
		})
	}
}

func TestHandlersDatabaseFailure(t *testing.T) {
	server := createTestServer(t)
	server.Store.Close()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"JWKS", server.JWKSHandler, http.MethodGet},
		{"auth", server.AuthHandler, http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.handler(recorder, httptest.NewRequest(tt.method, "/", nil))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", recorder.Code)
			}
		})
	}
}
