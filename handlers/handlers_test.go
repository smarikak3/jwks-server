package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/jwks"
)

func createTestServer(t *testing.T) *Server {
	t.Helper()

	validKey, err := jwks.GenerateKey(
		"valid-test-key",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("failed to generate valid key: %v", err)
	}

	expiredKey, err := jwks.GenerateKey(
		"expired-test-key",
		time.Now().Add(-time.Hour),
	)
	if err != nil {
		t.Fatalf("failed to generate expired key: %v", err)
	}

	return &Server{
		ValidKey:   validKey,
		ExpiredKey: expiredKey,
	}
}

func TestJWKSHandler(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.JWKSHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}

	var response JWKS

	err := json.NewDecoder(recorder.Body).Decode(&response)
	if err != nil {
		t.Fatalf("failed to decode JWKS response: %v", err)
	}

	if len(response.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(response.Keys))
	}

	if response.Keys[0].Kid != "valid-test-key" {
		t.Errorf(
			"expected valid-test-key, got %s",
			response.Keys[0].Kid,
		)
	}

	if response.Keys[0].Kid == "expired-test-key" {
		t.Error("expired key should not appear in JWKS")
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.JWKSHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"expected status 405, got %d",
			recorder.Code,
		)
	}
}

func TestAuthHandler(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.AuthHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var response map[string]string

	err := json.NewDecoder(recorder.Body).Decode(&response)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokenString := response["token"]

	if tokenString == "" {
		t.Fatal("expected JWT token")
	}

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &server.ValidKey.PrivateKey.PublicKey, nil
		},
	)

	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	if !token.Valid {
		t.Error("expected valid JWT")
	}

	if token.Header["kid"] != "valid-test-key" {
		t.Errorf(
			"expected valid-test-key kid, got %v",
			token.Header["kid"],
		)
	}
}

func TestExpiredAuthHandler(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	recorder := httptest.NewRecorder()

	server.AuthHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var response map[string]string

	err := json.NewDecoder(recorder.Body).Decode(&response)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tokenString := response["token"]

	if tokenString == "" {
		t.Fatal("expected expired JWT token")
	}

	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, _, err := parser.ParseUnverified(
		tokenString,
		jwt.MapClaims{},
	)

	if err != nil {
		t.Fatalf("failed to parse expired JWT: %v", err)
	}

	if token.Header["kid"] != "expired-test-key" {
		t.Errorf(
			"expected expired-test-key kid, got %v",
			token.Header["kid"],
		)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	expValue, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("failed to get expiration time: %v", err)
	}

	if expValue == nil {
		t.Fatal("expected exp claim")
	}

	if expValue.Time.After(time.Now()) {
		t.Error("expected JWT expiration time to be in the past")
	}
}

func TestAuthRejectsGet(t *testing.T) {
	server := createTestServer(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/auth",
		strings.NewReader(""),
	)

	recorder := httptest.NewRecorder()

	server.AuthHandler(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"expected status 405, got %d",
			recorder.Code,
		)
	}
}
