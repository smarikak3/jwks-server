package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateServer(t *testing.T) {
	server, err := createServer()

	if err != nil {
		t.Fatalf("createServer returned an error: %v", err)
	}

	if server == nil {
		t.Fatal("expected server to be created")
	}

	if server.ValidKey == nil {
		t.Fatal("expected valid key")
	}

	if server.ExpiredKey == nil {
		t.Fatal("expected expired key")
	}

	if server.ValidKey.Kid != "valid-key-1" {
		t.Errorf(
			"expected valid-key-1, got %s",
			server.ValidKey.Kid,
		)
	}

	if server.ValidKey.IsExpired() {
		t.Error("valid key should not be expired")
	}

	if !server.ExpiredKey.IsExpired() {
		t.Error("expired key should be expired")
	}
}

func TestCreateMux(t *testing.T) {
	server, err := createServer()
	if err != nil {
		t.Fatalf("createServer returned an error: %v", err)
	}

	mux := createMux(server)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	recorder := httptest.NewRecorder()

	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf(
			"expected status 200, got %d",
			recorder.Code,
		)
	}
}

func TestCreateMuxAuth(t *testing.T) {
	server, err := createServer()
	if err != nil {
		t.Fatalf("createServer returned an error: %v", err)
	}

	mux := createMux(server)

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	recorder := httptest.NewRecorder()

	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf(
			"expected status 200, got %d",
			recorder.Code,
		)
	}
}
