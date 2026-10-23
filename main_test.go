package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestCreateServerWithDB(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "test.db")

	server, err := createServerWithDB(filename)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := server.Store.GetKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if valid.IsExpired() {
		t.Error("expected an unexpired key")
	}

	expired, err := server.Store.GetKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if !expired.IsExpired() {
		t.Error("expected an expired key")
	}
	if valid.Kid == expired.Kid {
		t.Error("keys must have different IDs")
	}

	if err := server.Store.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening the database must preserve the same key.
	reopened, err := createServerWithDB(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Store.Close()

	persisted, err := reopened.Store.GetKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Kid != valid.Kid ||
		persisted.PrivateKey.N.Cmp(valid.PrivateKey.N) != 0 {
		t.Error("key did not persist across restart")
	}
}

func TestCreateServerInvalidPath(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing", "test.db")
	if server, err := createServerWithDB(filename); err == nil {
		server.Store.Close()
		t.Fatal("expected an error for a missing parent directory")
	}
}

func TestCreateMux(t *testing.T) {
	server, err := createServerWithDB(
		filepath.Join(t.TempDir(), "test.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Store.Close()

	mux := createMux(server)

	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/.well-known/jwks.json", 200},
		{http.MethodPost, "/auth", 200},
		{http.MethodPost, "/auth?expired=true", 200},
		{http.MethodGet, "/missing", 404},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, nil)
			mux.ServeHTTP(recorder, request)

			if recorder.Code != tt.status {
				t.Fatalf("expected %d, got %d", tt.status, recorder.Code)
			}
		})
	}
}
