package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"jwks-server/handlers"
	"jwks-server/jwks"
)

const databaseFile = "totally_not_my_privateKeys.db"

// createServer opens the persistent database.
func createServer() (*handlers.Server, error) {
	return createServerWithDB(databaseFile)
}

// createServerWithDB also lets tests use a separate temporary database.
func createServerWithDB(filename string) (*handlers.Server, error) {
	store, err := jwks.OpenStore(filename)
	if err != nil {
		return nil, err
	}

	// Keep existing keys. Add replacements only when needed.
	for _, expired := range []bool{false, true} {
		key, err := store.GetKey(expired)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			store.Close()
			return nil, fmt.Errorf("check stored keys: %w", err)
		}

		// At startup, ensure a valid key lasts at least another hour.
		if err == nil && (expired ||
			key.ExpiresAt.Unix() >= time.Now().Add(time.Hour).Unix()) {
			continue
		}

		expiration := time.Now().Add(24 * time.Hour)
		if expired {
			expiration = time.Now().Add(-time.Hour)
		}

		key, err = jwks.GenerateKey("", expiration)
		if err != nil {
			store.Close()
			return nil, err
		}

		if err := store.SaveKey(key); err != nil {
			store.Close()
			return nil, err
		}
	}

	return &handlers.Server{Store: store}, nil
}

// createMux configures the HTTP routes.
func createMux(server *handlers.Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	mux.HandleFunc("/auth", server.AuthHandler)
	return mux
}

func main() {
	server, err := createServer()
	if err != nil {
		log.Fatal(err)
	}
	defer server.Store.Close()

	httpServer := &http.Server{
		Addr:              ":8080",
		Handler:           createMux(server),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("JWKS server running on http://localhost:8080")
	if err := httpServer.ListenAndServe(); err != nil {
		log.Print(err)
	}
}
