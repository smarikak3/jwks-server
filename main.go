package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"jwks-server/handlers"
	"jwks-server/jwks"
)

// createServer generates the valid and expired RSA keys.
func createServer() (*handlers.Server, error) {
	validKey, err := jwks.GenerateKey(
		"valid-key-1",
		time.Now().Add(24*time.Hour),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate valid key: %w", err)
	}

	expiredKey, err := jwks.GenerateKey(
		"expired-key-1",
		time.Now().Add(-24*time.Hour),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate expired key: %w", err)
	}

	return &handlers.Server{
		ValidKey:   validKey,
		ExpiredKey: expiredKey,
	}, nil
}

// createMux configures the HTTP routes.
func createMux(server *handlers.Server) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"/.well-known/jwks.json",
		server.JWKSHandler,
	)

	mux.HandleFunc(
		"/auth",
		server.AuthHandler,
	)

	return mux
}

func main() {
	server, err := createServer()
	if err != nil {
		log.Fatal(err)
	}

	mux := createMux(server)

	log.Println("JWKS server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
