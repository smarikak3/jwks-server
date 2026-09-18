# JWKS Server - CSCE 3550 Project 1

## Description

This project implements a basic JWKS server in Go. The server generates RSA key pairs, assigns each key a unique Key ID (kid) and expiration time, and provides public keys through a JWKS endpoint.

The server can also issue signed JSON Web Tokens (JWTs), including expired JWTs for testing purposes.

## Endpoints

### GET /.well-known/jwks.json

Returns the public keys that have not expired in JWKS format.

### POST /auth

Returns a valid JWT signed using the unexpired RSA private key.

### POST /auth?expired=true

Returns an expired JWT signed using the expired RSA private key.

## Running the Project

Make sure Go is installed.

From the project directory, run:

```bash
go mod tidy
go run .