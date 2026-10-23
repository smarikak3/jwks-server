package jwks

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// Store manages private keys persisted in SQLite.
type Store struct {
	DB *sql.DB
}

// OpenStore opens the database and creates the required table.
func OpenStore(filename string) (*Store, error) {
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create keys table: %w", err)
	}

	return &Store{DB: db}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.DB.Close()
}

// SaveKey stores a PEM-encoded private key using SQL parameters.
// The database-generated ID becomes the key's JWT kid.
func (s *Store) SaveKey(key *Key) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key.PrivateKey),
	})

	result, err := s.DB.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		data,
		key.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("save key: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read inserted ID: %w", err)
	}

	key.Kid = strconv.FormatInt(id, 10)
	return nil
}

// decodeKey restores an RSA private key from a database row.
func decodeKey(id int64, data []byte, exp int64) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &Key{
		PrivateKey: privateKey,
		Kid:        strconv.FormatInt(id, 10),
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

// GetKey reads either an expired or an unexpired key.
func (s *Store) GetKey(expired bool) (*Key, error) {
	query := `
		SELECT kid, key, exp FROM keys
		WHERE exp > ?
		ORDER BY exp DESC LIMIT 1
	`
	if expired {
		query = `
			SELECT kid, key, exp FROM keys
			WHERE exp <= ?
			ORDER BY exp DESC LIMIT 1
		`
	}

	var id, exp int64
	var data []byte

	err := s.DB.QueryRow(query, time.Now().Unix()).Scan(
		&id, &data, &exp,
	)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	return decodeKey(id, data, exp)
}

// ValidKeys reads all unexpired keys for the JWKS endpoint.
func (s *Store) ValidKeys() ([]*Key, error) {
	rows, err := s.DB.Query(
		"SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
		time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("query valid keys: %w", err)
	}
	defer rows.Close()

	keys := make([]*Key, 0)

	for rows.Next() {
		var id, exp int64
		var data []byte

		if err := rows.Scan(&id, &data, &exp); err != nil {
			return nil, fmt.Errorf("read key row: %w", err)
		}

		key, err := decodeKey(id, data, exp)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate keys: %w", err)
	}

	return keys, nil
}
