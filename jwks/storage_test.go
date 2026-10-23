package jwks

import (
	"database/sql"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func saveTestKey(t *testing.T, store *Store, expiration time.Time) *Key {
	t.Helper()

	key, err := GenerateKey("", expiration)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKey(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestStoreSaveAndRead(t *testing.T) {
	store := newTestStore(t)

	valid := saveTestKey(t, store, time.Now().Add(2*time.Hour))
	expired := saveTestKey(t, store, time.Now().Add(-time.Hour))

	if valid.Kid == "" || valid.Kid == expired.Kid {
		t.Fatal("expected unique database-generated key IDs")
	}

	for _, want := range []*Key{valid, expired} {
		got, err := store.GetKey(want.IsExpired())
		if err != nil {
			t.Fatal(err)
		}

		if got.Kid != want.Kid {
			t.Error("stored key ID does not match")
		}
		if !got.PrivateKey.Equal(want.PrivateKey) {
			t.Error("private key changed after serialization")
		}
		if got.ExpiresAt.Unix() != want.ExpiresAt.Unix() {
			t.Error("stored expiration does not match")
		}
	}
}

func TestValidKeysFiltersExpired(t *testing.T) {
	store := newTestStore(t)

	first := saveTestKey(t, store, time.Now().Add(2*time.Hour))
	second := saveTestKey(t, store, time.Now().Add(3*time.Hour))
	saveTestKey(t, store, time.Now().Add(-time.Hour))

	keys, err := store.ValidKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected two valid keys, got %d", len(keys))
	}
	if keys[0].Kid != first.Kid || keys[1].Kid != second.Kid {
		t.Error("unexpected valid key IDs or order")
	}
}

func TestEmptyStore(t *testing.T) {
	store := newTestStore(t)

	for _, expired := range []bool{false, true} {
		if _, err := store.GetKey(expired); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("expected no rows, got %v", err)
		}
	}

	keys, err := store.ValidKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatal("expected no valid keys")
	}
}

func TestStorePersistsAfterClose(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "persistent.db")
	store, err := OpenStore(filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	want := saveTestKey(t, store, time.Now().Add(2*time.Hour))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	got, err := reopened.GetKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kid != want.Kid || !got.PrivateKey.Equal(want.PrivateKey) {
		t.Fatal("key did not persist after reopening database")
	}
}

func TestDecodeKeyRejectsInvalidData(t *testing.T) {
	inputs := [][]byte{
		[]byte("not PEM"),
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("not an RSA key"),
		}),
	}

	for _, input := range inputs {
		if _, err := decodeKey(1, input, time.Now().Unix()); err == nil {
			t.Error("expected invalid key data to be rejected")
		}
	}
}

func TestStoreRejectsCorruptKey(t *testing.T) {
	store := newTestStore(t)

	// Parameters keep even malicious-looking data separate from SQL.
	_, err := store.DB.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("'; DROP TABLE keys; --"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetKey(false); err == nil {
		t.Error("expected corrupt key error")
	}
	if _, err := store.ValidKeys(); err == nil {
		t.Error("expected corrupt key error")
	}

	var count int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatalf("keys table should still exist: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one stored row, got %d", count)
	}
}

func TestStoreClosedDatabase(t *testing.T) {
	store := newTestStore(t)
	key := saveTestKey(t, store, time.Now().Add(time.Hour))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveKey(key); err == nil {
		t.Error("expected save error")
	}
	if _, err := store.GetKey(false); err == nil {
		t.Error("expected read error")
	}
	if _, err := store.ValidKeys(); err == nil {
		t.Error("expected query error")
	}
}

func TestOpenStoreInvalidPath(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing", "test.db")
	store, err := OpenStore(filename)
	if err == nil {
		store.Close()
		t.Fatal("expected error for missing parent directory")
	}
}
