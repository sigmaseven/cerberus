package main

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database with the rules schema
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create rules table schema (simplified version)
	schema := `
		CREATE TABLE rules (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL DEFAULT 'sigma',
			name TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			conditions TEXT,
			sigma_yaml TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

// insertLegacyRule inserts a test rule with legacy conditions
func insertLegacyRule(t *testing.T, db *sql.DB, id, name, conditionsJSON string) {
	t.Helper()

	now := time.Now().UTC().Format(time.RFC3339)
	query := `
		INSERT INTO rules (id, type, name, description, severity, conditions, created_at, updated_at)
		VALUES (?, 'legacy', ?, 'Test rule', 'medium', ?, ?, ?)
	`

	_, err := db.Exec(query, id, name, conditionsJSON, now, now)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}
}
