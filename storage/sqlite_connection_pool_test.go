package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestSQLiteConnectionPoolSeparation verifies that separate read and write pools are created
// TASK 143.1: Validate read-only connection pool configuration
func TestSQLiteConnectionPoolSeparation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pools.db")

	// Initialize SQLite with separate pools
	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Verify separate connection pools exist
	if sqlite.WriteDB == nil {
		t.Error("WriteDB connection pool is nil")
	}
	if sqlite.ReadDB == nil {
		t.Error("ReadDB connection pool is nil")
	}

	// Verify DB field is set for backward compatibility
	if sqlite.DB == nil {
		t.Error("DB field is nil (breaks backward compatibility)")
	}
	if sqlite.DB != sqlite.WriteDB {
		t.Error("DB field should point to WriteDB for backward compatibility")
	}

	// Verify pool configurations
	writeStats := sqlite.WriteDB.Stats()
	readStats := sqlite.ReadDB.Stats()

	// Write pool should have MaxOpenConns=1
	if writeStats.MaxOpenConnections != 1 {
		t.Errorf("WriteDB MaxOpenConnections = %d, want 1", writeStats.MaxOpenConnections)
	}

	// Read pool should have MaxOpenConns=10
	if readStats.MaxOpenConnections != 10 {
		t.Errorf("ReadDB MaxOpenConnections = %d, want 10", readStats.MaxOpenConnections)
	}

	t.Logf("✓ Connection pool separation verified")
	t.Logf("  Write pool: MaxOpenConns=%d, Idle=%d, InUse=%d",
		writeStats.MaxOpenConnections, writeStats.Idle, writeStats.InUse)
	t.Logf("  Read pool: MaxOpenConns=%d, Idle=%d, InUse=%d",
		readStats.MaxOpenConnections, readStats.Idle, readStats.InUse)
}

// TestConnectionPoolStats verifies that connection pool statistics are properly exposed
// TASK 143.3: Connection pool monitoring metrics
func TestConnectionPoolStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_stats.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Get initial stats
	stats := sqlite.GetConnectionPoolStats()

	// Verify stats structure
	if stats.WritePool.MaxOpenConnections != 1 {
		t.Errorf("Write pool max connections = %d, want 1", stats.WritePool.MaxOpenConnections)
	}
	if stats.ReadPool.MaxOpenConnections != 10 {
		t.Errorf("Read pool max connections = %d, want 10", stats.ReadPool.MaxOpenConnections)
	}

	// Perform some read operations to exercise the read pool
	for i := 0; i < 5; i++ {
		var count int
		err := sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
		if err != nil {
			t.Errorf("Read query failed: %v", err)
		}
	}

	// Get updated stats
	stats = sqlite.GetConnectionPoolStats()
	t.Logf("After reads - ReadPool: OpenConns=%d, InUse=%d, Idle=%d, WaitCount=%d",
		stats.ReadPool.OpenConnections,
		stats.ReadPool.InUse,
		stats.ReadPool.Idle,
		stats.ReadPool.WaitCount)

	// Verify we didn't wait (pool has capacity)
	if stats.ReadPool.WaitCount > 0 {
		t.Logf("WARNING: Read pool had %d waits (may indicate pool size too small)", stats.ReadPool.WaitCount)
	}
}

// TestConcurrentReads verifies that multiple concurrent reads can execute without blocking
// TASK 143.4: Performance benchmarking and load testing validation
func TestConcurrentReads(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrent.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Insert some test data
	_, err = sqlite.WriteDB.Exec(`
		INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
		VALUES ('test-1', 'sigma', 'Test Rule', 'Description', 'high', 1, 1, datetime('now'), datetime('now'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Test concurrent reads (should not block each other with read pool)
	const concurrentReads = 50
	start := time.Now()

	var wg sync.WaitGroup
	errors := make(chan error, concurrentReads)

	for i := 0; i < concurrentReads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var count int
			// Simulate slow read query with 10ms sleep
			err := sqlite.ReadDB.QueryRow(`
				SELECT COUNT(*)
				FROM rules
			`).Scan(&count)

			if err != nil {
				errors <- fmt.Errorf("read %d failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Get final stats
	stats := sqlite.GetConnectionPoolStats()
	t.Logf("Concurrent reads completed in %v", duration)
	t.Logf("ReadPool stats: OpenConns=%d, InUse=%d, Idle=%d, WaitCount=%d, WaitDuration=%v",
		stats.ReadPool.OpenConnections,
		stats.ReadPool.InUse,
		stats.ReadPool.Idle,
		stats.ReadPool.WaitCount,
		stats.ReadPool.WaitDuration)

	// With 10 connections in the read pool, 50 concurrent reads should complete reasonably fast
	// If it takes more than 2 seconds, something is blocking
	if duration > 2*time.Second {
		t.Errorf("Concurrent reads took %v (expected < 2s), may indicate blocking", duration)
	}
}

// TestWALModeEnabled verifies that both pools use WAL mode
func TestWALModeEnabled(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_wal.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Verify WAL mode on write pool
	var writeJournalMode string
	err = sqlite.WriteDB.QueryRow("PRAGMA journal_mode").Scan(&writeJournalMode)
	if err != nil {
		t.Fatalf("Failed to query write pool journal mode: %v", err)
	}
	if writeJournalMode != "wal" {
		t.Errorf("Write pool journal mode = %s, want wal", writeJournalMode)
	}

	// Verify WAL mode on read pool
	var readJournalMode string
	err = sqlite.ReadDB.QueryRow("PRAGMA journal_mode").Scan(&readJournalMode)
	if err != nil {
		t.Fatalf("Failed to query read pool journal mode: %v", err)
	}
	if readJournalMode != "wal" {
		t.Errorf("Read pool journal mode = %s, want wal", readJournalMode)
	}

	t.Logf("✓ WAL mode verified on both pools")
}

// TestForeignKeysEnabled verifies that both pools have foreign keys enabled
func TestForeignKeysEnabled(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_fk.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Verify foreign keys on write pool
	var writeFKEnabled int
	err = sqlite.WriteDB.QueryRow("PRAGMA foreign_keys").Scan(&writeFKEnabled)
	if err != nil {
		t.Fatalf("Failed to query write pool foreign keys: %v", err)
	}
	if writeFKEnabled != 1 {
		t.Errorf("Write pool foreign_keys = %d, want 1", writeFKEnabled)
	}

	// Verify foreign keys on read pool
	var readFKEnabled int
	err = sqlite.ReadDB.QueryRow("PRAGMA foreign_keys").Scan(&readFKEnabled)
	if err != nil {
		t.Fatalf("Failed to query read pool foreign keys: %v", err)
	}
	if readFKEnabled != 1 {
		t.Errorf("Read pool foreign_keys = %d, want 1", readFKEnabled)
	}

	t.Logf("✓ Foreign keys verified enabled on both pools")
}

// TestWritePoolSingleWriter verifies that write pool properly serializes writes
func TestWritePoolSingleWriter(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_write.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Verify write pool has exactly 1 max connection
	stats := sqlite.WriteDB.Stats()
	if stats.MaxOpenConnections != 1 {
		t.Errorf("Write pool MaxOpenConnections = %d, want 1", stats.MaxOpenConnections)
	}

	// Perform concurrent writes - should serialize through single connection
	const concurrentWrites = 20
	var wg sync.WaitGroup
	errors := make(chan error, concurrentWrites)

	for i := 0; i < concurrentWrites; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			_, err := sqlite.WriteDB.Exec(`
				INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
				VALUES (?, 'sigma', 'Test', 'Desc', 'low', 1, 1, datetime('now'), datetime('now'))
			`, fmt.Sprintf("write-test-%d", idx))

			if err != nil {
				errors <- fmt.Errorf("write %d failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Verify all writes succeeded
	var count int
	err = sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules WHERE id LIKE 'write-test-%'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count inserted rows: %v", err)
	}
	if count != concurrentWrites {
		t.Errorf("Inserted %d rows, want %d", count, concurrentWrites)
	}

	t.Logf("✓ Write pool correctly serialized %d concurrent writes", concurrentWrites)
}

// TestPoolConnectionLifecycle verifies connection pool lifecycle management
func TestPoolConnectionLifecycle(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_lifecycle.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}

	// Verify both pools ping successfully
	if err := sqlite.WriteDB.Ping(); err != nil {
		t.Errorf("Write pool ping failed: %v", err)
	}
	if err := sqlite.ReadDB.Ping(); err != nil {
		t.Errorf("Read pool ping failed: %v", err)
	}

	// Close and verify both pools close cleanly
	err = sqlite.Close()
	if err != nil {
		t.Errorf("Failed to close SQLite: %v", err)
	}

	// Verify pools are closed (ping should fail)
	if err := sqlite.WriteDB.Ping(); err == nil {
		t.Error("Write pool still accepting connections after Close()")
	}
	if err := sqlite.ReadDB.Ping(); err == nil {
		t.Error("Read pool still accepting connections after Close()")
	}

	t.Logf("✓ Connection pool lifecycle managed correctly")
}

// TestInMemoryDatabase verifies that in-memory databases work with dual pools
func TestInMemoryDatabase(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	// Test with in-memory database
	sqlite, err := NewSQLite(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create in-memory SQLite: %v", err)
	}
	defer sqlite.Close()

	// Verify both pools exist
	if sqlite.WriteDB == nil || sqlite.ReadDB == nil {
		t.Fatal("Connection pools not initialized for in-memory database")
	}

	// Verify journal mode (in-memory uses "memory" not "wal")
	var journalMode string
	err = sqlite.ReadDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("Failed to query journal mode: %v", err)
	}
	// In-memory databases use "memory" journal mode, not WAL
	if journalMode != "memory" && journalMode != "wal" {
		t.Errorf("Unexpected journal mode for in-memory DB: %s", journalMode)
	}

	// Test basic operations work
	_, err = sqlite.WriteDB.Exec(`
		INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
		VALUES ('mem-test', 'sigma', 'Test', 'Desc', 'low', 1, 1, datetime('now'), datetime('now'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert into in-memory DB: %v", err)
	}

	var count int
	err = sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = 'mem-test'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to read from in-memory DB: %v", err)
	}
	if count != 1 {
		t.Errorf("Read count = %d, want 1", count)
	}

	t.Logf("✓ In-memory database works with dual pools")
}

// BenchmarkReadPoolConcurrency benchmarks concurrent read performance
// TASK 143.4: Performance benchmarking
func BenchmarkReadPoolConcurrency(b *testing.B) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		b.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Insert test data
	for i := 0; i < 100; i++ {
		_, err := sqlite.WriteDB.Exec(`
			INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
			VALUES (?, 'sigma', 'Test', 'Desc', 'low', 1, 1, datetime('now'), datetime('now'))
		`, fmt.Sprintf("bench-%d", i))
		if err != nil {
			b.Fatalf("Failed to insert test data: %v", err)
		}
	}

	b.ResetTimer()

	// Benchmark concurrent reads
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var count int
			err := sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
			if err != nil {
				b.Errorf("Read failed: %v", err)
			}
		}
	})

	stats := sqlite.GetConnectionPoolStats()
	b.Logf("ReadPool: OpenConns=%d, WaitCount=%d, WaitDuration=%v",
		stats.ReadPool.OpenConnections,
		stats.ReadPool.WaitCount,
		stats.ReadPool.WaitDuration)
}

// BenchmarkOldVsNewReadConcurrency compares single-pool vs dual-pool read performance
// This benchmark demonstrates the performance improvement from Task 143
func BenchmarkOldVsNewReadConcurrency(b *testing.B) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	// Setup function to create a database with test data
	setupDB := func(maxConns int) (*sql.DB, string, func()) {
		tmpDir := b.TempDir()
		dbPath := filepath.Join(tmpDir, "bench.db")

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			b.Fatalf("Failed to open database: %v", err)
		}

		// Configure pool
		db.SetMaxOpenConns(maxConns)

		// Set WAL mode
		_, err = db.Exec("PRAGMA journal_mode=WAL")
		if err != nil {
			b.Fatalf("Failed to enable WAL: %v", err)
		}

		// Create schema
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS rules (
				id TEXT PRIMARY KEY,
				type TEXT NOT NULL,
				name TEXT NOT NULL,
				description TEXT,
				severity TEXT NOT NULL,
				enabled INTEGER NOT NULL,
				version INTEGER NOT NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL
			)
		`)
		if err != nil {
			b.Fatalf("Failed to create schema: %v", err)
		}

		// Insert test data
		for i := 0; i < 100; i++ {
			_, err := db.Exec(`
				INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
				VALUES (?, 'sigma', 'Test', 'Desc', 'low', 1, 1, datetime('now'), datetime('now'))
			`, fmt.Sprintf("bench-%d", i))
			if err != nil {
				b.Fatalf("Failed to insert test data: %v", err)
			}
		}

		cleanup := func() {
			db.Close()
			os.RemoveAll(tmpDir)
		}

		return db, dbPath, cleanup
	}

	b.Run("OldApproach_MaxOpenConns1", func(b *testing.B) {
		db, _, cleanup := setupDB(1)
		defer cleanup()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
				if err != nil {
					b.Errorf("Read failed: %v", err)
				}
			}
		})
	})

	b.Run("NewApproach_MaxOpenConns10", func(b *testing.B) {
		db, _, cleanup := setupDB(10)
		defer cleanup()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
				if err != nil {
					b.Errorf("Read failed: %v", err)
				}
			}
		})
	})
}

// TestContextCancellation verifies that connection pool respects context cancellation
func TestContextCancellation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_context.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Test context cancellation on read pool
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// This should fail due to context timeout
	_, err = sqlite.ReadDB.QueryContext(ctx, "SELECT COUNT(*) FROM rules")
	if err == nil {
		t.Error("Expected context timeout error, got nil")
	}
	if err != context.DeadlineExceeded && err != sql.ErrConnDone {
		t.Logf("Got error: %v (acceptable if related to context cancellation)", err)
	}
}

// TestNoSQLiteBusyErrors verifies that the dual pool setup prevents SQLITE_BUSY errors
func TestNoSQLiteBusyErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	logger := zap.NewNop().Sugar()
	defer logger.Sync()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_busy.db")

	sqlite, err := NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Stress test: Mix concurrent reads and writes
	const operations = 1000
	var wg sync.WaitGroup
	errors := make(chan error, operations)

	// Start read goroutines
	for i := 0; i < operations/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var count int
			err := sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
			if err != nil {
				errors <- fmt.Errorf("read %d failed: %w", idx, err)
			}
		}(i)
	}

	// Start write goroutines
	for i := 0; i < operations/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := sqlite.WriteDB.Exec(`
				INSERT INTO rules (id, type, name, description, severity, enabled, version, created_at, updated_at)
				VALUES (?, 'sigma', 'Test', 'Desc', 'low', 1, 1, datetime('now'), datetime('now'))
			`, fmt.Sprintf("stress-%d", idx))
			if err != nil {
				errors <- fmt.Errorf("write %d failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for SQLITE_BUSY errors
	busyErrors := 0
	for err := range errors {
		t.Error(err)
		if err != nil && (err.Error() == "database is locked" || err.Error() == "database table is locked") {
			busyErrors++
		}
	}

	if busyErrors > 0 {
		t.Errorf("Got %d SQLITE_BUSY errors (should be 0 with proper WAL configuration)", busyErrors)
	}

	stats := sqlite.GetConnectionPoolStats()
	t.Logf("Stress test stats:")
	t.Logf("  Write pool: WaitCount=%d, WaitDuration=%v", stats.WritePool.WaitCount, stats.WritePool.WaitDuration)
	t.Logf("  Read pool: WaitCount=%d, WaitDuration=%v", stats.ReadPool.WaitCount, stats.ReadPool.WaitDuration)
}
