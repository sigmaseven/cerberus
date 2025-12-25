package storage

import (
	"database/sql"
	"testing"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

func BenchmarkSQLiteInsert(b *testing.B) {
	sqlite := setupBenchmarkDB(b)
	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := &core.Rule{
			ID:      "bench-rule",
			Name:    "Benchmark Rule",
			Enabled: true,
		}
		_ = storage.CreateRule(rule)
	}
}

func BenchmarkSQLiteQuery(b *testing.B) {
	sqlite := setupBenchmarkDB(b)
	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	rule := &core.Rule{ID: "query-rule", Name: "Query Rule", Enabled: true}
	_ = storage.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetRule("query-rule")
	}
}

func BenchmarkConcurrentOperations(b *testing.B) {
	sqlite := setupBenchmarkDB(b)
	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, zap.NewNop().Sugar())

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rule := &core.Rule{
				ID:      "concurrent-rule",
				Name:    "Concurrent Rule",
				Enabled: true,
			}
			_ = storage.CreateRule(rule)
		}
	})
}

// setupBenchmarkDB creates a test database for benchmarks
func setupBenchmarkDB(b *testing.B) *SQLite {
	b.Helper()

	db, err := sql.Open("sqlite", ":memory:?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		b.Fatal(err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zap.NewNop().Sugar(),
	}

	if err := sqlite.createTables(); err != nil {
		b.Fatal(err)
	}

	return sqlite
}
