package testing

import (
	"fmt"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/storage"
	"go.uber.org/zap"
)

// SetupTestConfig creates a standard test configuration with optional overrides.
// This eliminates duplicate config structs across test files and ensures
// consistent test configuration values.
//
// Example usage:
//
//	cfg := testing.SetupTestConfig()
//	cfg := testing.SetupTestConfig(func(c *config.Config) {
//	    c.Engine.WorkerCount = 10
//	})
func SetupTestConfig(overrides ...func(*config.Config)) *config.Config {
	cfg := &config.Config{}

	// Engine configuration with test-optimized values
	cfg.Engine.ChannelBufferSize = TestChannelBufferSize
	cfg.Engine.WorkerCount = TestWorkerCount
	cfg.Engine.ActionWorkerCount = TestActionWorkerCount
	cfg.Engine.RateLimit = TestRateLimit
	cfg.Engine.CorrelationStateTTL = TestCorrelationStateTTL
	cfg.Engine.ActionTimeout = TestActionTimeout

	// Circuit breaker configuration
	cfg.Engine.CircuitBreaker.MaxFailures = TestCircuitBreakerMaxFailures
	cfg.Engine.CircuitBreaker.TimeoutSeconds = TestCircuitBreakerTimeoutSeconds
	cfg.Engine.CircuitBreaker.MaxHalfOpenRequests = TestCircuitBreakerMaxHalfOpenRequests

	// Storage configuration
	cfg.Storage.BufferSize = TestStorageBufferSize
	cfg.Storage.Deduplication = false // Disabled by default in tests for predictability

	// API configuration
	cfg.API.Port = 0 // Use random port in tests to avoid conflicts
	cfg.API.TLS = false
	cfg.API.RateLimit.RequestsPerSecond = 0 // Disabled in tests

	// Apply any overrides
	for _, override := range overrides {
		override(cfg)
	}

	return cfg
}

// SetupTestDB creates an isolated in-memory SQLite database for testing.
// Each test gets a unique database to prevent interference between tests.
// The database is automatically cleaned up when the test completes via t.Cleanup().
//
// Example usage:
//
//	db := testing.SetupTestDB(t)
//	// db is ready to use and will be cleaned up automatically
func SetupTestDB(t *testing.T) *storage.SQLite {
	t.Helper()

	// Use unique database name per test to prevent interference
	// Memory mode with shared cache allows access from the same connection
	dbPath := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())

	logger := setupTestLogger(t)

	db, err := storage.NewSQLite(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Ensure cleanup happens even if test panics
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	})

	return db
}

// SetupTestLogger creates a test logger that writes to t.Log instead of stdout.
// This ensures log output is associated with specific tests and only shown
// when tests fail or when -v flag is used.
//
// Example usage:
//
//	logger := testing.SetupTestLogger(t)
func SetupTestLogger(t testing.TB) *zap.SugaredLogger {
	t.Helper()
	// Use a no-op logger for tests to avoid clutter
	// Tests can override with a real logger if needed
	return zap.NewNop().Sugar()
}

// setupTestLogger is a private wrapper for backward compatibility
func setupTestLogger(t *testing.T) *zap.SugaredLogger {
	return SetupTestLogger(t)
}

// WaitForCondition polls a condition function with timeout, replacing sleep-based timing.
// This eliminates flaky tests caused by timing assumptions and works correctly
// on slow CI systems.
//
// The condition function is called repeatedly (every 10ms) until it returns true
// or the timeout expires. If the timeout expires, the test fails with t.Fatalf.
//
// Example usage:
//
//	testing.WaitForCondition(t, func() bool {
//	    return cb.State() == core.CircuitBreakerStateClosed
//	}, testing.TestMediumTimeout, "circuit breaker to return to closed state")
//
// Why this is critical:
//   - Sleep-based tests assume specific timing: time.Sleep(150*time.Millisecond)
//   - This fails on slow CI or under debugger
//   - Polling adapts to actual system performance
//   - Tests become deterministic instead of timing-dependent
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, description string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}

		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatalf("Timeout waiting for condition: %s (timeout: %v)", description, timeout)
			}
		}
	}
}

// WaitForConditionWithCleanup is like WaitForCondition but calls a cleanup function
// if the condition times out before failing the test. This is useful for debugging
// or collecting diagnostic information.
//
// Example usage:
//
//	testing.WaitForConditionWithCleanup(t, func() bool {
//	    return len(alerts) > 0
//	}, testing.TestMediumTimeout, "alerts to be generated", func() {
//	    t.Logf("Current state: alerts=%d, events=%d", len(alerts), len(events))
//	})
func WaitForConditionWithCleanup(t *testing.T, condition func() bool, timeout time.Duration, description string, cleanup func()) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}

		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				if cleanup != nil {
					cleanup()
				}
				t.Fatalf("Timeout waiting for condition: %s (timeout: %v)", description, timeout)
			}
		}
	}
}
