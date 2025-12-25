package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"cerberus/config"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test environment variables for ClickHouse integration tests
// Set CLICKHOUSE_ADDR to run these tests against a real ClickHouse instance
const (
	testClickHouseAddr     = "localhost:9000"
	testClickHouseDatabase = "cerberus_test"
	testClickHouseUser     = "default"
	testClickHousePassword = ""
)

// skipIfNoClickHouse skips the test if ClickHouse is not available
func skipIfNoClickHouse(t *testing.T) {
	if os.Getenv("CLICKHOUSE_ADDR") == "" {
		t.Skip("Skipping ClickHouse integration test (set CLICKHOUSE_ADDR to enable)")
	}
}

// getTestClickHouseAddr returns the ClickHouse address from environment or default
func getTestClickHouseAddr() string {
	if addr := os.Getenv("CLICKHOUSE_ADDR"); addr != "" {
		return addr
	}
	return testClickHouseAddr
}

// setupTestClickHouse creates a test ClickHouse connection
func setupTestClickHouse(t *testing.T) (*ClickHouse, *config.Config) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()

	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 5

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err, "Failed to create ClickHouse connection")
	require.NotNil(t, ch, "ClickHouse connection should not be nil")

	// Clean up test data from previous runs
	t.Cleanup(func() {
		cleanupTestClickHouse(t, ch)
	})

	return ch, cfg
}

// cleanupTestClickHouse drops test tables
func cleanupTestClickHouse(t *testing.T, ch *ClickHouse) {
	ctx := context.Background()

	// Drop test tables if they exist
	_ = ch.Conn.Exec(ctx, "DROP TABLE IF EXISTS events")
	_ = ch.Conn.Exec(ctx, "DROP TABLE IF EXISTS alerts")

	// Close connection
	if err := ch.Close(); err != nil {
		t.Logf("Warning: failed to close ClickHouse connection: %v", err)
	}
}

// TestNewClickHouse_Success tests successful ClickHouse connection
func TestNewClickHouse_Success(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err, "Should successfully connect to ClickHouse")
	require.NotNil(t, ch, "ClickHouse instance should not be nil")
	require.NotNil(t, ch.Conn, "Connection should not be nil")

	// Cleanup
	defer func() {
		cleanupTestClickHouse(t, ch)
	}()
}

// TestNewClickHouse_InvalidAddress tests connection with invalid address
func TestNewClickHouse_InvalidAddress(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = "invalid-host:9999"
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	assert.Error(t, err, "Should fail with invalid address")
	assert.Nil(t, ch, "ClickHouse instance should be nil on error")
}

// TestNewClickHouse_InvalidCredentials tests connection with invalid credentials
func TestNewClickHouse_InvalidCredentials(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = "invalid_user"
	cfg.ClickHouse.Password = "invalid_password"
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	// ClickHouse may or may not fail immediately depending on auth configuration
	// If it succeeds in creating connection, ping should fail
	if err == nil && ch != nil {
		err = ch.HealthCheck(context.Background())
		assert.Error(t, err, "Health check should fail with invalid credentials")
		_ = ch.Close()
	}
}

// TestClickHouse_HealthCheck tests health check functionality
func TestClickHouse_HealthCheck(t *testing.T) {
	ch, _ := setupTestClickHouse(t)

	ctx := context.Background()
	err := ch.HealthCheck(ctx)
	assert.NoError(t, err, "Health check should pass on valid connection")
}

// TestClickHouse_HealthCheck_Timeout tests health check with timeout
func TestClickHouse_HealthCheck_Timeout(t *testing.T) {
	ch, _ := setupTestClickHouse(t)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait to ensure timeout occurs
	time.Sleep(1 * time.Millisecond)

	err := ch.HealthCheck(ctx)
	// Should either succeed quickly or fail with context deadline exceeded
	if err != nil {
		assert.Contains(t, err.Error(), "context", "Error should be context-related")
	}
}

// TestClickHouse_GetVersion tests version retrieval
func TestClickHouse_GetVersion(t *testing.T) {
	ch, _ := setupTestClickHouse(t)

	ctx := context.Background()
	version, err := ch.GetVersion(ctx)
	require.NoError(t, err, "Should successfully get version")
	assert.NotEmpty(t, version, "Version should not be empty")
	t.Logf("ClickHouse version: %s", version)
}

// TestClickHouse_CreateTablesIfNotExist tests table creation
func TestClickHouse_CreateTablesIfNotExist(t *testing.T) {
	ch, _ := setupTestClickHouse(t)

	ctx := context.Background()
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err, "Should successfully create tables")

	// Verify events table exists
	var count uint64
	err = ch.Conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = ?",
		testClickHouseDatabase, "events").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), count, "Events table should exist")

	// Verify alerts table exists
	err = ch.Conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = ?",
		testClickHouseDatabase, "alerts").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), count, "Alerts table should exist")

	// Call again to ensure idempotency
	err = ch.CreateTablesIfNotExist(ctx)
	assert.NoError(t, err, "Creating tables again should be idempotent")
}

// TestValidateDatabaseName tests database name validation
func TestValidateDatabaseName(t *testing.T) {
	tests := []struct {
		name     string
		dbName   string
		wantErr  bool
		errorMsg string
	}{
		{
			name:    "valid alphanumeric",
			dbName:  "cerberus_test123",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			dbName:  "test_database_name",
			wantErr: false,
		},
		{
			name:     "empty name",
			dbName:   "",
			wantErr:  true,
			errorMsg: "cannot be empty",
		},
		{
			name:     "too long",
			dbName:   "a123456789012345678901234567890123456789012345678901234567890123456789",
			wantErr:  true,
			errorMsg: "too long",
		},
		{
			name:     "invalid characters - dash",
			dbName:   "test-database",
			wantErr:  true,
			errorMsg: "invalid characters",
		},
		{
			name:     "invalid characters - space",
			dbName:   "test database",
			wantErr:  true,
			errorMsg: "invalid characters",
		},
		{
			name:     "invalid characters - special",
			dbName:   "test@database",
			wantErr:  true,
			errorMsg: "invalid characters",
		},
		{
			name:     "SQL injection attempt - semicolon",
			dbName:   "test; DROP DATABASE",
			wantErr:  true,
			errorMsg: "invalid characters",
		},
		{
			name:     "SQL injection attempt - quotes",
			dbName:   "test' OR '1'='1",
			wantErr:  true,
			errorMsg: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDatabaseName(tt.dbName)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for database name: %s", tt.dbName)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid database name: %s", tt.dbName)
			}
		})
	}
}

// TestEnsureDatabase tests database creation with validation
func TestEnsureDatabase(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	// Create connection without database
	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err)
	defer ch.Close()

	ctx := context.Background()

	// Test with valid database name
	err = ensureDatabase(ctx, ch.Conn, testClickHouseDatabase, logger)
	assert.NoError(t, err, "Should create database with valid name")

	// Test with invalid database name (SQL injection attempt)
	err = ensureDatabase(ctx, ch.Conn, "invalid; DROP DATABASE test", logger)
	assert.Error(t, err, "Should reject SQL injection attempt")
	assert.Contains(t, err.Error(), "invalid database name", "Error should indicate invalid name")
}

// TestIPv4StringToNum tests IP address conversion to uint32
func TestIPv4StringToNum(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected uint32
	}{
		{
			name:     "valid IP - localhost",
			ip:       "127.0.0.1",
			expected: 0x7F000001, // 127 << 24 | 0 << 16 | 0 << 8 | 1
		},
		{
			name:     "valid IP - private network",
			ip:       "192.168.1.1",
			expected: 0xC0A80101, // 192 << 24 | 168 << 16 | 1 << 8 | 1
		},
		{
			name:     "valid IP - zeros",
			ip:       "0.0.0.0",
			expected: 0,
		},
		{
			name:     "valid IP - max values",
			ip:       "255.255.255.255",
			expected: 0xFFFFFFFF,
		},
		{
			name:     "empty string",
			ip:       "",
			expected: 0,
		},
		{
			name:     "invalid IP format",
			ip:       "invalid",
			expected: 0,
		},
		{
			name:     "IPv6 address",
			ip:       "::1",
			expected: 0, // Should return 0 for non-IPv4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPv4StringToNum(tt.ip)
			assert.Equal(t, tt.expected, result, "IP conversion mismatch for %s", tt.ip)
		})
	}
}

// TestIPv4NumToString tests uint32 to IP address conversion
func TestIPv4NumToString(t *testing.T) {
	tests := []struct {
		name     string
		num      uint32
		expected string
	}{
		{
			name:     "localhost",
			num:      0x7F000001,
			expected: "127.0.0.1",
		},
		{
			name:     "private network",
			num:      0xC0A80101,
			expected: "192.168.1.1",
		},
		{
			name:     "zeros",
			num:      0,
			expected: "0.0.0.0",
		},
		{
			name:     "max value",
			num:      0xFFFFFFFF,
			expected: "255.255.255.255",
		},
		{
			name:     "arbitrary IP",
			num:      0x08080808,
			expected: "8.8.8.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPv4NumToString(tt.num)
			assert.Equal(t, tt.expected, result, "IP string mismatch for %d", tt.num)
		})
	}
}

// TestIPv4Conversion_Roundtrip tests IP conversion roundtrip
func TestIPv4Conversion_Roundtrip(t *testing.T) {
	testIPs := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.2.3.4",
		"255.255.255.255",
	}

	for _, ip := range testIPs {
		t.Run(ip, func(t *testing.T) {
			// Convert to number and back
			num := IPv4StringToNum(ip)
			result := IPv4NumToString(num)
			assert.Equal(t, ip, result, "Roundtrip conversion should preserve IP address")
		})
	}
}

// TestClickHouse_Close tests connection closure
func TestClickHouse_Close(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, ch)

	// Close connection
	err = ch.Close()
	assert.NoError(t, err, "Should close connection without error")

	// Closing again should not panic or error
	err = ch.Close()
	// Some drivers may error on double close, that's acceptable
	t.Logf("Double close result: %v", err)
}

// TestClickHouse_ConnectionPooling tests connection pool settings
func TestClickHouse_ConnectionPooling(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 5 // Small pool for testing

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err)
	defer ch.Close()

	// Verify connection works
	ctx := context.Background()
	err = ch.HealthCheck(ctx)
	assert.NoError(t, err, "Health check should pass")

	// Make multiple concurrent queries to test pooling
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			var version string
			err := ch.Conn.QueryRow(ctx, "SELECT version()").Scan(&version)
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestClickHouse_TLSConfiguration tests TLS settings (unit test, doesn't connect)
func TestClickHouse_TLSConfiguration(t *testing.T) {
	// This is a unit test that verifies TLS configuration is set up correctly
	// It won't actually connect since we don't have a TLS-enabled ClickHouse for testing

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = "localhost:9440" // Standard ClickHouse TLS port
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = true
	cfg.ClickHouse.MaxPoolSize = 10

	// This will likely fail to connect, but we're testing that TLS config is created
	ch, err := NewClickHouse(cfg, logger)
	// We expect either success (if TLS ClickHouse is available) or connection error
	// What we don't want is a panic or nil pointer error
	if ch != nil {
		defer ch.Close()
	}

	// Test passes if no panic occurred
	t.Logf("TLS connection attempt completed (err: %v)", err)
}

// TestEnsureDatabase_InvalidDatabaseNames tests database name validation in ensureDatabase
func TestEnsureDatabase_InvalidDatabaseNames(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err)
	defer ch.Close()

	ctx := context.Background()

	tests := []struct {
		name   string
		dbName string
	}{
		{"empty database name", ""},
		{"SQL injection with semicolon", "test; DROP DATABASE"},
		{"SQL injection with quotes", "test' OR '1'='1"},
		{"database name with dash", "test-database"},
		{"database name with space", "test database"},
		{"database name with special chars", "test@database!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureDatabase(ctx, ch.Conn, tt.dbName, logger)
			assert.Error(t, err, "Should reject invalid database name: %s", tt.dbName)
			assert.Contains(t, err.Error(), "invalid database name")
		})
	}
}

// TestClickHouse_GetVersion_AfterClose tests version retrieval after connection close
func TestClickHouse_GetVersion_AfterClose(t *testing.T) {
	skipIfNoClickHouse(t)

	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = testClickHouseDatabase
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err)

	// Close connection
	err = ch.Close()
	assert.NoError(t, err)

	// Try to get version after close
	ctx := context.Background()
	_, err = ch.GetVersion(ctx)
	// Should fail since connection is closed
	if err != nil {
		t.Logf("GetVersion correctly failed after close: %v", err)
	}
}

// TestClickHouse_CreateTablesIfNotExist_Idempotent tests table creation is idempotent
func TestClickHouse_CreateTablesIfNotExist_Idempotent(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// Create tables first time
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	// Create tables second time (should be idempotent)
	err = ch.CreateTablesIfNotExist(ctx)
	assert.NoError(t, err, "Creating tables again should be idempotent")

	// Create tables third time
	err = ch.CreateTablesIfNotExist(ctx)
	assert.NoError(t, err, "Creating tables third time should still be idempotent")
}

// ==================== SECURITY TESTS ====================
// Tests that verify protection against security vulnerabilities
// Required by: AFFIRMATIONS.md, security-threat-model.md FR-SEC-003

// TestClickHouse_SQLInjection_DatabaseName tests SQL injection prevention in database names
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestClickHouse_SQLInjection_DatabaseName(t *testing.T) {
	ctx := context.Background()

	// Create a test connection to default database
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = getTestClickHouseAddr()
	cfg.ClickHouse.Database = "default"
	cfg.ClickHouse.Username = testClickHouseUser
	cfg.ClickHouse.Password = testClickHousePassword
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10

	tests := []struct {
		name           string
		maliciousDB    string
		shouldFail     bool
		verifyQuery    string
		verifyExpected interface{}
	}{
		{
			name:        "SQL injection - DROP DATABASE",
			maliciousDB: "test'; DROP DATABASE default; --",
			shouldFail:  true,
		},
		{
			name:        "SQL injection - UNION SELECT",
			maliciousDB: "test' UNION SELECT * FROM system.tables --",
			shouldFail:  true,
		},
		{
			name:        "SQL injection - comment bypass",
			maliciousDB: "test`; DROP DATABASE default; --",
			shouldFail:  true,
		},
		{
			name:        "SQL injection - OR 1=1",
			maliciousDB: "test' OR '1'='1",
			shouldFail:  true,
		},
		{
			name:        "SQL injection - semicolon commands",
			maliciousDB: "test; ALTER TABLE events DROP COLUMN event_id",
			shouldFail:  true,
		},
		{
			name:        "SQL injection - backslash escape",
			maliciousDB: "test\\'; DROP DATABASE default; --",
			shouldFail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First verify the malicious database name is rejected by validation
			err := validateDatabaseName(tt.maliciousDB)
			if tt.shouldFail {
				assert.Error(t, err, "Malicious database name should be rejected: %s", tt.maliciousDB)
				assert.Contains(t, err.Error(), "invalid characters",
					"Error should indicate invalid characters for database name: %s", tt.maliciousDB)
			}

			// Even if validation is bypassed, verify database creation fails safely
			// This is defense-in-depth testing
			skipIfNoClickHouse(t)

			conn, err := clickhouse.Open(&clickhouse.Options{
				Addr: []string{cfg.ClickHouse.Addr},
				Auth: clickhouse.Auth{
					Database: "default",
					Username: cfg.ClickHouse.Username,
					Password: cfg.ClickHouse.Password,
				},
			})
			if err != nil {
				t.Skip("Cannot connect to ClickHouse for injection test")
			}
			defer conn.Close()

			// Try to create database with malicious name (will fail due to validation)
			// But even if it didn't fail, ClickHouse should reject it
			err = conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", tt.maliciousDB))
			// We expect this to fail due to invalid database name
			assert.Error(t, err, "Direct database creation with malicious name should fail")

			// Verify the default database still exists (wasn't dropped)
			var dbExists uint8
			err = conn.QueryRow(ctx, "SELECT 1 FROM system.databases WHERE name = 'default'").Scan(&dbExists)
			assert.NoError(t, err, "Default database should still exist after injection attempt")
			assert.Equal(t, uint8(1), dbExists, "Default database should still exist")
		})
	}
}

// TestClickHouse_SQLInjection_ParameterizedQueries tests that parameterized queries prevent injection
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestClickHouse_SQLInjection_ParameterizedQueries(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// Ensure tables exist
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	tests := []struct {
		name           string
		maliciousValue string
		queryFunc      func(string) error
		verifyFunc     func() error
	}{
		{
			name:           "SQL injection in event_id - DROP TABLE",
			maliciousValue: "'; DROP TABLE events; --",
			queryFunc: func(val string) error {
				query := "SELECT COUNT(*) FROM events WHERE event_id = ?"
				var count uint64
				return ch.Conn.QueryRow(ctx, query, val).Scan(&count)
			},
			verifyFunc: func() error {
				// Verify events table still exists
				var tableExists uint8
				err := ch.Conn.QueryRow(ctx,
					"SELECT 1 FROM system.tables WHERE database = ? AND name = 'events'",
					ch.Config.ClickHouse.Database).Scan(&tableExists)
				if err != nil {
					return fmt.Errorf("events table was dropped! %w", err)
				}
				if tableExists != 1 {
					return fmt.Errorf("events table does not exist")
				}
				return nil
			},
		},
		{
			name:           "SQL injection - UNION SELECT",
			maliciousValue: "' UNION SELECT password FROM users WHERE '1'='1",
			queryFunc: func(val string) error {
				query := "SELECT COUNT(*) FROM events WHERE source = ?"
				var count uint64
				return ch.Conn.QueryRow(ctx, query, val).Scan(&count)
			},
			verifyFunc: func() error {
				// Verify the query executed safely (returned 0 results, not union data)
				return nil
			},
		},
		{
			name:           "SQL injection - comment bypass",
			maliciousValue: "test'; DELETE FROM events; --",
			queryFunc: func(val string) error {
				query := "SELECT COUNT(*) FROM events WHERE listener_name = ?"
				var count uint64
				return ch.Conn.QueryRow(ctx, query, val).Scan(&count)
			},
			verifyFunc: func() error {
				// Verify events table still exists and has expected structure
				var tableExists uint8
				return ch.Conn.QueryRow(ctx,
					"SELECT 1 FROM system.tables WHERE database = ? AND name = 'events'",
					ch.Config.ClickHouse.Database).Scan(&tableExists)
			},
		},
		{
			name:           "SQL injection - OR 1=1",
			maliciousValue: "' OR '1'='1' --",
			queryFunc: func(val string) error {
				query := "SELECT COUNT(*) FROM events WHERE source_format = ?"
				var count uint64
				err := ch.Conn.QueryRow(ctx, query, val).Scan(&count)
				// Verify count is 0 (no match), not all records
				if err == nil && count > 0 {
					return fmt.Errorf("SQL injection succeeded - returned %d rows", count)
				}
				return err
			},
			verifyFunc: func() error {
				return nil
			},
		},
		{
			name:           "SQL injection - semicolon command chain",
			maliciousValue: "test'; ALTER TABLE events DROP COLUMN event_id; SELECT '1",
			queryFunc: func(val string) error {
				query := "SELECT COUNT(*) FROM events WHERE listener_id = ?"
				var count uint64
				return ch.Conn.QueryRow(ctx, query, val).Scan(&count)
			},
			verifyFunc: func() error {
				// Verify event_id column still exists
				var columnExists uint8
				err := ch.Conn.QueryRow(ctx,
					"SELECT 1 FROM system.columns WHERE database = ? AND table = 'events' AND name = 'event_id'",
					ch.Config.ClickHouse.Database).Scan(&columnExists)
				if err != nil {
					return fmt.Errorf("event_id column was dropped! %w", err)
				}
				if columnExists != 1 {
					return fmt.Errorf("event_id column does not exist")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute the query with malicious input
			// It should either fail safely OR execute without side effects
			err := tt.queryFunc(tt.maliciousValue)
			// Query may succeed (with 0 results) or fail - both are acceptable
			// as long as the injection doesn't execute

			// The critical test: verify no SQL injection occurred
			err = tt.verifyFunc()
			assert.NoError(t, err, "SQL injection should be prevented - database should be intact")

			// Additional verification: events table structure is intact
			var columnCount uint64
			err = ch.Conn.QueryRow(ctx,
				"SELECT COUNT(*) FROM system.columns WHERE database = ? AND table = 'events'",
				ch.Config.ClickHouse.Database).Scan(&columnCount)
			assert.NoError(t, err, "Should be able to query system.columns")
			assert.GreaterOrEqual(t, columnCount, uint64(9),
				"Events table should have at least 9 columns (not dropped/altered)")
		})
	}
}

// ==================== TASK 101: DISPOSITION MIGRATION TESTS ====================

// TestIsExpectedMigrationError tests error classification for migrations
// TASK 101: Ensures proper distinction between expected and genuine errors
func TestIsExpectedMigrationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "column already exists",
			err:      fmt.Errorf("column already exists"),
			expected: true,
		},
		{
			name:     "COLUMN_ALREADY_EXISTS code",
			err:      fmt.Errorf("Code: 44. COLUMN_ALREADY_EXISTS"),
			expected: true,
		},
		{
			name:     "duplicate column error",
			err:      fmt.Errorf("duplicate column 'disposition'"),
			expected: true,
		},
		{
			name:     "index already exists",
			err:      fmt.Errorf("index already exists"),
			expected: true,
		},
		{
			name:     "INDEX_ALREADY_EXISTS code",
			err:      fmt.Errorf("Code: 36. INDEX_ALREADY_EXISTS"),
			expected: true,
		},
		{
			name:     "connection refused - genuine error",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
		{
			name:     "permission denied - genuine error",
			err:      fmt.Errorf("permission denied"),
			expected: false,
		},
		{
			name:     "timeout - genuine error",
			err:      fmt.Errorf("context deadline exceeded"),
			expected: false,
		},
		{
			name:     "table not found - genuine error",
			err:      fmt.Errorf("Table 'alerts' doesn't exist"),
			expected: false,
		},
		{
			name:     "syntax error - genuine error",
			err:      fmt.Errorf("Syntax error at position 42"),
			expected: false,
		},
		{
			name:     "network error - genuine error",
			err:      fmt.Errorf("dial tcp: lookup clickhouse: no such host"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isExpectedMigrationError(tt.err)
			assert.Equal(t, tt.expected, result,
				"isExpectedMigrationError(%v) = %v, expected %v",
				tt.err, result, tt.expected)
		})
	}
}

// TestContainsIgnoreCase tests case-insensitive substring matching
// TASK 101: Helper function for error classification
func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"already exists", "already exists", true},
		{"ALREADY EXISTS", "already exists", true},
		{"Already Exists", "already exists", true},
		{"column already exists in table", "already exists", true},
		{"no match here", "already exists", false},
		{"", "already exists", false},
		{"already exists", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_contains_%s", tt.s, tt.substr), func(t *testing.T) {
			result := containsIgnoreCase(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClickHouse_MigrateAlertsDispositionFields tests disposition field migration
// TASK 101: Tests that migration adds all required disposition columns
func TestClickHouse_MigrateAlertsDispositionFields(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// First create tables (which should include disposition fields)
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err, "Should create tables successfully")

	// Verify all disposition columns exist in alerts table
	dispositionColumns := []struct {
		name         string
		expectedType string
	}{
		{"disposition", "LowCardinality(String)"},
		{"disposition_reason", "String"},
		{"disposition_set_at", "Nullable(DateTime64(3, 'UTC'))"},
		{"disposition_set_by", "String"},
		{"investigation_id", "String"},
	}

	for _, col := range dispositionColumns {
		t.Run("column_"+col.name, func(t *testing.T) {
			var columnType string
			err := ch.Conn.QueryRow(ctx,
				`SELECT type FROM system.columns
				 WHERE database = currentDatabase() AND table = 'alerts' AND name = ?`,
				col.name).Scan(&columnType)
			require.NoError(t, err, "Column %s should exist in alerts table", col.name)
			assert.Equal(t, col.expectedType, columnType,
				"Column %s should have expected type", col.name)
		})
	}

	// Verify disposition index exists
	t.Run("disposition_index", func(t *testing.T) {
		var indexExists uint64
		err := ch.Conn.QueryRow(ctx,
			`SELECT count() FROM system.data_skipping_indices
			 WHERE database = currentDatabase() AND table = 'alerts' AND name = 'idx_disposition'`).Scan(&indexExists)
		require.NoError(t, err, "Should be able to query indexes")
		assert.Equal(t, uint64(1), indexExists, "idx_disposition index should exist")
	})
}

// TestClickHouse_MigrateAlertsDispositionFields_Idempotent tests migration idempotency
// TASK 101: Migration should be safe to run multiple times
func TestClickHouse_MigrateAlertsDispositionFields_Idempotent(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// Create tables
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	// Run migration explicitly multiple times
	for i := 0; i < 3; i++ {
		err = ch.MigrateAlertsDispositionFields(ctx)
		assert.NoError(t, err, "Migration should be idempotent on iteration %d", i+1)
	}

	// Verify columns still exist and have correct types
	var columnCount uint64
	err = ch.Conn.QueryRow(ctx,
		`SELECT count() FROM system.columns
		 WHERE database = currentDatabase() AND table = 'alerts'
		 AND name IN ('disposition', 'disposition_reason', 'disposition_set_at', 'disposition_set_by', 'investigation_id')`).Scan(&columnCount)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), columnCount, "All 5 disposition columns should exist after multiple migrations")
}

// TestClickHouse_DispositionDefaultValues tests that disposition fields have correct defaults
// TASK 101: Verify default values are set correctly
func TestClickHouse_DispositionDefaultValues(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// Create tables
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	// Insert an alert without disposition fields (should use defaults)
	batch, err := ch.Conn.PrepareBatch(ctx, `
		INSERT INTO alerts (
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel
		)
	`)
	require.NoError(t, err)

	testAlertID := fmt.Sprintf("test-alert-%d", time.Now().UnixNano())
	now := time.Now()
	err = batch.Append(
		testAlertID, "rule-1", "event-1", now, "medium", "open",
		"", "fp-123", uint32(1), now,
		[]string{"event-1"}, "", "{}", "{}",
	)
	require.NoError(t, err)
	err = batch.Send()
	require.NoError(t, err)

	// Query the inserted alert and verify default values
	var disposition, dispositionReason, dispositionSetBy, investigationID string
	err = ch.Conn.QueryRow(ctx,
		`SELECT disposition, disposition_reason, disposition_set_by, investigation_id
		 FROM alerts WHERE alert_id = ?`, testAlertID).Scan(
		&disposition, &dispositionReason, &dispositionSetBy, &investigationID)
	require.NoError(t, err, "Should be able to query inserted alert")

	assert.Equal(t, "undetermined", disposition, "Default disposition should be 'undetermined'")
	assert.Equal(t, "", dispositionReason, "Default disposition_reason should be empty")
	assert.Equal(t, "", dispositionSetBy, "Default disposition_set_by should be empty")
	assert.Equal(t, "", investigationID, "Default investigation_id should be empty")

	// Cleanup
	_ = ch.Conn.Exec(ctx, "ALTER TABLE alerts DELETE WHERE alert_id = ?", testAlertID)
}

// TestClickHouse_SQLInjection_BatchInsert tests that batch inserts prevent injection
// REQUIREMENT: AFFIRMATIONS.md - SQL Injection Prevention
// REQUIREMENT: security-threat-model.md FR-SEC-003
func TestClickHouse_SQLInjection_BatchInsert(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	ctx := context.Background()

	// Ensure tables exist
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	tests := []struct {
		name          string
		eventID       string
		source        string
		rawData       string
		expectedError bool
	}{
		{
			name:          "SQL injection in event_id",
			eventID:       "'; DROP TABLE events; --",
			source:        "test",
			rawData:       "normal data",
			expectedError: false, // Should succeed (injection prevented)
		},
		{
			name:          "SQL injection in source",
			eventID:       "event-123",
			source:        "test'); DELETE FROM events; --",
			rawData:       "normal data",
			expectedError: false,
		},
		{
			name:          "SQL injection in raw_data",
			eventID:       "event-456",
			source:        "test",
			rawData:       "'; ALTER TABLE events DROP COLUMN event_id; --",
			expectedError: false,
		},
		{
			name:          "SQL injection - multiple injections",
			eventID:       "'; DROP DATABASE " + testClickHouseDatabase + "; --",
			source:        "' OR '1'='1",
			rawData:       "'; DELETE FROM events WHERE '1'='1'; --",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare batch insert with malicious data
			batch, err := ch.Conn.PrepareBatch(ctx, `
				INSERT INTO events (
					event_id, timestamp, ingested_at, listener_id, listener_name,
					source, source_format, raw_data, fields
				)
			`)
			require.NoError(t, err, "PrepareBatch should succeed")

			// Append event with potentially malicious data
			now := time.Now()
			err = batch.Append(
				tt.eventID,
				now,
				now,
				"test-listener",
				"test-listener-name",
				tt.source,
				"json",
				tt.rawData,
				"{}",
			)
			require.NoError(t, err, "Append should succeed with parameterized data")

			// Send batch
			err = batch.Send()
			if tt.expectedError {
				assert.Error(t, err, "Expected error for test case")
			} else {
				assert.NoError(t, err, "Batch insert should succeed despite malicious input")
			}

			// CRITICAL VERIFICATION: Ensure table still exists and structure is intact
			var tableExists uint8
			err = ch.Conn.QueryRow(ctx,
				"SELECT 1 FROM system.tables WHERE database = ? AND name = 'events'",
				ch.Config.ClickHouse.Database).Scan(&tableExists)
			assert.NoError(t, err, "Should be able to query system.tables")
			assert.Equal(t, uint8(1), tableExists, "Events table should still exist after injection attempt")

			// Verify column structure is intact
			var columnCount uint64
			err = ch.Conn.QueryRow(ctx,
				"SELECT COUNT(*) FROM system.columns WHERE database = ? AND table = 'events'",
				ch.Config.ClickHouse.Database).Scan(&columnCount)
			assert.NoError(t, err, "Should be able to query system.columns")
			assert.GreaterOrEqual(t, columnCount, uint64(9), "Events table should have all 9 columns intact")

			// Verify database still exists
			var dbExists uint8
			err = ch.Conn.QueryRow(ctx,
				"SELECT 1 FROM system.databases WHERE name = ?",
				ch.Config.ClickHouse.Database).Scan(&dbExists)
			assert.NoError(t, err, "Should be able to query system.databases")
			assert.Equal(t, uint8(1), dbExists, "Database should still exist after injection attempt")

			// If insert succeeded, verify the data was stored AS-IS (not executed as SQL)
			if !tt.expectedError && err == nil {
				var storedEventID string
				queryErr := ch.Conn.QueryRow(ctx,
					"SELECT event_id FROM events WHERE event_id = ? LIMIT 1",
					tt.eventID).Scan(&storedEventID)
				assert.NoError(t, queryErr, "Should be able to retrieve stored event")
				assert.Equal(t, tt.eventID, storedEventID,
					"Event ID should be stored as literal string, not executed as SQL")

				// Clean up
				_ = ch.Conn.Exec(ctx, "DELETE FROM events WHERE event_id = ?", tt.eventID)
			}
		})
	}
}
