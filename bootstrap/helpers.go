package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"go.uber.org/zap"
)

// DataDirectories defines the paths that need to exist for Cerberus to run.
type DataDirectories struct {
	Base   string // Base data directory (default: ./data)
	Feeds  string // SIGMA feeds working directory
	ML     string // ML models directory
	SQLite string // SQLite database path
}

// DefaultDataDirectories returns the default data directory configuration.
// This is used during pre-flight checks before config is loaded.
func DefaultDataDirectories() DataDirectories {
	base := os.Getenv("CERBERUS_DATA_DIR")
	if base == "" {
		base = "./data"
	}

	sqlitePath := os.Getenv("CERBERUS_SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = filepath.Join(base, "cerberus.db")
	}

	feedsDir := os.Getenv("CERBERUS_FEEDS_DIR")
	if feedsDir == "" {
		feedsDir = filepath.Join(base, "feeds")
	}

	mlDir := os.Getenv("CERBERUS_ML_DIR")
	if mlDir == "" {
		mlDir = filepath.Join(base, "ml_models")
	}

	return DataDirectories{
		Base:   base,
		Feeds:  feedsDir,
		ML:     mlDir,
		SQLite: sqlitePath,
	}
}

// EnsureDataDirectories creates required data directories with proper permissions.
// This is a pre-flight check that runs before any service initialization.
func EnsureDataDirectories(sugar *zap.SugaredLogger) (DataDirectories, error) {
	dirs := DefaultDataDirectories()

	directoriesToCreate := []string{dirs.Base, dirs.Feeds, dirs.ML}

	for _, dir := range directoriesToCreate {
		absPath, err := filepath.Abs(dir)
		if err != nil {
			return dirs, fmt.Errorf("failed to resolve absolute path for %s: %w", dir, err)
		}

		if err := os.MkdirAll(absPath, 0755); err != nil {
			return dirs, fmt.Errorf("failed to create directory %s: %w\n"+
				"  Remediation: Ensure the parent directory exists and is writable\n"+
				"  For Docker: Check volume mount permissions\n"+
				"  For bare metal: Run 'mkdir -p %s && chmod 755 %s'", dir, err, absPath, absPath)
		}

		// Verify write permissions
		testFile := filepath.Join(absPath, ".cerberus_write_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return dirs, fmt.Errorf("directory %s is not writable: %w\n"+
				"  Remediation: Check file system permissions\n"+
				"  For Docker: Ensure volume is mounted with write access\n"+
				"  For bare metal: Run 'chmod -R u+w %s'", dir, err, absPath)
		}
		os.Remove(testFile)

		sugar.Infow("Data directory ready", "path", absPath)
	}

	sugar.Info("All data directories verified")
	return dirs, nil
}

// GenerateSecurePassword generates a cryptographically secure random password.
func GenerateSecurePassword(length int) (string, error) {
	if length < 16 {
		length = 16
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	password := base64.URLEncoding.EncodeToString(bytes)
	if len(password) > length {
		password = password[:length]
	}

	return password, nil
}

// ClassifyConnectionError provides specific error messages based on the type of connection failure.
func ClassifyConnectionError(err error, addr string) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return fmt.Sprintf("Connection to ClickHouse at %s timed out.\n"+
				"  Possible causes:\n"+
				"  - ClickHouse is starting up (wait and retry)\n"+
				"  - Network latency or firewall blocking the connection\n"+
				"  - ClickHouse is overloaded\n"+
				"  Remediation:\n"+
				"  - Check if ClickHouse is running: docker ps | grep clickhouse\n"+
				"  - Verify network connectivity: nc -zv %s", addr, addr)
		}
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			if errors.Is(opErr.Err, syscall.ECONNREFUSED) ||
				(opErr.Err != nil && (containsIgnoreCase(opErr.Err.Error(), "connection refused") ||
					containsIgnoreCase(opErr.Err.Error(), "actively refused"))) {
				return fmt.Sprintf("Connection refused by ClickHouse at %s.\n"+
					"  This usually means ClickHouse is not running.\n"+
					"  Remediation:\n"+
					"  - Start ClickHouse: docker compose up -d clickhouse\n"+
					"  - Check ClickHouse logs: docker logs cerberus-clickhouse-1\n"+
					"  - Verify the address is correct in config.yaml", addr)
			}
		}
	}

	if containsIgnoreCase(errStr, "no such host") || containsIgnoreCase(errStr, "lookup") {
		return fmt.Sprintf("Cannot resolve hostname in ClickHouse address %s.\n"+
			"  Remediation:\n"+
			"  - Verify the hostname is correct\n"+
			"  - Check DNS configuration\n"+
			"  - Try using IP address (127.0.0.1) instead of hostname", addr)
	}

	if containsIgnoreCase(errStr, "authentication") || containsIgnoreCase(errStr, "password") || containsIgnoreCase(errStr, "denied") {
		return fmt.Sprintf("Authentication failed for ClickHouse at %s.\n"+
			"  Remediation:\n"+
			"  - Verify username and password in config.yaml\n"+
			"  - Check CERBERUS_CLICKHOUSE_USER and CERBERUS_CLICKHOUSE_PASSWORD env vars\n"+
			"  - Default credentials: user=default, password=testpass123", addr)
	}

	return fmt.Sprintf("Failed to connect to ClickHouse at %s: %v\n"+
		"  Remediation:\n"+
		"  - Ensure ClickHouse is running and accessible\n"+
		"  - Check config.yaml clickhouse.addr setting\n"+
		"  - Verify network connectivity", addr, err)
}

// ClassifySQLiteError provides specific error messages based on the type of SQLite failure.
func ClassifySQLiteError(err error, dbPath string) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()
	absPath, _ := filepath.Abs(dbPath)
	parentDir := filepath.Dir(absPath)

	if containsIgnoreCase(errStr, "permission denied") || containsIgnoreCase(errStr, "access denied") {
		return fmt.Sprintf("Permission denied accessing SQLite database at %s.\n"+
			"  Possible causes:\n"+
			"  - The database file or directory has incorrect permissions\n"+
			"  - Another process has an exclusive lock on the file\n"+
			"  Remediation:\n"+
			"  - Check file permissions: ls -la %s\n"+
			"  - Check directory permissions: ls -la %s\n"+
			"  - For Docker: Ensure volume is mounted with proper user permissions\n"+
			"  - For bare metal: Run 'chmod 644 %s' or 'chown youruser %s'",
			absPath, absPath, parentDir, absPath, absPath)
	}

	if containsIgnoreCase(errStr, "database is locked") || containsIgnoreCase(errStr, "SQLITE_BUSY") {
		return fmt.Sprintf("SQLite database at %s is locked by another process.\n"+
			"  Possible causes:\n"+
			"  - Another Cerberus instance is running\n"+
			"  - A database migration or backup is in progress\n"+
			"  - A crashed process left a stale lock\n"+
			"  Remediation:\n"+
			"  - Check for running Cerberus processes: ps aux | grep cerberus\n"+
			"  - Wait for any migrations to complete\n"+
			"  - If stale lock: Remove -shm and -wal files (CAUTION: only if no process is using them)\n"+
			"  - Check for lock files: ls -la %s*", absPath, absPath)
	}

	if containsIgnoreCase(errStr, "disk full") || containsIgnoreCase(errStr, "no space") || containsIgnoreCase(errStr, "SQLITE_FULL") {
		return fmt.Sprintf("Disk full - cannot write to SQLite database at %s.\n"+
			"  Remediation:\n"+
			"  - Check available disk space: df -h %s\n"+
			"  - Free up disk space or expand the volume\n"+
			"  - Consider moving data directory to a larger partition\n"+
			"  - Review retention settings to reduce data volume", absPath, parentDir)
	}

	if containsIgnoreCase(errStr, "corrupt") || containsIgnoreCase(errStr, "malformed") || containsIgnoreCase(errStr, "SQLITE_CORRUPT") {
		return fmt.Sprintf("SQLite database at %s appears to be corrupted.\n"+
			"  CRITICAL: Backup any existing data before proceeding!\n"+
			"  Remediation options:\n"+
			"  1. Try recovery: sqlite3 %s \".recover\" | sqlite3 %s.recovered\n"+
			"  2. Check integrity: sqlite3 %s \"PRAGMA integrity_check;\"\n"+
			"  3. If recovery fails, restore from backup\n"+
			"  4. As last resort, delete %s and restart (will lose data)",
			absPath, absPath, absPath, absPath, absPath)
	}

	if containsIgnoreCase(errStr, "no such file or directory") || containsIgnoreCase(errStr, "cannot find the path") {
		return fmt.Sprintf("Cannot create SQLite database - path does not exist: %s.\n"+
			"  Remediation:\n"+
			"  - Create the parent directory: mkdir -p %s\n"+
			"  - Verify the path in config or CERBERUS_SQLITE_PATH env var\n"+
			"  - Check that you have write permissions to create files there",
			absPath, parentDir)
	}

	if containsIgnoreCase(errStr, "read-only") {
		return fmt.Sprintf("SQLite database location is on a read-only file system: %s.\n"+
			"  Remediation:\n"+
			"  - Remount the file system as read-write\n"+
			"  - For Docker: Ensure volume is not mounted as read-only\n"+
			"  - Move database to a writable location via CERBERUS_SQLITE_PATH", absPath)
	}

	return fmt.Sprintf("Failed to initialize SQLite database at %s: %v\n"+
		"  Remediation:\n"+
		"  - Ensure the directory %s exists and is writable\n"+
		"  - Check disk space and permissions\n"+
		"  - Review error message for specific details", absPath, err, parentDir)
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldAt(s, substr, i) {
			return true
		}
	}
	return false
}

func equalFoldAt(s, substr string, start int) bool {
	for i := 0; i < len(substr); i++ {
		c1, c2 := s[start+i], substr[i]
		if c1 == c2 {
			continue
		}
		if 'A' <= c1 && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if 'A' <= c2 && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}
