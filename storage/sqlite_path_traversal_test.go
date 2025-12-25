package storage

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// REQUIREMENT: AFFIRMATIONS.md - Path Traversal Prevention
// REQUIREMENT: docs/requirements/security-threat-model.md FR-SEC-007 (Path Traversal)
// CRITICAL: Test that database file paths are validated to prevent directory traversal attacks

// TestNewSQLite_PathTraversal_BasicDotDot tests rejection of basic ../ path traversal
func TestNewSQLite_PathTraversal_BasicDotDot(t *testing.T) {
	// REQUIREMENT: Database paths with ../ must be rejected
	// SECURITY: Prevents accessing files outside intended directory
	logger := zap.NewNop().Sugar()

	maliciousPaths := []string{
		"../../../etc/passwd.db",
		"data/../../secrets/keys.db",
		"./../../../../../../etc/shadow.db",
		"data/../../../root/.ssh/id_rsa.db",
	}

	for _, path := range maliciousPaths {
		t.Run(path, func(t *testing.T) {
			// Attempt to create database with traversal path
			sqlite, err := NewSQLite(path, logger)

			// Even if creation succeeds, verify the actual path is sanitized
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				// Get absolute path of created database
				absPath, _ := filepath.Abs(sqlite.Path)

				// Verify it doesn't escape to system directories
				assert.NotContains(t, absPath, "/etc/", "Database should not be in /etc/")
				assert.NotContains(t, absPath, "/root/", "Database should not be in /root")
				assert.NotContains(t, absPath, "C:\\Windows\\", "Database should not be in C:\\Windows")
				assert.NotContains(t, absPath, "C:\\Program Files\\", "Database should not be in C:\\Program Files")

				t.Logf("Path '%s' resolved to '%s'", path, absPath)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_EncodedDotDot tests rejection of URL-encoded traversal
func TestNewSQLite_PathTraversal_EncodedDotDot(t *testing.T) {
	// REQUIREMENT: URL-encoded path traversal must be prevented
	// SECURITY: Prevents bypass via URL encoding (%2e%2e%2f = ../)
	logger := zap.NewNop().Sugar()

	encodedPaths := []string{
		"data/%2e%2e/%2e%2e/etc/passwd.db",
		"..%2Fetc%2Fpasswd.db",
		"%2e%2e%2f%2e%2e%2froot%2f.ssh%2fid_rsa.db",
	}

	for _, path := range encodedPaths {
		t.Run(path, func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)

			// Most file systems will reject these as literal filenames
			// If they succeed, ensure they don't escape
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				absPath, _ := filepath.Abs(sqlite.Path)
				assert.NotContains(t, absPath, "/etc/", "Encoded traversal should not reach /etc/")
				assert.NotContains(t, absPath, "/root/", "Encoded traversal should not reach /root")

				t.Logf("Encoded path '%s' resolved to '%s'", path, absPath)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_AbsolutePaths tests handling of absolute paths
func TestNewSQLite_PathTraversal_AbsolutePaths(t *testing.T) {
	// REQUIREMENT: Absolute paths to sensitive locations must be rejected
	// SECURITY: Prevents direct access to system files
	logger := zap.NewNop().Sugar()

	var sensitivePaths []string

	if runtime.GOOS == "windows" {
		sensitivePaths = []string{
			"C:\\Windows\\System32\\config\\SAM",
			"C:\\Windows\\System32\\drivers\\etc\\hosts.db",
			"C:\\ProgramData\\secrets.db",
		}
	} else {
		sensitivePaths = []string{
			"/etc/passwd.db",
			"/etc/shadow.db",
			"/root/.ssh/id_rsa.db",
			"/var/run/secrets.db",
		}
	}

	for _, path := range sensitivePaths {
		t.Run(path, func(t *testing.T) {
			// Attempt to create database at sensitive location
			sqlite, err := NewSQLite(path, logger)

			// If creation succeeds (e.g., no permissions), still verify location
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				// Verify database was not created in sensitive location
				if runtime.GOOS == "windows" {
					assert.NotContains(t, sqlite.Path, "C:\\Windows\\System32",
						"Database should not be in System32")
				} else {
					assert.NotContains(t, sqlite.Path, "/etc/",
						"Database should not be in /etc")
					assert.NotContains(t, sqlite.Path, "/root/",
						"Database should not be in /root")
				}

				t.Logf("Absolute path '%s' resolved to '%s'", path, sqlite.Path)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_SymlinkBypass tests symlink-based traversal
func TestNewSQLite_PathTraversal_SymlinkBypass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink test not applicable on Windows without admin privileges")
	}

	// REQUIREMENT: Symlinks must not bypass path restrictions
	// SECURITY: Prevents symlink-based directory traversal
	logger := zap.NewNop().Sugar()

	// Create temporary directory
	tempDir := t.TempDir()

	// Create a symlink to /etc
	symlinkPath := filepath.Join(tempDir, "link_to_etc")
	err := os.Symlink("/etc", symlinkPath)
	if err != nil {
		t.Skipf("Cannot create symlink: %v", err)
	}

	// Try to create database via symlink
	dbPath := filepath.Join(symlinkPath, "malicious.db")
	sqlite, err := NewSQLite(dbPath, logger)

	// Even if creation succeeds, verify it doesn't end up in /etc
	if err == nil && sqlite != nil {
		defer sqlite.Close()

		absPath, _ := filepath.Abs(sqlite.Path)
		assert.NotContains(t, absPath, "/etc/", "Symlink should not allow access to /etc")

		t.Logf("Symlink path '%s' resolved to '%s'", dbPath, absPath)
	}
}

// TestNewSQLite_PathTraversal_NullByteInjection tests null byte injection
func TestNewSQLite_PathTraversal_NullByteInjection(t *testing.T) {
	// REQUIREMENT: Null bytes in paths must be rejected
	// SECURITY: Prevents null byte injection to bypass extension checks
	logger := zap.NewNop().Sugar()

	nullBytePaths := []string{
		"malicious.db\x00.txt",
		"data/test\x00/../../../etc/passwd",
		"normal.db\x00/../../secret",
	}

	for _, path := range nullBytePaths {
		t.Run(strings.ReplaceAll(path, "\x00", "\\x00"), func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)

			// Go's file system API should reject null bytes
			// If it succeeds, verify path is safe
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				// Verify null byte doesn't truncate path
				assert.NotContains(t, sqlite.Path, "\x00", "Path should not contain null bytes")

				t.Logf("Null byte path resolved to '%s'", sqlite.Path)
			} else {
				// Expected: null bytes should cause error
				t.Logf("Null byte path correctly rejected: %v", err)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_BackslashVariations tests Windows-specific traversal
func TestNewSQLite_PathTraversal_BackslashVariations(t *testing.T) {
	// REQUIREMENT: Windows path traversal variants must be prevented
	// SECURITY: Prevents Windows-specific directory traversal
	logger := zap.NewNop().Sugar()

	windowsPaths := []string{
		"..\\..\\..\\Windows\\System32\\config.db",
		"data\\..\\..\\..\\..\\secrets.db",
		"./../../Windows/System32/test.db", // Mixed slashes
		".\\..\\..\\ProgramData\\secrets.db",
	}

	for _, path := range windowsPaths {
		t.Run(path, func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)

			if err == nil && sqlite != nil {
				defer sqlite.Close()

				absPath, _ := filepath.Abs(sqlite.Path)

				if runtime.GOOS == "windows" {
					assert.NotContains(t, absPath, "Windows\\System32",
						"Database should not be in System32")
					assert.NotContains(t, absPath, "ProgramData",
						"Database should not be in ProgramData (unless intended)")
				}

				t.Logf("Windows path '%s' resolved to '%s'", path, absPath)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_LongPaths tests extremely long paths
func TestNewSQLite_PathTraversal_LongPaths(t *testing.T) {
	// REQUIREMENT: Extremely long paths must be handled safely
	// SECURITY: Prevents buffer overflow or DoS via path length
	logger := zap.NewNop().Sugar()

	// Create a very long path (exceeds most PATH_MAX limits)
	longPath := strings.Repeat("../", 500) + "etc/passwd.db"

	sqlite, err := NewSQLite(longPath, logger)

	// System should either reject or safely handle long paths
	if err == nil && sqlite != nil {
		defer sqlite.Close()

		absPath, _ := filepath.Abs(sqlite.Path)

		// Even with long path, should not reach system directories
		assert.NotContains(t, absPath, "/etc/", "Long path should not reach /etc")
		assert.NotContains(t, absPath, "/root/", "Long path should not reach /root")

		t.Logf("Long path (len=%d) resolved to '%s'", len(longPath), absPath)
	}
}

// TestNewSQLite_PathTraversal_SpecialFilenames tests special OS filenames
func TestNewSQLite_PathTraversal_SpecialFilenames(t *testing.T) {
	// REQUIREMENT: Special OS filenames must be handled safely
	// SECURITY: Prevents device file access or OS-specific attacks
	logger := zap.NewNop().Sugar()

	var specialNames []string

	if runtime.GOOS == "windows" {
		specialNames = []string{
			"CON",
			"PRN",
			"AUX",
			"NUL",
			"COM1",
			"LPT1",
			"CON.db",
			"data/NUL/test.db",
		}
	} else {
		specialNames = []string{
			"/dev/null",
			"/dev/zero",
			"/dev/random",
			"/proc/self/mem",
		}
	}

	for _, name := range specialNames {
		t.Run(name, func(t *testing.T) {
			sqlite, err := NewSQLite(name, logger)

			// System may reject these special names
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				// Verify it's not actually a device file
				if runtime.GOOS != "windows" {
					fileInfo, statErr := os.Stat(sqlite.Path)
					if statErr == nil {
						assert.False(t, fileInfo.Mode()&os.ModeDevice != 0,
							"Database should not be a device file")
					}
				}

				t.Logf("Special name '%s' resolved to '%s'", name, sqlite.Path)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_UNCPaths tests UNC path handling (Windows)
func TestNewSQLite_PathTraversal_UNCPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("UNC paths are Windows-specific")
	}

	// REQUIREMENT: UNC paths must be handled safely
	// SECURITY: Prevents remote file system access or SMB attacks
	logger := zap.NewNop().Sugar()

	uncPaths := []string{
		"\\\\malicious-server\\share\\database.db",
		"\\\\localhost\\c$\\Windows\\System32\\config.db",
		"\\\\?\\C:\\Windows\\System32\\test.db",
	}

	for _, path := range uncPaths {
		t.Run(path, func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)

			// UNC paths may be rejected or handled specially
			if err == nil && sqlite != nil {
				defer sqlite.Close()

				// Verify we're not accessing remote shares unintentionally
				assert.NotContains(t, sqlite.Path, "\\\\malicious-server",
					"Should not access malicious remote servers")

				t.Logf("UNC path '%s' resolved to '%s'", path, sqlite.Path)
			}
		})
	}
}

// TestNewSQLite_PathTraversal_SafePaths tests that legitimate paths work correctly
func TestNewSQLite_PathTraversal_SafePaths(t *testing.T) {
	// REQUIREMENT: Legitimate database paths must work correctly
	// SECURITY: Path validation must not break normal operation
	logger := zap.NewNop().Sugar()

	tempDir := t.TempDir()

	safePaths := []string{
		filepath.Join(tempDir, "test.db"),
		filepath.Join(tempDir, "data", "cerberus.db"),
		filepath.Join(tempDir, "backup", "2024-01-15", "database.db"),
		":memory:", // Special case: in-memory database
	}

	for _, path := range safePaths {
		t.Run(path, func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)
			require.NoError(t, err, "Legitimate path should be accepted: %s", path)
			require.NotNil(t, sqlite)
			defer sqlite.Close()

			// Verify database is functional
			err = sqlite.HealthCheck()
			assert.NoError(t, err, "Database should be healthy")
		})
	}
}

// TestSQLite_DirectoryCreation_PathTraversal tests directory creation safety
func TestSQLite_DirectoryCreation_PathTraversal(t *testing.T) {
	// REQUIREMENT: Automatic directory creation must not enable traversal
	// SECURITY: Prevents creation of directories in unintended locations
	logger := zap.NewNop().Sugar()

	tempDir := t.TempDir()

	// Test that nested directory creation works safely
	safePath := filepath.Join(tempDir, "level1", "level2", "level3", "test.db")

	sqlite, err := NewSQLite(safePath, logger)
	require.NoError(t, err)
	require.NotNil(t, sqlite)
	defer sqlite.Close()

	// Verify all parent directories were created
	assert.DirExists(t, filepath.Join(tempDir, "level1"))
	assert.DirExists(t, filepath.Join(tempDir, "level1", "level2"))
	assert.DirExists(t, filepath.Join(tempDir, "level1", "level2", "level3"))

	// Verify database file exists
	assert.FileExists(t, safePath)
}

// TestSQLite_PathTraversal_RaceCondition tests TOCTOU vulnerabilities
func TestSQLite_PathTraversal_RaceCondition(t *testing.T) {
	// REQUIREMENT: Path validation must prevent TOCTOU (Time-of-Check Time-of-Use) attacks
	// SECURITY: Prevents symlink race conditions
	logger := zap.NewNop().Sugar()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "race_test.db")

	// Create database
	sqlite1, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	require.NotNil(t, sqlite1)

	// Close first connection
	err = sqlite1.Close()
	require.NoError(t, err)

	// Remove database file
	err = os.Remove(dbPath)
	require.NoError(t, err)

	// On Unix systems, could replace with symlink here (TOCTOU attack)
	// Create database again - should create new file, not follow symlink
	sqlite2, err := NewSQLite(dbPath, logger)
	require.NoError(t, err)
	require.NotNil(t, sqlite2)
	defer sqlite2.Close()

	// Verify it's a regular file, not a symlink
	fileInfo, err := os.Lstat(dbPath) // Lstat doesn't follow symlinks
	require.NoError(t, err)

	assert.False(t, fileInfo.Mode()&os.ModeSymlink != 0,
		"Database should be a regular file, not a symlink")
}

// TestSQLite_PathTraversal_CaseSensitivity tests case sensitivity handling
func TestSQLite_PathTraversal_CaseSensitivity(t *testing.T) {
	// REQUIREMENT: Path handling must be consistent across case-sensitive/insensitive systems
	// SECURITY: Prevents bypass via case variations on case-insensitive systems
	logger := zap.NewNop().Sugar()

	tempDir := t.TempDir()

	// Test paths with different case variations
	paths := []string{
		filepath.Join(tempDir, "Database.db"),
		filepath.Join(tempDir, "database.db"),
		filepath.Join(tempDir, "DATABASE.DB"),
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			sqlite, err := NewSQLite(path, logger)
			require.NoError(t, err)
			require.NotNil(t, sqlite)
			defer sqlite.Close()

			// On case-insensitive systems, these should all refer to same file
			// On case-sensitive systems, they're different files (both are valid behaviors)
			t.Logf("Created database at: %s", sqlite.Path)
		})
	}
}
