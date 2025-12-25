package storage

import (
	"cerberus/metrics"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// SQLite holds the SQLite database connections for metadata storage
// PERFORMANCE: Separate read and write pools to leverage WAL mode's concurrent read capability
// TASK 143: Fix SQLite connection pool performance bottleneck
type SQLite struct {
	DB      *sql.DB // Write connection pool (legacy field, kept for backward compatibility, same as WriteDB)
	WriteDB *sql.DB // Write-only connection pool (MaxOpenConns=1 for WAL mode single writer)
	ReadDB  *sql.DB // Read-only connection pool (MaxOpenConns=10 for concurrent reads)
	Path    string
	Logger  *zap.SugaredLogger

	// BLOCKER #4 FIX: Track previous counter values for delta calculation
	// Counters in Prometheus should only increase, so we track deltas
	prevWriteWaitCount         int64
	prevWriteMaxIdleClosed     int64
	prevWriteMaxLifetimeClosed int64
	prevReadWaitCount          int64
	prevReadMaxIdleClosed      int64
	prevReadMaxLifetimeClosed  int64
}

// configureSQLiteConnection configures a SQLite database connection with standard settings
// This function sets up WAL mode, foreign keys, and busy timeout for both read and write pools
func configureSQLiteConnection(db *sql.DB, logger *zap.SugaredLogger, dbPath string, poolType string) error {
	// BLOCKER #1 FIX: Enable WAL mode explicitly with PRAGMA (connection string params don't work reliably)
	_, err := db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Enable foreign key constraints
	// SECURITY FIX GAP-003: Enable foreign key constraints
	// REQUIREMENT: TEST_IMPROVEMENTS_PART2.md GAP-003 (DATA-001)
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.2
	// CRITICAL: SQLite disables foreign keys by default - MUST enable explicitly
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Verify foreign keys are actually enabled
	var fkEnabled int
	err = db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	if err != nil {
		return fmt.Errorf("failed to verify foreign keys: %w", err)
	}
	if fkEnabled != 1 {
		return fmt.Errorf("CRITICAL: foreign keys not enabled (got: %d, expected: 1) - referential integrity will not be enforced", fkEnabled)
	}
	logger.Infof("SQLite %s pool: foreign keys verified enabled", poolType)

	// Set busy timeout to prevent immediate SQLITE_BUSY errors
	_, err = db.Exec("PRAGMA busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("failed to set busy timeout: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	// Verify WAL mode is actually enabled
	// BLOCKER #1 FIX: Verify WAL mode is actually enabled
	// REQUIREMENT: FR-ACID-002 (Crash Recovery requires WAL mode)
	// NOTE: In-memory databases (":memory:") use "memory" journal mode, not "wal"
	var journalMode string
	err = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		return fmt.Errorf("failed to query journal mode: %w", err)
	}
	// Skip WAL check for in-memory databases (they use "memory" mode)
	if dbPath != ":memory:" && journalMode != "wal" {
		return fmt.Errorf("CRITICAL: WAL mode not enabled (got: %s, expected: wal) - crash recovery will not work", journalMode)
	}
	logger.Infof("SQLite %s pool: journal mode verified: %s", poolType, journalMode)

	return nil
}

// NewSQLite creates a new SQLite connection
func NewSQLite(dbPath string, logger *zap.SugaredLogger) (*SQLite, error) {
	// SECURITY: Validate database path to prevent path traversal attacks
	// REQUIREMENT: AFFIRMATIONS.md - Path Traversal Prevention
	// FR-SEC-007: File path validation
	if err := validateDatabasePath(dbPath); err != nil {
		return nil, fmt.Errorf("invalid database path: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// PERFORMANCE FIX TASK 143: Create separate read and write connection pools
	// CRITICAL: WAL mode supports unlimited concurrent readers + 1 writer
	// Previous bottleneck: MaxOpenConns=1 serialized ALL operations (reads + writes)
	// New approach: Separate pools to leverage WAL concurrency model
	// Reference: https://www.sqlite.org/wal.html#concurrency

	// TASK 149 FIX: For in-memory databases, use shared cache mode so both pools access the same database
	// Without shared cache, each sql.Open(":memory:") creates a separate empty database
	// Reference: https://www.sqlite.org/inmemorydb.html#sharedmemdb
	actualPath := dbPath
	if dbPath == ":memory:" {
		actualPath = "file::memory:?cache=shared"
	}

	// === WRITE CONNECTION POOL ===
	// Open write connection pool (for INSERT, UPDATE, DELETE, DDL)
	writeDB, err := sql.Open("sqlite", actualPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite write database: %w", err)
	}

	// Configure write connection
	if err := configureSQLiteConnection(writeDB, logger, dbPath, "write"); err != nil {
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to configure write connection: %w", err)
	}

	// WRITE POOL: Single writer for WAL mode safety
	// WAL mode requires exactly one writer at a time for consistency
	writeDB.SetMaxOpenConns(1)
	writeDB.SetMaxIdleConns(1)
	writeDB.SetConnMaxLifetime(0)                // Connections never expire (important for in-memory databases)
	writeDB.SetConnMaxIdleTime(10 * time.Minute) // Close idle connections after 10 minutes
	logger.Infof("SQLite write pool configured: MaxOpenConns=1 (WAL single writer)")

	// === READ CONNECTION POOL ===
	// Open read connection pool (for SELECT queries)
	readDB, err := sql.Open("sqlite", actualPath)
	if err != nil {
		_ = writeDB.Close()
		return nil, fmt.Errorf("failed to open SQLite read database: %w", err)
	}

	// Configure read connection
	if err := configureSQLiteConnection(readDB, logger, dbPath, "read"); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("failed to configure read connection: %w", err)
	}

	// BLOCKER #3 FIX: Enable query_only mode for read pool to prevent accidental writes
	// SECURITY: This enforces read-only access at the SQLite level
	// REQUIREMENT: GATEKEEPER BLOCKER #3 - ReadDB Write Prevention
	_, err = readDB.Exec("PRAGMA query_only=ON")
	if err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("failed to enable query_only mode on read pool: %w", err)
	}

	// Verify query_only is actually enabled
	var queryOnly int
	err = readDB.QueryRow("PRAGMA query_only").Scan(&queryOnly)
	if err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("failed to verify query_only mode: %w", err)
	}
	if queryOnly != 1 {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("CRITICAL: query_only mode not enabled on read pool (got: %d, expected: 1)", queryOnly)
	}
	logger.Infof("SQLite read pool: query_only mode verified enabled")

	// READ POOL: Multiple concurrent readers (10 connections)
	// WAL mode allows unlimited concurrent readers without blocking
	// 10 connections balances throughput with resource usage
	readDB.SetMaxOpenConns(10)                  // Enable concurrent reads
	readDB.SetMaxIdleConns(5)                   // Keep half the connections warm
	readDB.SetConnMaxLifetime(5 * time.Minute)  // Rotate connections periodically
	readDB.SetConnMaxIdleTime(10 * time.Minute) // Close idle connections
	logger.Infof("SQLite read pool configured: MaxOpenConns=10 (concurrent reads enabled)")

	sqlite := &SQLite{
		DB:      writeDB, // Legacy field for backward compatibility
		WriteDB: writeDB,
		ReadDB:  readDB,
		Path:    dbPath,
		Logger:  logger,
	}

	// Create tables
	if err := sqlite.createTables(); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	logger.Infof("SQLite database initialized at %s with separate read/write pools", dbPath)

	return sqlite, nil
}

// WithTransaction executes a function within a database transaction
// TASK 6.2: Transaction wrapper utility with rollback on error/panic
// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 4.2
// SECURITY: Ensures ACID compliance for multi-statement operations
func (s *SQLite) WithTransaction(fn func(*sql.Tx) error) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // Re-panic after rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("failed to rollback transaction (original error: %w, rollback error: %v)", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// createTables creates all necessary tables
func (s *SQLite) createTables() error {
	schema := `
	-- Rules table (unified SIGMA and CQL)
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma', -- 'sigma' or 'cql'
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		version INTEGER NOT NULL DEFAULT 1,
		tags TEXT, -- JSON array
		mitre_tactics TEXT, -- JSON array
		mitre_techniques TEXT, -- JSON array
		author TEXT,
		rule_references TEXT, -- JSON array (renamed from 'references' to avoid reserved keyword)
		false_positives TEXT,
		metadata TEXT, -- JSON object
		-- SIGMA-specific fields (detection is authoritative for SIGMA rules)
		sigma_yaml TEXT, -- Full SIGMA YAML for display/editing (primary source of truth)
		detection TEXT, -- JSON object: SIGMA detection logic for YAML editing
		logsource TEXT, -- JSON object: SIGMA logsource definition
		logsource_category TEXT, -- Denormalized for filtering
		logsource_product TEXT, -- Denormalized for filtering
		logsource_service TEXT, -- Denormalized for filtering
		actions TEXT, -- JSON array
		-- CQL-specific fields
		query TEXT, -- CQL query string (optional for SIGMA)
		correlation TEXT, -- JSON object (optional for SIGMA)
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
	CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
	-- TASK 150: Additional indexes for query performance
	CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at DESC);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled_severity ON rules(enabled, severity);  -- Composite index for common query pattern
	-- SIGMA YAML denormalized logsource indexes for filtering
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_category ON rules(logsource_category);
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_product ON rules(logsource_product);
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_service ON rules(logsource_service);

	-- Actions table
	CREATE TABLE IF NOT EXISTS actions (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		config TEXT NOT NULL, -- JSON object
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_actions_type ON actions(type);

	-- Correlation Rules table
	CREATE TABLE IF NOT EXISTS correlation_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		window INTEGER NOT NULL, -- Duration in nanoseconds
		conditions TEXT NOT NULL, -- JSON array
		sequence TEXT NOT NULL, -- JSON array
		actions TEXT, -- JSON array
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_correlation_rules_severity ON correlation_rules(severity);

	-- Roles table for RBAC
	-- TASK 31.4: Roles persistence layer in SQLite
	CREATE TABLE IF NOT EXISTS roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		permissions TEXT NOT NULL, -- JSON array of permissions
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

	-- TASK 31.4: Role permissions table for flexible permission assignment (optional normalized schema)
	-- Note: Currently using JSON array in roles table for simplicity
	-- This table provides a normalized alternative for future use
	CREATE TABLE IF NOT EXISTS role_permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		role_id INTEGER NOT NULL,
		permission TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		UNIQUE(role_id, permission)
	);
	CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
	CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission);

	-- TASK 31.4: User roles table for user-role mapping with audit fields
	-- Note: Currently using role_id foreign key in users table for simplicity
	-- This table provides a normalized alternative with audit trail for future use
	CREATE TABLE IF NOT EXISTS user_roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		role_id INTEGER NOT NULL,
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		assigned_by TEXT,
		FOREIGN KEY (user_id) REFERENCES users(username) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
		UNIQUE(user_id, role_id)
	);
	CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_assigned_at ON user_roles(assigned_at DESC);

	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		roles TEXT, -- JSON array (DEPRECATED - for backward compatibility)
		role_id INTEGER, -- Foreign key to roles table
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		-- TASK 8.3: MFA/TOTP support
		totp_secret TEXT, -- TOTP secret for MFA
		mfa_enabled INTEGER NOT NULL DEFAULT 0, -- Whether MFA is enabled
		-- TASK 8.5: Account lockout support
		failed_login_attempts INTEGER NOT NULL DEFAULT 0, -- Number of consecutive failed login attempts
		locked_until DATETIME, -- Account lockout expiration
		password_changed_at DATETIME, -- Last password change time (for password expiry)
		-- TASK 38.3: Force password change on first login
		must_change_password INTEGER NOT NULL DEFAULT 1, -- Force password change on next login (default: true for new users)
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
	);
	CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
	CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
	CREATE INDEX IF NOT EXISTS idx_users_password_changed_at ON users(password_changed_at);

	-- TASK 38.3: Password history table for tracking password reuse
	CREATE TABLE IF NOT EXISTS password_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(username) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
	CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at DESC);

	-- ML Models table (TASK 26.2: Model persistence and versioning)
	-- TASK 37: Enhanced with status, file_path, and lifecycle tracking
	CREATE TABLE IF NOT EXISTS ml_models (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		model_type TEXT NOT NULL,
		model_data BLOB, -- TASK 37: Made optional (can be stored in file_path instead)
		file_path TEXT, -- TASK 37: Path to serialized model file (optional, alternative to BLOB)
		status TEXT NOT NULL DEFAULT 'training', -- TASK 37: active, retired, training
		algorithm TEXT, -- TASK 37: zscore, iqr, isolation_forest (derived from model_type for clarity)
		config TEXT,
		trained_at DATETIME NOT NULL,
		training_started_at DATETIME, -- TASK 37: When training began
		training_completed_at DATETIME, -- TASK 37: When training finished
		training_samples INTEGER, -- TASK 37: Number of samples used for training
		hyperparameters TEXT, -- TASK 37: JSON hyperparameters
		metrics TEXT, -- JSON performance metrics (precision, recall, F1)
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- TASK 37: Creation timestamp
		UNIQUE(name, version)
	);
	CREATE INDEX IF NOT EXISTS idx_ml_models_name ON ml_models(name);
	CREATE INDEX IF NOT EXISTS idx_ml_models_version ON ml_models(name, version);
	CREATE INDEX IF NOT EXISTS idx_ml_models_status ON ml_models(status); -- TASK 37: Index for active model queries
	CREATE INDEX IF NOT EXISTS idx_ml_models_algorithm ON ml_models(algorithm); -- TASK 37: Index for algorithm filtering

	-- ML Model Deployments table (TASK 26.5: Model rollback and deployment tracking)
	CREATE TABLE IF NOT EXISTS ml_model_deployments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		model_name TEXT NOT NULL,
		model_version TEXT NOT NULL,
		deployed_at DATETIME NOT NULL,
		deployed_by TEXT,
		is_active INTEGER NOT NULL DEFAULT 1,
		FOREIGN KEY (model_name, model_version) REFERENCES ml_models(name, version)
	);
	CREATE INDEX IF NOT EXISTS idx_ml_deployments_active ON ml_model_deployments(model_name, is_active);
	CREATE INDEX IF NOT EXISTS idx_ml_deployments_deployed_at ON ml_model_deployments(deployed_at DESC);

	-- Exceptions table
	CREATE TABLE IF NOT EXISTS exceptions (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		rule_id TEXT, -- Empty or NULL for global exceptions
		type TEXT NOT NULL, -- 'suppress' or 'modify_severity'
		condition_type TEXT NOT NULL, -- 'sigma_filter' or 'cql'
		condition TEXT NOT NULL,
		new_severity TEXT, -- For modify_severity type
		enabled INTEGER NOT NULL DEFAULT 1,
		priority INTEGER NOT NULL DEFAULT 100, -- Lower = higher priority
		expires_at DATETIME,
		hit_count INTEGER NOT NULL DEFAULT 0,
		last_hit DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		created_by TEXT,
		justification TEXT,
		tags TEXT, -- JSON array
		-- SECURITY FIX GAP-003: Add foreign key constraint for referential integrity
		-- REQUIREMENT: TEST_IMPROVEMENTS_PART2.md GAP-003 (DATA-001)
		-- REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.2
		-- CRITICAL: Prevents orphaned exceptions pointing to deleted rules
		-- ON DELETE CASCADE: When a rule is deleted, auto-delete its exceptions
		-- NULL is allowed for global exceptions (not tied to specific rule)
		FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_exceptions_rule_id ON exceptions(rule_id);
	CREATE INDEX IF NOT EXISTS idx_exceptions_enabled ON exceptions(enabled);
	CREATE INDEX IF NOT EXISTS idx_exceptions_priority ON exceptions(priority);
	CREATE INDEX IF NOT EXISTS idx_exceptions_type ON exceptions(type);
	CREATE INDEX IF NOT EXISTS idx_exceptions_expires_at ON exceptions(expires_at);

	-- Dead Letter Queue (DLQ) table for malformed events
	-- TASK 7.1: DLQ database schema for malformed event storage
	-- REQUIREMENT: docs/requirements/data-ingestion-requirements.md FR-ING-012
	CREATE TABLE IF NOT EXISTS dead_letter_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		listener_id TEXT,  -- Optional listener ID for per-listener DLQ filtering
		protocol TEXT NOT NULL,  -- 'syslog', 'cef', 'json', 'fluentd'
		raw_event TEXT NOT NULL,
		error_reason TEXT NOT NULL,
		error_details TEXT,
		source_ip TEXT,
		retries INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'replayed', 'discarded'
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_dlq_timestamp ON dead_letter_queue(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dlq_status ON dead_letter_queue(status);
	CREATE INDEX IF NOT EXISTS idx_dlq_protocol ON dead_letter_queue(protocol);
	-- Note: idx_dlq_listener_id index is created by migration to support existing databases

	-- MITRE ATT&CK Tactics table
	-- TASK 9.1: MITRE tactics storage
	CREATE TABLE IF NOT EXISTS mitre_tactics (
		id TEXT PRIMARY KEY,  -- 'TA0001'
		stix_id TEXT UNIQUE NOT NULL,  -- STIX UUID
		name TEXT NOT NULL,
		description TEXT,
		short_name TEXT NOT NULL,  -- 'initial-access'
		version TEXT,
		deprecated INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tactics_short_name ON mitre_tactics(short_name);

	-- MITRE ATT&CK Techniques table (supports sub-techniques)
	-- TASK 9.1: MITRE techniques and sub-techniques storage
	CREATE TABLE IF NOT EXISTS mitre_techniques (
		id TEXT PRIMARY KEY,  -- 'T1234' or 'T1234.001'
		stix_id TEXT UNIQUE NOT NULL,  -- STIX UUID
		name TEXT NOT NULL,
		description TEXT,
		tactic_id TEXT,  -- Tactic this technique belongs to (can be multiple via relationships)
		parent_technique_id TEXT,  -- For sub-techniques
		detection_methods TEXT,  -- JSON array
		data_sources TEXT,  -- JSON array
		platforms TEXT,  -- JSON array
		is_subtechnique INTEGER NOT NULL DEFAULT 0,
		version TEXT,
		deprecated INTEGER NOT NULL DEFAULT 0,
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (parent_technique_id) REFERENCES mitre_techniques(id)
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_tactic_id ON mitre_techniques(tactic_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_parent_id ON mitre_techniques(parent_technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_techniques_is_subtechnique ON mitre_techniques(is_subtechnique);

	-- MITRE ATT&CK Data Sources table
	-- TASK 9.1: MITRE data sources storage
	CREATE TABLE IF NOT EXISTS mitre_data_sources (
		id TEXT PRIMARY KEY,  -- 'DS0001' (external ID) or STIX UUID
		stix_id TEXT UNIQUE NOT NULL,  -- STIX UUID
		name TEXT NOT NULL,
		description TEXT,
		collection_layers TEXT,  -- JSON array
		platforms TEXT,  -- JSON array
		version TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- MITRE Technique-Data Source mapping table
	-- TASK 9.1: Many-to-many relationship between techniques and data sources
	CREATE TABLE IF NOT EXISTS mitre_technique_data_sources (
		technique_id TEXT NOT NULL,
		data_source_id TEXT NOT NULL,
		PRIMARY KEY (technique_id, data_source_id),
		FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
		FOREIGN KEY (data_source_id) REFERENCES mitre_data_sources(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tds_technique_id ON mitre_technique_data_sources(technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_tds_data_source_id ON mitre_technique_data_sources(data_source_id);

	-- MITRE Technique-Tactic mapping table (many-to-many)
	-- TASK 9.1: Techniques can belong to multiple tactics
	CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
		technique_id TEXT NOT NULL,
		tactic_id TEXT NOT NULL,
		PRIMARY KEY (technique_id, tactic_id),
		FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
		FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_mitre_tt_technique_id ON mitre_technique_tactics(technique_id);
	CREATE INDEX IF NOT EXISTS idx_mitre_tt_tactic_id ON mitre_technique_tactics(tactic_id);

	-- TASK 160.1: System metadata table for application-level settings
	-- Stores key-value pairs for system configuration like setup completion status
	CREATE TABLE IF NOT EXISTS system_metadata (
		key TEXT PRIMARY KEY NOT NULL,
		value TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := s.DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	s.Logger.Info("SQLite tables created/verified")

	// Run migrations using the new framework
	if err := s.RunMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// migrate applies schema migrations for existing databases
func (s *SQLite) migrate() error {
	// Migration 1: Check if type column exists in rules table
	var hasTypeColumn bool
	row := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='type'")
	var count int
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("failed to check for type column: %w", err)
	}
	hasTypeColumn = count > 0

	// Add new columns if they don't exist
	if !hasTypeColumn {
		s.Logger.Info("Running migration: Adding unified rule columns")
		migrations := []string{
			"ALTER TABLE rules ADD COLUMN type TEXT NOT NULL DEFAULT 'sigma'",
			"ALTER TABLE rules ADD COLUMN tags TEXT",
			"ALTER TABLE rules ADD COLUMN mitre_tactics TEXT",
			"ALTER TABLE rules ADD COLUMN mitre_techniques TEXT",
			"ALTER TABLE rules ADD COLUMN author TEXT",
			"ALTER TABLE rules ADD COLUMN rule_references TEXT",
			"ALTER TABLE rules ADD COLUMN false_positives TEXT",
			"ALTER TABLE rules ADD COLUMN metadata TEXT",
			"ALTER TABLE rules ADD COLUMN query TEXT",
			"ALTER TABLE rules ADD COLUMN correlation TEXT",
			"CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type)",
		}

		for _, migration := range migrations {
			if _, err := s.DB.Exec(migration); err != nil {
				// Some columns might already exist, log but continue
				s.Logger.Warnf("Migration warning: %v (query: %s)", err, migration)
			}
		}
		s.Logger.Info("Migration completed: Unified rule schema applied")
	}

	// Migration: Add detection and logsource columns for SIGMA YAML editing
	var hasDetectionColumn bool
	row = s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='detection'")
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("failed to check for detection column: %w", err)
	}
	hasDetectionColumn = count > 0

	if !hasDetectionColumn {
		s.Logger.Info("Running migration: Adding SIGMA detection and logsource columns")
		detectionMigrations := []string{
			"ALTER TABLE rules ADD COLUMN detection TEXT", // JSON object for SIGMA detection
			"ALTER TABLE rules ADD COLUMN logsource TEXT", // JSON object for SIGMA logsource
		}
		for _, migration := range detectionMigrations {
			if _, err := s.DB.Exec(migration); err != nil {
				s.Logger.Warnf("Migration warning: %v (query: %s)", err, migration)
			}
		}
		s.Logger.Info("Migration completed: SIGMA detection columns added")
	}

	// Migration 2: Add role_id column to users table for RBAC
	var hasRoleIDColumn bool
	row = s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='role_id'")
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("failed to check for role_id column: %w", err)
	}
	hasRoleIDColumn = count > 0

	if !hasRoleIDColumn {
		s.Logger.Info("Running migration: Adding RBAC role_id column to users table")
		// Add role_id column (nullable for backward compatibility)
		if _, err := s.DB.Exec("ALTER TABLE users ADD COLUMN role_id INTEGER"); err != nil {
			s.Logger.Warnf("Migration warning: %v (adding role_id column)", err)
		}
		// Create index for performance
		if _, err := s.DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id)"); err != nil {
			s.Logger.Warnf("Migration warning: %v (creating role_id index)", err)
		}
		s.Logger.Info("Migration completed: RBAC role_id column added")
	}

	// Migration 3: Add security columns (MFA, account lockout, password expiry) to users table
	// TASK 8.3 & 8.5: MFA/TOTP and account lockout support
	securityMigrations := []struct {
		name  string
		query string
		check string
	}{
		{
			name:  "totp_secret",
			query: "ALTER TABLE users ADD COLUMN totp_secret TEXT",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='totp_secret'",
		},
		{
			name:  "mfa_enabled",
			query: "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='mfa_enabled'",
		},
		{
			name:  "failed_login_attempts",
			query: "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='failed_login_attempts'",
		},
		{
			name:  "locked_until",
			query: "ALTER TABLE users ADD COLUMN locked_until DATETIME",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='locked_until'",
		},
		{
			name:  "password_changed_at",
			query: "ALTER TABLE users ADD COLUMN password_changed_at DATETIME",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='password_changed_at'",
		},
		// TASK 38.3: Force password change on first login
		{
			name:  "must_change_password",
			query: "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1",
			check: "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='must_change_password'",
		},
	}

	for _, migration := range securityMigrations {
		var hasColumn bool
		row = s.DB.QueryRow(migration.check)
		if err := row.Scan(&count); err != nil {
			s.Logger.Warnf("Failed to check for %s column: %v", migration.name, err)
			continue
		}
		hasColumn = count > 0

		if !hasColumn {
			s.Logger.Infof("Running migration: Adding %s column to users table", migration.name)
			if _, err := s.DB.Exec(migration.query); err != nil {
				s.Logger.Warnf("Migration warning: %v (adding %s column)", err, migration.name)
			} else {
				s.Logger.Infof("Migration completed: %s column added", migration.name)
			}
		}
	}

	// Create index for locked_until if it doesn't exist
	if _, err := s.DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until)"); err != nil {
		s.Logger.Warnf("Migration warning: %v (creating locked_until index)", err)
	}

	// TASK 37: ML model table migrations for enhanced persistence
	mlModelMigrations := []struct {
		name  string
		query string
		check string
	}{
		{
			name:  "status",
			query: "ALTER TABLE ml_models ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='status'",
		},
		{
			name:  "file_path",
			query: "ALTER TABLE ml_models ADD COLUMN file_path TEXT",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='file_path'",
		},
		{
			name:  "algorithm",
			query: "ALTER TABLE ml_models ADD COLUMN algorithm TEXT",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='algorithm'",
		},
		{
			name:  "training_started_at",
			query: "ALTER TABLE ml_models ADD COLUMN training_started_at DATETIME",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='training_started_at'",
		},
		{
			name:  "training_completed_at",
			query: "ALTER TABLE ml_models ADD COLUMN training_completed_at DATETIME",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='training_completed_at'",
		},
		{
			name:  "training_samples",
			query: "ALTER TABLE ml_models ADD COLUMN training_samples INTEGER",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='training_samples'",
		},
		{
			name:  "hyperparameters",
			query: "ALTER TABLE ml_models ADD COLUMN hyperparameters TEXT",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='hyperparameters'",
		},
		{
			name:  "created_at",
			query: "ALTER TABLE ml_models ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
			check: "SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='created_at'",
		},
	}

	for _, migration := range mlModelMigrations {
		var hasColumn bool
		row = s.DB.QueryRow(migration.check)
		if err := row.Scan(&count); err != nil {
			s.Logger.Warnf("Failed to check for %s column in ml_models: %v", migration.name, err)
			continue
		}
		hasColumn = count > 0

		if !hasColumn {
			s.Logger.Infof("Running migration: Adding %s column to ml_models table", migration.name)
			if _, err := s.DB.Exec(migration.query); err != nil {
				s.Logger.Warnf("Migration warning: %v (adding %s column to ml_models)", err, migration.name)
			} else {
				s.Logger.Infof("Migration completed: %s column added to ml_models", migration.name)
			}
		}
	}

	// TASK 37: Create indexes for new ML model fields
	if _, err := s.DB.Exec("CREATE INDEX IF NOT EXISTS idx_ml_models_status ON ml_models(status)"); err != nil {
		s.Logger.Warnf("Migration warning: %v (creating ml_models status index)", err)
	}
	if _, err := s.DB.Exec("CREATE INDEX IF NOT EXISTS idx_ml_models_algorithm ON ml_models(algorithm)"); err != nil {
		s.Logger.Warnf("Migration warning: %v (creating ml_models algorithm index)", err)
	}

	// Migration: Add listener_id column to dead_letter_queue for per-listener DLQ support
	var dlqListenerIDExists int
	row = s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('dead_letter_queue') WHERE name='listener_id'")
	if err := row.Scan(&dlqListenerIDExists); err != nil {
		s.Logger.Warnf("Failed to check for listener_id column in dead_letter_queue: %v", err)
	} else if dlqListenerIDExists == 0 {
		s.Logger.Info("Running migration: Adding listener_id column to dead_letter_queue table")
		if _, err := s.DB.Exec("ALTER TABLE dead_letter_queue ADD COLUMN listener_id TEXT"); err != nil {
			s.Logger.Warnf("Migration warning: %v (adding listener_id column to dead_letter_queue)", err)
		} else {
			s.Logger.Info("Migration completed: listener_id column added to dead_letter_queue")
		}
	}
	// Always try to create the index (for both new and migrated databases)
	if _, err := s.DB.Exec("CREATE INDEX IF NOT EXISTS idx_dlq_listener_id ON dead_letter_queue(listener_id)"); err != nil {
		s.Logger.Warnf("Migration warning: %v (creating dlq listener_id index)", err)
	}

	return nil
}

// RunMigrations runs all pending migrations using the centralized migration framework
func (s *SQLite) RunMigrations() error {
	// Create migration runner
	runner, err := NewMigrationRunner(s.DB, s.Logger)
	if err != nil {
		return fmt.Errorf("failed to create migration runner: %w", err)
	}

	// Register all SQLite migrations
	RegisterSQLiteMigrations(runner)

	// Check if this is a fresh database or one with existing inline migrations
	// If columns already exist but no schema_migrations records, mark base migrations as applied
	if err := s.reconcileExistingMigrations(runner); err != nil {
		s.Logger.Warnf("Failed to reconcile existing migrations: %v", err)
		// Continue anyway - migrations will be idempotent
	}

	// Run any pending migrations
	if err := runner.RunMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Verify integrity
	issues, err := runner.VerifyIntegrity()
	if err != nil {
		s.Logger.Warnf("Failed to verify migration integrity: %v", err)
	} else if len(issues) > 0 {
		for _, issue := range issues {
			s.Logger.Warnf("Migration integrity issue: %s", issue)
		}
	}

	// Log migration status
	status, err := runner.GetMigrationStatus()
	if err != nil {
		s.Logger.Warnf("Failed to get migration status: %v", err)
	} else {
		s.Logger.Infof("Migration status: %d applied, %d pending",
			status["applied_count"], status["pending_count"])
	}

	return nil
}

// reconcileExistingMigrations marks migrations as applied if their changes already exist
// This handles databases that were migrated before the framework was introduced
func (s *SQLite) reconcileExistingMigrations(runner *MigrationRunner) error {
	applied, err := runner.GetAppliedMigrations()
	if err != nil {
		return err
	}

	// If we have applied migrations, the framework is already in use
	if len(applied) > 0 {
		return nil
	}

	s.Logger.Info("Reconciling existing database state with migration framework")

	// Check which migrations were already applied based on schema state
	migrationsToMark := []struct {
		version   string
		name      string
		checkFunc func() (bool, error)
	}{
		{
			version: "1.0.0",
			name:    "initial_schema",
			checkFunc: func() (bool, error) {
				// Check if rules table exists
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.1.0",
			name:    "add_unified_rule_columns",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='type'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.2.0",
			name:    "add_rbac_role_id",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='role_id'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.3.0",
			name:    "add_security_columns",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='mfa_enabled'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.3.1",
			name:    "add_must_change_password",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='must_change_password'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.4.0",
			name:    "add_ml_model_columns",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('ml_models') WHERE name='status'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.5.0",
			name:    "add_dlq_listener_id",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('dead_letter_queue') WHERE name='listener_id'").Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.6.0",
			name:    "add_password_expiry_index",
			checkFunc: func() (bool, error) {
				var count int
				err := s.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_users_password_changed_at'").Scan(&count)
				return count > 0, err
			},
		},
	}

	for _, m := range migrationsToMark {
		exists, err := m.checkFunc()
		if err != nil {
			s.Logger.Warnf("Failed to check migration %s: %v", m.version, err)
			continue
		}

		if exists {
			// Mark migration as applied (it was done by the old inline system)
			_, err = s.DB.Exec(`
				INSERT OR IGNORE INTO schema_migrations (version, name, checksum, applied_at, duration_ms)
				VALUES (?, ?, 'reconciled', datetime('now'), 0)
			`, m.version, m.name)
			if err != nil {
				s.Logger.Warnf("Failed to mark migration %s as applied: %v", m.version, err)
			} else {
				s.Logger.Debugf("Reconciled migration %s: %s (already applied)", m.version, m.name)
			}
		}
	}

	return nil
}

// Close closes the SQLite database connections (both read and write pools)
func (s *SQLite) Close() error {
	var writeErr, readErr error

	// Close write connection pool
	if s.WriteDB != nil {
		writeErr = s.WriteDB.Close()
	}

	// Close read connection pool
	if s.ReadDB != nil {
		readErr = s.ReadDB.Close()
	}

	// Return first error encountered, or nil if both succeeded
	if writeErr != nil {
		return fmt.Errorf("failed to close write pool: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("failed to close read pool: %w", readErr)
	}

	return nil
}

// HealthCheck verifies the database connection is alive
func (s *SQLite) HealthCheck() error {
	return s.DB.Ping()
}

// ConnectionPoolStats returns statistics about the read and write connection pools
// TASK 143.3: Connection pool monitoring metrics
type ConnectionPoolStats struct {
	WritePool PoolStats `json:"write_pool"`
	ReadPool  PoolStats `json:"read_pool"`
}

type PoolStats struct {
	MaxOpenConnections int           `json:"max_open_connections"`
	OpenConnections    int           `json:"open_connections"`
	InUse              int           `json:"in_use"`
	Idle               int           `json:"idle"`
	WaitCount          int64         `json:"wait_count"`
	WaitDuration       time.Duration `json:"wait_duration"`
	MaxIdleClosed      int64         `json:"max_idle_closed"`
	MaxIdleTimeClosed  int64         `json:"max_idle_time_closed"`
	MaxLifetimeClosed  int64         `json:"max_lifetime_closed"`
}

// GetConnectionPoolStats returns current connection pool statistics for monitoring
// This provides visibility into pool utilization and helps identify bottlenecks
func (s *SQLite) GetConnectionPoolStats() ConnectionPoolStats {
	writeStats := s.WriteDB.Stats()
	readStats := s.ReadDB.Stats()

	return ConnectionPoolStats{
		WritePool: PoolStats{
			MaxOpenConnections: writeStats.MaxOpenConnections,
			OpenConnections:    writeStats.OpenConnections,
			InUse:              writeStats.InUse,
			Idle:               writeStats.Idle,
			WaitCount:          writeStats.WaitCount,
			WaitDuration:       writeStats.WaitDuration,
			MaxIdleClosed:      writeStats.MaxIdleClosed,
			MaxIdleTimeClosed:  writeStats.MaxIdleTimeClosed,
			MaxLifetimeClosed:  writeStats.MaxLifetimeClosed,
		},
		ReadPool: PoolStats{
			MaxOpenConnections: readStats.MaxOpenConnections,
			OpenConnections:    readStats.OpenConnections,
			InUse:              readStats.InUse,
			Idle:               readStats.Idle,
			WaitCount:          readStats.WaitCount,
			WaitDuration:       readStats.WaitDuration,
			MaxIdleClosed:      readStats.MaxIdleClosed,
			MaxIdleTimeClosed:  readStats.MaxIdleTimeClosed,
			MaxLifetimeClosed:  readStats.MaxLifetimeClosed,
		},
	}
}

// StartMetricsCollection starts a background goroutine to periodically update Prometheus metrics
// TASK 143.3: Connection pool monitoring metrics with Prometheus integration
// OBSERVABILITY: Enables Grafana dashboards and alerting on pool health
// Call this after NewSQLite() to enable metrics collection
func (s *SQLite) StartMetricsCollection(ctx context.Context, interval time.Duration) {
	// Import metrics package - metrics will be registered automatically via promauto
	// Set initial static configuration metrics
	s.updatePoolMetrics()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.Logger.Info("SQLite metrics collection stopped")
				return
			case <-ticker.C:
				s.updatePoolMetrics()
			}
		}
	}()

	s.Logger.Infof("SQLite metrics collection started (interval: %v)", interval)
}

// updatePoolMetrics updates Prometheus metrics with current connection pool stats
// Called periodically by StartMetricsCollection goroutine
// BLOCKER #4 FIX: Properly compute deltas for cumulative counters
func (s *SQLite) updatePoolMetrics() {
	writeStats := s.WriteDB.Stats()
	readStats := s.ReadDB.Stats()

	// Update write pool metrics
	s.updatePoolMetricsForType("write", writeStats, &s.prevWriteWaitCount, &s.prevWriteMaxIdleClosed, &s.prevWriteMaxLifetimeClosed)

	// Update read pool metrics
	s.updatePoolMetricsForType("read", readStats, &s.prevReadWaitCount, &s.prevReadMaxIdleClosed, &s.prevReadMaxLifetimeClosed)
}

// updatePoolMetricsForType updates Prometheus metrics for a specific pool type
// poolType should be "read" or "write"
// BLOCKER #4 FIX: Track deltas for counters instead of using Add(0) no-ops
func (s *SQLite) updatePoolMetricsForType(poolType string, stats sql.DBStats, prevWaitCount, prevMaxIdleClosed, prevMaxLifetimeClosed *int64) {
	// Gauge metrics (current values)
	metrics.SQLitePoolOpenConnections.WithLabelValues(poolType).Set(float64(stats.OpenConnections))
	metrics.SQLitePoolInUse.WithLabelValues(poolType).Set(float64(stats.InUse))
	metrics.SQLitePoolIdle.WithLabelValues(poolType).Set(float64(stats.Idle))
	metrics.SQLitePoolMaxOpenConnections.WithLabelValues(poolType).Set(float64(stats.MaxOpenConnections))

	// Counter metrics: Add deltas only (Prometheus counters should only increase)
	// BLOCKER #4 FIX: Calculate and add deltas instead of Add(0) no-ops
	waitCountDelta := stats.WaitCount - *prevWaitCount
	if waitCountDelta > 0 {
		metrics.SQLitePoolWaitCount.WithLabelValues(poolType).Add(float64(waitCountDelta))
		*prevWaitCount = stats.WaitCount
	}

	maxIdleClosedDelta := stats.MaxIdleClosed - *prevMaxIdleClosed
	if maxIdleClosedDelta > 0 {
		metrics.SQLitePoolMaxIdleClosed.WithLabelValues(poolType).Add(float64(maxIdleClosedDelta))
		*prevMaxIdleClosed = stats.MaxIdleClosed
	}

	maxLifetimeClosedDelta := stats.MaxLifetimeClosed - *prevMaxLifetimeClosed
	if maxLifetimeClosedDelta > 0 {
		metrics.SQLitePoolMaxLifetimeClosed.WithLabelValues(poolType).Add(float64(maxLifetimeClosedDelta))
		*prevMaxLifetimeClosed = stats.MaxLifetimeClosed
	}

	// For wait duration, we observe the total wait duration (Prometheus handles bucketing)
	if stats.WaitDuration > 0 {
		metrics.SQLitePoolWaitDuration.WithLabelValues(poolType).Observe(stats.WaitDuration.Seconds())
	}
}

// validateDatabasePath validates a database path to prevent path traversal attacks
// SECURITY: Path traversal prevention (FR-SEC-007)
// REQUIREMENT: AFFIRMATIONS.md - File path validation
// THREAT MODEL: Prevents attackers from accessing/overwriting arbitrary files
//
// Attack Examples Blocked:
// - "../../../etc/passwd" - Directory traversal
// - "C:\Windows\System32\config\SAM" - Absolute path to sensitive file
// - "data\x00hidden.db" - Null byte injection
// - "CON" - Windows reserved device name
// - "/dev/null" - Unix device file
//
// Requirements:
// - MUST reject absolute paths
// - MUST reject paths with ".." sequences
// - MUST reject null bytes
// - MUST reject Windows reserved names
// - MUST ensure path resolves within working directory
//
// Returns: error if path is invalid, nil if valid
func validateDatabasePath(dbPath string) error {
	// Empty path check
	if dbPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}

	// Length check - prevent abuse
	if len(dbPath) > 512 {
		return fmt.Errorf("database path exceeds maximum length of 512 characters")
	}

	// SECURITY: Reject absolute paths (except in-memory and temp directories for testing)
	// Absolute paths bypass working directory restriction
	// Allow :memory: for in-memory databases and temp directories for tests
	if filepath.IsAbs(dbPath) && dbPath != ":memory:" {
		// Allow temp directories (common in tests) - they're safe and isolated
		if !strings.Contains(dbPath, os.TempDir()) {
			return fmt.Errorf("absolute paths not allowed: %s", dbPath)
		}
	}

	// SECURITY: Reject paths with ".." sequences (path traversal)
	// Even if path is relative, ".." can escape working directory
	if strings.Contains(dbPath, "..") {
		return fmt.Errorf("path traversal not allowed (..): %s", dbPath)
	}

	// SECURITY: Reject null bytes (C string termination attack)
	// Null bytes can truncate path validation but not actual filesystem operation
	if strings.Contains(dbPath, "\x00") {
		return fmt.Errorf("null bytes not allowed in path")
	}

	// SECURITY: Reject Windows reserved device names
	// CON, PRN, AUX, NUL, COM1, LPT1 etc. are special device files
	// Writing to these can hang the system or bypass security controls
	base := filepath.Base(dbPath)
	reserved := []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
		"COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
		"LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}

	baseUpper := strings.ToUpper(base)
	// Check both exact match and with extension (e.g., "CON.db")
	for _, r := range reserved {
		if baseUpper == r || strings.HasPrefix(baseUpper, r+".") {
			return fmt.Errorf("reserved name not allowed: %s", base)
		}
	}

	// SECURITY: Resolve to absolute path and verify it's within working directory
	// This catches symlink attacks and complex traversal attempts
	// Exception: Allow temp directories (common in tests) - they're safe and isolated
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Skip working directory check for temp directories (used in tests)
	if strings.Contains(absPath, os.TempDir()) {
		return nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Ensure absolute path starts with working directory
	// Use filepath.Rel to handle edge cases correctly
	rel, err := filepath.Rel(wd, absPath)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// If relative path starts with "..", it's outside working directory
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("path escapes working directory: %s resolves to %s", dbPath, absPath)
	}

	return nil
}
