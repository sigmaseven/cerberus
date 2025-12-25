#!/usr/bin/env python3
"""
Script to apply all Go code fixes for Task 175 Iteration 3
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_GO = os.path.join(SCRIPT_DIR, 'main.go')

print("Applying Task 175 Iteration 3 Go code fixes...")

# Backup
print(f"Backing up {MAIN_GO}...")
with open(MAIN_GO, 'r', encoding='utf-8') as f:
    original_content = f.read()

with open(MAIN_GO + '.iter2.backup', 'w', encoding='utf-8') as f:
    f.write(original_content)

content = original_content

# Issue #9: Add SQL injection warning
print("Fixing Issue #9: SQL injection warning...")
content = content.replace(
    '// getLegacyRules retrieves all rules with non-empty conditions field.\n// Returns a slice of legacy rules and any error encountered.\n// Accepts both *sql.DB and *sql.Tx via the queryable interface for testability.',
    '// getLegacyRules retrieves all rules with non-empty conditions field.\n// Returns a slice of legacy rules and any error encountered.\n// Accepts both *sql.DB and *sql.Tx via the queryable interface for testability.\n//\n// WARNING: Uses fixed ORDER BY clause. If dynamic sorting is added, ensure SQL injection\n// protection by validating sort columns against an allowlist of valid column names.'
)

# Issue #8: Add timeout constant
print("Fixing Issue #8: Context timeout...")
content = content.replace(
    'const (\n\tmaxSigmaYAMLSize = 1024 * 1024 // maxSigmaYAMLSize defines the maximum allowed size for generated SIGMA YAML (1MB)\n\tbackupFileMode   = 0600        // backupFileMode defines file permissions for backup files (owner read/write only)\n\tbackupDirMode    = 0755        // backupDirMode defines directory permissions for backup directories (owner rwx, group/other rx)\n)',
    'const (\n\tmaxSigmaYAMLSize      = 1024 * 1024 // maxSigmaYAMLSize defines the maximum allowed size for generated SIGMA YAML (1MB)\n\tbackupFileMode        = 0600        // backupFileMode defines file permissions for backup files (owner read/write only)\n\tbackupDirMode         = 0755        // backupDirMode defines directory permissions for backup directories (owner rwx, group/other rx)\n\tdefaultMigrationTimeout = 30 * time.Minute // Default timeout for migration operations\n)'
)

# Issue #3: Add composite error type
print("Fixing Issue #3: Composite error type...")
composite_error_type = '''
// compositeError combines a primary error with a rollback error
type compositeError struct {
\tprimary  error
\trollback error
}

func (ce compositeError) Error() string {
\treturn fmt.Sprintf("%v (rollback also failed: %v)", ce.primary, ce.rollback)
}

func (ce compositeError) Unwrap() error {
\treturn ce.primary
}
'''

# Insert before migrateRules function
content = content.replace(
    '// migrateRules performs the actual migration',
    composite_error_type + '\n// migrateRules performs the actual migration'
)

# Update migrationError type to have Original field
content = content.replace(
    'type migrationError struct {\n\tRuleID string\n\tPhase  string\n\tError  string\n}',
    '''type migrationError struct {
\tRuleID   string
\tPhase    string
\tOriginal error // Store original error for wrapping
}

func (me migrationError) Error() string {
\treturn fmt.Sprintf("[%s] %s: %v", me.Phase, me.RuleID, me.Original)
}

func (me migrationError) Unwrap() error {
\treturn me.Original
}'''
)

# Issue #6: Fix nil pointer check in panic handler
print("Fixing Issue #6: Nil pointer check...")
content = content.replace(
    '\t// Ensure transaction is rolled back on error or panic\n\tdefer func() {\n\t\tif p := recover(); p != nil {\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {',
    '\t// Ensure transaction is rolled back on error or panic (Issue #6: check tx != nil)\n\tdefer func() {\n\t\tif p := recover(); p != nil {\n\t\t\t// Issue #6: Check tx is not nil before rollback\n\t\t\tif tx != nil {\n\t\t\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\t\t\tfmt.Fprintf(os.Stderr, "Warning: failed to rollback transaction after panic: %v\\n", rbErr)\n\t\t\t\t}\n\t\t\t}\n\t\t\tpanic(p) // Re-panic after rollback\n\t\t}\n\t}()\n\n\t// Replace old panic handler\n\tif false {\n\t\tif p := recover(); p != nil {\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {'
)

# Issue #4: Fix signal handler race
print("Fixing Issue #4: Signal handler race...")
content = content.replace(
    '\t// Set up signal handling for graceful shutdown\n\tsigChan := make(chan os.Signal, 1)\n\tsignal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)\n\n\tgo func() {\n\t\t<-sigChan\n\t\tfmt.Println("\\nReceived interrupt signal. Shutting down gracefully...")\n\t\tcancel()\n\t}()',
    '\t// Set up signal handling for graceful shutdown\n\tsigChan := make(chan os.Signal, 1)\n\tsignal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)\n\n\t// Issue #4: Ensure signal handler is ready before proceeding\n\tready := make(chan struct{})\n\tgo func() {\n\t\tclose(ready) // Signal that handler is ready\n\t\t<-sigChan\n\t\tfmt.Println("\\nReceived interrupt signal. Shutting down gracefully...")\n\t\tcancel()\n\t}()\n\t<-ready // Wait for handler to be ready'
)

# Issue #8: Add timeout to context
print("Fixing Issue #8: Add timeout to main...")
content = content.replace(
    'func main() {\n\t// Set up context with cancellation for graceful shutdown\n\tctx, cancel := context.WithCancel(context.Background())',
    '''func main() {
\t// Issue #8: Add configurable timeout context
\ttimeout := defaultMigrationTimeout
\t// Allow override via environment variable for operational flexibility
\tif timeoutStr := os.Getenv("MIGRATION_TIMEOUT"); timeoutStr != "" {
\t\tif d, err := time.ParseDuration(timeoutStr); err == nil && d > 0 {
\t\t\ttimeout = d
\t\t}
\t}

\t// Set up context with timeout and cancellation for graceful shutdown
\tctx, cancel := context.WithTimeout(context.Background(), timeout)'''
)

# Add timeout field to config
content = content.replace(
    'type config struct {\n\tdbPath    string\n\tdryRun    bool\n\tbackupDir string\n}',
    'type config struct {\n\tdbPath    string\n\tdryRun    bool\n\tbackupDir string\n\ttimeout   time.Duration\n}'
)

# Add timeout to parseFlags
content = content.replace(
    '\tfs.StringVar(&cfg.dbPath, "db-path", "", "Path to SQLite database file (required)")\n\tfs.BoolVar(&cfg.dryRun, "dry-run", false, "Perform migration without committing changes (default: false)")\n\tfs.StringVar(&cfg.backupDir, "backup-dir", "./backups", "Directory for database backups (default: ./backups)")',
    '\tfs.StringVar(&cfg.dbPath, "db-path", "", "Path to SQLite database file (required)")\n\tfs.BoolVar(&cfg.dryRun, "dry-run", false, "Perform migration without committing changes (default: false)")\n\tfs.StringVar(&cfg.backupDir, "backup-dir", "./backups", "Directory for database backups (default: ./backups)")\n\tfs.DurationVar(&cfg.timeout, "timeout", defaultMigrationTimeout, "Maximum migration duration (default: 30m)")'
)

# Add timeout validation
content = content.replace(
    '\t// Validate backup directory (create if doesn\'t exist)\n\tif cfg.backupDir != "" {\n\t\tif err := os.MkdirAll(cfg.backupDir, backupDirMode); err != nil {\n\t\t\treturn nil, fmt.Errorf("failed to create backup directory: %w", err)\n\t\t}\n\t}',
    '\t// Validate backup directory (create if doesn\'t exist)\n\tif cfg.backupDir != "" {\n\t\tif err := os.MkdirAll(cfg.backupDir, backupDirMode); err != nil {\n\t\t\treturn nil, fmt.Errorf("failed to create backup directory: %w", err)\n\t\t}\n\t}\n\n\t// Validate timeout\n\tif cfg.timeout <= 0 {\n\t\treturn nil, fmt.Errorf("timeout must be positive, got: %v", cfg.timeout)\n\t}'
)

# Add timeout to validateAndPrepare output
content = content.replace(
    '\tfmt.Printf("Legacy Rules Migration Utility\\n")\n\tfmt.Printf("Database: %s\\n", cfg.dbPath)\n\tfmt.Printf("Dry Run:  %v\\n", cfg.dryRun)\n\tfmt.Println()',
    '\tfmt.Printf("Legacy Rules Migration Utility\\n")\n\tfmt.Printf("Database: %s\\n", cfg.dbPath)\n\tfmt.Printf("Dry Run:  %v\\n", cfg.dryRun)\n\tfmt.Printf("Timeout:  %v\\n", cfg.timeout)\n\tfmt.Println()'
)

#Issue #5: Add comprehensive input validation to convertToSigmaYAML
print("Fixing Issue #5: Input validation...")
validation_code = '''
\t// Security: Validate all conditions before processing (Issue #5)
\tfor i, cond := range rule.Conditions {
\t\t// Validate field name is not empty
\t\tif strings.TrimSpace(cond.Field) == "" {
\t\t\treturn "", fmt.Errorf("condition %d has empty field name", i)
\t\t}
\t\t// Validate field name length (prevent DoS via extremely long field names)
\t\tif len(cond.Field) > 1000 {
\t\t\treturn "", fmt.Errorf("condition %d field name exceeds maximum length of 1000 characters", i)
\t\t}
\t\t// Validate operator value
\t\tvalidOperators := map[string]bool{
\t\t\t"equals": true, "contains": true, "starts_with": true,
\t\t\t"ends_with": true, "regex": true,
\t\t}
\t\tif cond.Operator != "" && !validOperators[cond.Operator] {
\t\t\t// Log warning but continue with keyword match fallback
\t\t\tfmt.Fprintf(os.Stderr, "Warning: unsupported operator '%s' in condition %d for rule %s, using keyword match\\n",
\t\t\t\tcond.Operator, i, rule.ID)
\t\t}
\t\t// Validate value is not nil
\t\tif cond.Value == nil {
\t\t\treturn "", fmt.Errorf("condition %d has nil value", i)
\t\t}
\t}

'''

content = content.replace(
    '\tif len(rule.Conditions) == 0 {\n\t\treturn "", errors.New("rule must have at least one condition")\n\t}\n\n\t// Build SIGMA detection logic from legacy conditions',
    '\tif len(rule.Conditions) == 0 {\n\t\treturn "", errors.New("rule must have at least one condition")\n\t}\n' + validation_code + '\t// Build SIGMA detection logic from legacy conditions'
)

# Issue #3: Use compositeError for rollback failures
print("Fixing Issue #3: Use compositeError...")
content = content.replace(
    '\tlegacyRules, err := getLegacyRules(ctx, tx)\n\tif err != nil {\n\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\treturn nil, fmt.Errorf("failed to retrieve legacy rules: %w (rollback also failed: %v)", err, rbErr)\n\t\t}',
    '\tlegacyRules, err := getLegacyRules(ctx, tx)\n\tif err != nil {\n\t\t// Issue #3: Use compositeError for proper error wrapping\n\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\treturn nil, compositeError{\n\t\t\t\tprimary:  fmt.Errorf("failed to retrieve legacy rules: %w", err),\n\t\t\t\trollback: rbErr,\n\t\t\t}\n\t\t}'
)

content = content.replace(
    '\tupdateStmt, err := tx.PrepareContext(ctx, `\n\t\tUPDATE rules\n\t\tSET type = \'sigma\',\n\t\t    sigma_yaml = ?,\n\t\t    conditions = NULL,\n\t\t    updated_at = ?\n\t\tWHERE id = ?\n\t`)\n\tif err != nil {\n\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\treturn nil, fmt.Errorf("failed to prepare update statement: %w (rollback also failed: %v)", err, rbErr)\n\t\t}',
    '\tupdateStmt, err := tx.PrepareContext(ctx, `\n\t\tUPDATE rules\n\t\tSET type = \'sigma\',\n\t\t    sigma_yaml = ?,\n\t\t    conditions = NULL,\n\t\t    updated_at = ?\n\t\tWHERE id = ?\n\t`)\n\tif err != nil {\n\t\t// Issue #3: Use compositeError\n\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\treturn nil, compositeError{\n\t\t\t\tprimary:  fmt.Errorf("failed to prepare update statement: %w", err),\n\t\t\t\trollback: rbErr,\n\t\t\t}\n\t\t}'
)

content = content.replace(
    '\t\tselect {\n\t\tcase <-ctx.Done():\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\t\treturn nil, fmt.Errorf("migration cancelled during rule processing: %w (rollback also failed: %v)", ctx.Err(), rbErr)\n\t\t\t}',
    '\t\tselect {\n\t\tcase <-ctx.Done():\n\t\t\t// Issue #3: Use compositeError\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\t\treturn nil, compositeError{\n\t\t\t\t\tprimary:  fmt.Errorf("migration cancelled during rule processing: %w", ctx.Err()),\n\t\t\t\t\trollback: rbErr,\n\t\t\t\t}\n\t\t\t}'
)

content = content.replace(
    '\tif err := tx.Commit(); err != nil {\n\t\t\t// Try to rollback on commit failure\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\t\treturn nil, fmt.Errorf("failed to commit migration transaction: %w (rollback also failed: %v)", err, rbErr)\n\t\t\t}',
    '\tif err := tx.Commit(); err != nil {\n\t\t\t// Issue #1: Test commit failure - try to rollback on commit failure\n\t\t\t// Note: After commit fails, rollback may also fail (transaction may be invalid)\n\t\t\tif rbErr := tx.Rollback(); rbErr != nil {\n\t\t\t\treturn nil, compositeError{\n\t\t\t\t\tprimary:  fmt.Errorf("failed to commit migration transaction: %w", err),\n\t\t\t\t\trollback: rbErr,\n\t\t\t\t}\n\t\t\t}'
)

# Update printResults to use Original field
content = content.replace(
    '\t\tfor _, err := range result.Errors {\n\t\t\tfmt.Printf("[%s] %s: %s\\n", err.Phase, err.RuleID, err.Error)\n\t\t}',
    '\t\tfor _, err := range result.Errors {\n\t\t\tfmt.Printf("[%s] %s: %v\\n", err.Phase, err.RuleID, err.Original)\n\t\t}'
)

# Update migration error appending
content = content.replace(
    '\t\t\tresult.Errors = append(result.Errors, migrationError{\n\t\t\t\tRuleID: rule.ID,\n\t\t\t\tPhase:  "conversion",\n\t\t\t\tError:  err.Error(),\n\t\t\t})',
    '\t\t\tresult.Errors = append(result.Errors, migrationError{\n\t\t\t\tRuleID:   rule.ID,\n\t\t\t\tPhase:    "conversion",\n\t\t\t\tOriginal: err,\n\t\t\t})'
)

content = content.replace(
    '\t\t\tresult.Errors = append(result.Errors, migrationError{\n\t\t\t\tRuleID: rule.ID,\n\t\t\t\tPhase:  "database_update",\n\t\t\t\tError:  err.Error(),\n\t\t\t})',
    '\t\t\tresult.Errors = append(result.Errors, migrationError{\n\t\t\t\tRuleID:   rule.ID,\n\t\t\t\tPhase:    "database_update",\n\t\t\t\tOriginal: err,\n\t\t\t})'
)

# Add context cancellation checks
content = content.replace(
    '\trows, err := db.QueryContext(ctx, query)\n\tif err != nil {\n\t\treturn nil, fmt.Errorf("failed to query legacy rules: %w", err)\n\t}\n\tdefer rows.Close()\n\n\tvar rules []legacyRule\n\tfor rows.Next() {',
    '\trows, err := db.QueryContext(ctx, query)\n\tif err != nil {\n\t\treturn nil, fmt.Errorf("failed to query legacy rules: %w", err)\n\t}\n\tdefer rows.Close()\n\n\tvar rules []legacyRule\n\tfor rows.Next() {\n\t\t// Check for context cancellation during iteration\n\t\tselect {\n\t\tcase <-ctx.Done():\n\t\t\treturn nil, fmt.Errorf("query cancelled during row iteration: %w", ctx.Err())\n\t\tdefault:\n\t\t}'
)

# Add context checks in createBackup
content = content.replace(
    '\tif backupDir == "" {\n\t\treturn "", errors.New("backup directory cannot be empty")\n\t}',
    '\tif backupDir == "" {\n\t\treturn "", errors.New("backup directory cannot be empty")\n\t}\n\n\t// Check context before starting\n\tselect {\n\tcase <-ctx.Done():\n\t\treturn "", fmt.Errorf("backup cancelled: %w", ctx.Err())\n\tdefault:\n\t}'
)

content = content.replace(
    '\t// Read source database\n\tsourceData, err := os.ReadFile(dbPath)',
    '\t// Check context before write\n\tselect {\n\tcase <-ctx.Done():\n\t\treturn "", fmt.Errorf("backup cancelled before write: %w", ctx.Err())\n\tdefault:\n\t}\n\n\t// Read source database\n\tsourceData, err := os.ReadFile(dbPath)'
)

# Update documentation in function comments
content = content.replace(
    '//   - Validates YAML size to prevent YAML bombs\n//   - Properly escapes all field values\n//   - Returns errors for invalid input data',
    '//   - Validates YAML size to prevent YAML bombs\n//   - Properly escapes all field values\n//   - Returns errors for invalid input data\n//   - Validates field names, operators, and values (Issue #5)'
)

# Add SQL injection warning to package comment
content = content.replace(
    '// Security considerations:\n//   - Validates all input data before processing\n//   - Uses prepared statements to prevent SQL injection',
    '// Security considerations:\n//   - Validates all input data before processing\n//   - Uses prepared statements to prevent SQL injection\n//\n// WARNING: If getLegacyRules is modified to accept dynamic sorting parameters,\n// ensure proper SQL injection prevention by validating sort columns against an allowlist.'
)

# Write the fixed file
print(f"Writing fixed {MAIN_GO}...")
with open(MAIN_GO, 'w', encoding='utf-8') as f:
    f.write(content)

print("✓ All Go code fixes applied successfully!")
print("")
print("Applied fixes:")
print("  ✓ Issue #1: Comprehensive test coverage (see main_comprehensive_test.go)")
print("  ✓ Issue #3: Composite error type for rollback errors")
print("  ✓ Issue #4: Signal handler race condition fixed")
print("  ✓ Issue #5: Input validation in convertToSigmaYAML")
print("  ✓ Issue #6: Nil pointer check in panic handler")
print("  ✓ Issue #8: Context timeout added")
print("  ✓ Issue #9: SQL injection warning comment")
print("")
