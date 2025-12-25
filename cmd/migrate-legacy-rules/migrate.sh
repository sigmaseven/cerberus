#!/usr/bin/env bash

# Legacy Rules Migration Script
# This script automates the migration of legacy JSON condition-based rules to SIGMA format.
#
# Usage:
#   ./migrate.sh <database-path> [backup-dir]
#
# Example:
#   ./migrate.sh /path/to/cerberus.db /path/to/backups
#
# Exit codes:
#   0 - Success
#   1 - Invalid arguments or precondition failure
#   2 - Migration failure
#   3 - Verification failure

set -euo pipefail

# Error handling with trap
trap 'handle_error $? $LINENO' ERR

handle_error() {
    local exit_code=$1
    local line_number=$2
    echo "ERROR: Script failed at line ${line_number} with exit code ${exit_code}" >&2
    cleanup_on_error
    exit "${exit_code}"
}

cleanup_on_error() {
    # Cleanup temporary files if migration fails
    if [ -n "${TEMP_LOG_FILE:-}" ] && [ -f "${TEMP_LOG_FILE}" ]; then
        echo "Migration log saved to: ${TEMP_LOG_FILE}" >&2
    fi
}

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATION_TOOL="${SCRIPT_DIR}/migrate-legacy-rules"
TEMP_LOG_FILE=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Validate arguments
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    log_error "Invalid arguments"
    echo "Usage: $0 <database-path> [backup-dir]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  database-path  Path to the SQLite database file (required)" >&2
    echo "  backup-dir     Directory for database backups (optional, default: ./backups)" >&2
    exit 1
fi

DB_PATH="$1"
BACKUP_DIR="${2:-./backups}"

# Validate database file exists
if [ ! -f "${DB_PATH}" ]; then
    log_error "Database file does not exist: ${DB_PATH}"
    exit 1
fi

# Validate database is readable
if [ ! -r "${DB_PATH}" ]; then
    log_error "Database file is not readable: ${DB_PATH}"
    exit 1
fi

# Validate database is writable
if [ ! -w "${DB_PATH}" ]; then
    log_error "Database file is not writable: ${DB_PATH}"
    exit 1
fi

# Check if migration tool exists and is executable
if [ ! -f "${MIGRATION_TOOL}" ]; then
    log_error "Migration tool not found: ${MIGRATION_TOOL}"
    log_info "Build the migration tool with: go build -o ${MIGRATION_TOOL}"
    exit 1
fi

if [ ! -x "${MIGRATION_TOOL}" ]; then
    log_error "Migration tool is not executable: ${MIGRATION_TOOL}"
    log_info "Make it executable with: chmod +x ${MIGRATION_TOOL}"
    exit 1
fi

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Create temporary log file
TEMP_LOG_FILE=$(mktemp "${BACKUP_DIR}/migration-log-XXXXXX.txt")

log_info "Starting legacy rules migration"
log_info "Database: ${DB_PATH}"
log_info "Backup directory: ${BACKUP_DIR}"
log_info "Log file: ${TEMP_LOG_FILE}"
echo ""

# Step 1: Perform dry-run to validate migration
log_info "Step 1: Performing dry-run validation..."
if ! "${MIGRATION_TOOL}" --db-path="${DB_PATH}" --backup-dir="${BACKUP_DIR}" --dry-run 2>&1 | tee -a "${TEMP_LOG_FILE}"; then
    log_error "Dry-run validation failed"
    log_info "Review the log file for details: ${TEMP_LOG_FILE}"
    exit 2
fi
echo ""

# Step 2: Get user confirmation (skip if non-interactive)
if [ -t 0 ]; then
    read -p "Dry-run successful. Proceed with actual migration? (yes/no): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        log_warn "Migration cancelled by user"
        exit 0
    fi
else
    log_info "Non-interactive mode: proceeding with migration"
fi

# Step 3: Compute database checksum before migration
log_info "Step 2: Computing database checksum..."
DB_CHECKSUM_BEFORE=$(sha256sum "${DB_PATH}" | awk '{print $1}')
DB_SIZE_BEFORE=$(stat -c%s "${DB_PATH}" 2>/dev/null || stat -f%z "${DB_PATH}" 2>/dev/null || echo "unknown")
log_info "Database checksum (before): ${DB_CHECKSUM_BEFORE}"
log_info "Database size (before): ${DB_SIZE_BEFORE} bytes"
echo ""

# Step 4: Perform actual migration
log_info "Step 3: Performing migration..."
MIGRATION_START=$(date +%s)

if ! "${MIGRATION_TOOL}" --db-path="${DB_PATH}" --backup-dir="${BACKUP_DIR}" 2>&1 | tee -a "${TEMP_LOG_FILE}"; then
    log_error "Migration failed"
    log_info "Review the log file for details: ${TEMP_LOG_FILE}"
    log_warn "Database may be in an inconsistent state"
    log_warn "Restore from backup if needed: ls -lt ${BACKUP_DIR}/"
    exit 2
fi

MIGRATION_END=$(date +%s)
MIGRATION_DURATION=$((MIGRATION_END - MIGRATION_START))
echo ""

# Step 5: Verify database integrity after migration
log_info "Step 4: Verifying database integrity..."
DB_CHECKSUM_AFTER=$(sha256sum "${DB_PATH}" | awk '{print $1}')
DB_SIZE_AFTER=$(stat -c%s "${DB_PATH}" 2>/dev/null || stat -f%z "${DB_PATH}" 2>/dev/null || echo "unknown")

if [ "${DB_CHECKSUM_BEFORE}" = "${DB_CHECKSUM_AFTER}" ]; then
    log_warn "Database checksum unchanged - no rules were migrated"
else
    log_info "Database checksum (after): ${DB_CHECKSUM_AFTER}"
    log_info "Database size (after): ${DB_SIZE_AFTER} bytes"
fi
echo ""

# Step 6: Final atomic write to ensure durability
log_info "Step 5: Ensuring database durability..."
sync
if command -v sqlite3 &> /dev/null; then
    if ! sqlite3 "${DB_PATH}" "PRAGMA integrity_check;" | grep -q "ok"; then
        log_error "Database integrity check failed after migration"
        log_warn "Restore from backup immediately: ls -lt ${BACKUP_DIR}/"
        exit 3
    fi
    log_info "Database integrity check passed"
else
    log_warn "sqlite3 not found - skipping integrity check"
fi
echo ""

# Success
log_info "Migration completed successfully in ${MIGRATION_DURATION} seconds"
log_info "Log file: ${TEMP_LOG_FILE}"
log_info "Backup files: ls -lt ${BACKUP_DIR}/"
echo ""

# Checksum verification for backup
LATEST_BACKUP=$(find "${BACKUP_DIR}" -name "cerberus-pre-migration-*.db" -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -n1 | cut -d' ' -f2-)
if [ -n "${LATEST_BACKUP}" ]; then
    BACKUP_CHECKSUM=$(sha256sum "${LATEST_BACKUP}" | awk '{print $1}')
    log_info "Latest backup: ${LATEST_BACKUP}"
    log_info "Backup checksum: ${BACKUP_CHECKSUM}"
fi

exit 0
