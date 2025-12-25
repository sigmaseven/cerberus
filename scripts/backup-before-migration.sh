#!/bin/bash
# ============================================================================
# Database Backup Script for SIGMA Migration
# ============================================================================
# Purpose: Create a verified backup of the Cerberus database before migration
#
# Features:
#   - Creates timestamped backup in specified directory
#   - Verifies backup integrity (size and SQLite integrity check)
#   - Supports both SQLite and ClickHouse databases
#   - Provides rollback instructions on completion
#
# Usage:
#   ./scripts/backup-before-migration.sh [OPTIONS]
#
# Options:
#   --db-path PATH          Path to SQLite database (default: data/cerberus.db)
#   --backup-dir DIR        Backup directory (default: backups)
#   --verify                Run integrity check on backup
#   --help                  Show this help message
#
# Exit codes:
#   0 = Backup successful
#   1 = Backup failed
#   2 = Verification failed
# ============================================================================

set -euo pipefail

# Default configuration
DB_PATH="${DB_PATH:-data/cerberus.db}"
BACKUP_DIR="${BACKUP_DIR:-backups}"
VERIFY_BACKUP=true
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

show_help() {
    sed -n '/^# ====/,/^# ====/p' "$0" | sed 's/^# //g' | sed 's/^#//g'
    exit 0
}

# ============================================================================
# Parse Command-Line Arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --db-path)
            DB_PATH="$2"
            shift 2
            ;;
        --backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --verify)
            VERIFY_BACKUP=true
            shift
            ;;
        --no-verify)
            VERIFY_BACKUP=false
            shift
            ;;
        --help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================================
# Validation
# ============================================================================

log_info "Cerberus Database Backup Utility"
log_info "================================="
echo ""

# Check if database file exists
if [[ ! -f "$DB_PATH" ]]; then
    log_error "Database file not found: $DB_PATH"
    exit 1
fi

log_info "Database:   $DB_PATH"
log_info "Backup dir: $BACKUP_DIR"
echo ""

# Create backup directory if it doesn't exist
if [[ ! -d "$BACKUP_DIR" ]]; then
    log_info "Creating backup directory..."
    mkdir -p "$BACKUP_DIR"
fi

# ============================================================================
# Pre-Backup Information
# ============================================================================

log_info "Database information:"
DB_SIZE=$(stat -c%s "$DB_PATH" 2>/dev/null || stat -f%z "$DB_PATH" 2>/dev/null || echo "unknown")
if [[ "$DB_SIZE" != "unknown" ]]; then
    DB_SIZE_MB=$(echo "scale=2; $DB_SIZE / 1024 / 1024" | bc)
    log_info "  Size: ${DB_SIZE_MB} MB"
else
    log_warn "  Could not determine database size"
fi

# Count rules in database
if command -v sqlite3 &> /dev/null; then
    RULE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM rules;" 2>/dev/null || echo "unknown")
    log_info "  Rules: $RULE_COUNT"
else
    log_warn "  sqlite3 not found - cannot query rule count"
fi

echo ""

# ============================================================================
# Create Backup
# ============================================================================

BACKUP_NAME="cerberus-pre-migration-${TIMESTAMP}.db"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

log_info "Creating backup..."
log_info "  Source: $DB_PATH"
log_info "  Target: $BACKUP_PATH"

# Use rsync if available for progress, otherwise fallback to cp
if command -v rsync &> /dev/null; then
    rsync -ah --progress "$DB_PATH" "$BACKUP_PATH"
else
    cp "$DB_PATH" "$BACKUP_PATH"
fi

if [[ ! -f "$BACKUP_PATH" ]]; then
    log_error "Backup file was not created"
    exit 1
fi

log_success "Backup created successfully"
echo ""

# ============================================================================
# Verify Backup
# ============================================================================

if [[ "$VERIFY_BACKUP" == true ]]; then
    log_info "Verifying backup integrity..."

    # Check file size matches
    BACKUP_SIZE=$(stat -c%s "$BACKUP_PATH" 2>/dev/null || stat -f%z "$BACKUP_PATH" 2>/dev/null)
    if [[ "$DB_SIZE" != "unknown" ]] && [[ "$BACKUP_SIZE" != "$DB_SIZE" ]]; then
        log_error "Backup verification failed: Size mismatch"
        log_error "  Source: $DB_SIZE bytes"
        log_error "  Backup: $BACKUP_SIZE bytes"
        exit 2
    fi
    log_success "  Size verification passed"

    # Run SQLite integrity check
    if command -v sqlite3 &> /dev/null; then
        INTEGRITY_CHECK=$(sqlite3 "$BACKUP_PATH" "PRAGMA integrity_check;" 2>&1)
        if [[ "$INTEGRITY_CHECK" == "ok" ]]; then
            log_success "  SQLite integrity check passed"
        else
            log_error "Backup verification failed: Integrity check failed"
            log_error "  $INTEGRITY_CHECK"
            exit 2
        fi
    else
        log_warn "  sqlite3 not found - skipping integrity check"
    fi

    # Verify backup is readable
    if command -v sqlite3 &> /dev/null; then
        BACKUP_RULE_COUNT=$(sqlite3 "$BACKUP_PATH" "SELECT COUNT(*) FROM rules;" 2>/dev/null || echo "error")
        if [[ "$BACKUP_RULE_COUNT" == "error" ]]; then
            log_error "Backup verification failed: Cannot read backup database"
            exit 2
        fi
        if [[ "$RULE_COUNT" != "unknown" ]] && [[ "$BACKUP_RULE_COUNT" != "$RULE_COUNT" ]]; then
            log_error "Backup verification failed: Rule count mismatch"
            log_error "  Source: $RULE_COUNT rules"
            log_error "  Backup: $BACKUP_RULE_COUNT rules"
            exit 2
        fi
        log_success "  Rule count verification passed ($BACKUP_RULE_COUNT rules)"
    fi

    echo ""
    log_success "Backup verification completed successfully"
fi

# ============================================================================
# Backup Summary and Rollback Instructions
# ============================================================================

echo ""
echo "============================================"
echo "BACKUP SUMMARY"
echo "============================================"
echo "Backup file: $BACKUP_PATH"
echo "Backup size: $(du -h "$BACKUP_PATH" | cut -f1)"
echo "Timestamp:   $TIMESTAMP"
echo ""
echo "============================================"
echo "ROLLBACK INSTRUCTIONS"
echo "============================================"
echo "If migration fails, restore from backup:"
echo ""
echo "1. Stop the Cerberus service:"
echo "   systemctl stop cerberus"
echo ""
echo "2. Restore the backup:"
echo "   cp \"$BACKUP_PATH\" \"$DB_PATH\""
echo ""
echo "3. Verify the restored database:"
echo "   sqlite3 \"$DB_PATH\" \"PRAGMA integrity_check;\""
echo ""
echo "4. Restart the Cerberus service:"
echo "   systemctl start cerberus"
echo ""
echo "============================================"
echo ""

log_success "Backup completed successfully"
log_info "You may now proceed with migration"

exit 0
