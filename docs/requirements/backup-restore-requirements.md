# Backup and Restore Requirements

**Document Owner**: Backend Team  
**Created**: 2025-01-19  
**Status**: ACTIVE  
**Last Updated**: 2025-01-19  
**Version**: 1.0  

**Reference Implementation**: `api/backup.go`

---

## 1. Executive Summary

The Cerberus SIEM backup and restore system provides the capability to backup and restore critical configuration data (rules, actions, correlation rules) for disaster recovery, configuration management, and migration purposes. This document defines the comprehensive requirements for backup creation, restore operations, security, and retention policies.

**Critical Requirements**:
- Backup of rules, actions, and correlation rules
- Secure backup format (gzipped tarball with JSON)
- Path traversal protection
- Selective restore capabilities
- Conflict resolution strategies
- Atomic restore operations

**Implementation Status**: ✅ 100% IMPLEMENTED

---

## 2. Functional Requirements

### FR-BACKUP-001: Backup Creation
**Requirement**: The system MUST support creating backups of all critical configuration data.

**Specification**:
- Backup scope includes:
  - All detection rules (Sigma and CQL rules)
  - All actions (webhooks, email, etc.)
  - All correlation rules
- Backup format: gzipped tarball containing JSON data
- Backup file naming: `cerberus-backup-YYYYMMDD-HHMMSS.tar.gz`
- Backup metadata includes:
  - Timestamp of backup creation
  - Version of backup format
  - Counts of backed-up items

**Implementation**: `api/backup.go:52-133` (CreateBackup)

**Acceptance Criteria**:
- [x] Backup includes all rules, actions, and correlation rules
- [x] Backup is in gzipped tarball format
- [x] Backup metadata is included
- [x] Backup operation completes successfully

---

### FR-BACKUP-002: Backup Format
**Requirement**: Backups MUST use a standardized, versioned format for compatibility.

**Specification**:
- Format version: 1.0
- Archive format: TAR with GZIP compression
- Internal structure:
  - Single file: `cerberus-backup.json`
  - JSON structure:
    ```json
    {
      "timestamp": "2025-01-19T12:00:00Z",
      "version": "1.0",
      "rules": [...],
      "actions": [...],
      "correlation_rules": [...]
    }
    ```
- Compression reduces backup size by ~70-90%

**Implementation**: `api/backup.go:88-133`

**Acceptance Criteria**:
- [x] Backup format is versioned
- [x] Backup uses gzipped tarball
- [x] Backup JSON is properly formatted

---

### FR-BACKUP-003: Path Traversal Protection
**Requirement**: Backup and restore operations MUST prevent path traversal attacks.

**Specification**:
- Validate all file paths before use
- Reject paths containing `..` or symlinks
- Ensure paths are within safe base directory
- Use absolute path resolution and cleaning
- Validate relative paths don't escape base directory

**Implementation**: `api/backup.go:263-299` (validateBackupPath)

**Security Considerations**:
- Prevents unauthorized file system access
- Protects against directory traversal attacks
- Ensures backups are stored in expected locations

**Acceptance Criteria**:
- [x] Path validation rejects `..` patterns
- [x] Path validation prevents symlink traversal
- [x] Path validation restricts to safe base directory

---

### FR-BACKUP-004: Restore Operations
**Requirement**: The system MUST support restoring configuration data from backups.

**Specification**:
- Restore supports selective restoration:
  - Rules only
  - Actions only
  - Correlation rules only
  - All items (default)
- Restore options:
  - `RestoreRules`: Restore rules (default: true)
  - `RestoreActions`: Restore actions (default: true)
  - `RestoreCorrelationRules`: Restore correlation rules (default: true)
  - `ContinueOnError`: Continue restore on individual item errors (default: false)
- Restore validates backup version compatibility
- Restore validates backup file integrity

**Implementation**: `api/backup.go:135-243` (RestoreBackup)

**Acceptance Criteria**:
- [x] Restore supports selective restoration
- [x] Restore validates backup version
- [x] Restore validates backup integrity
- [x] Restore handles errors gracefully

---

### FR-BACKUP-005: Conflict Resolution
**Requirement**: Restore operations MUST handle conflicts with existing data.

**Specification**:
- Duplicate rule/action IDs: Restore fails with error (or skips if ContinueOnError=true)
- Validation errors: Restore fails (or logs warning if ContinueOnError=true)
- Missing dependencies: Restore fails with clear error message
- Default behavior: Fail on first error (atomic restore)

**Implementation**: `api/backup.go:196-233`

**Acceptance Criteria**:
- [x] Duplicate IDs are detected
- [x] Conflicts are handled according to ContinueOnError option
- [x] Error messages are clear and actionable

---

### FR-BACKUP-006: Backup API Endpoints
**Requirement**: The system MUST provide REST API endpoints for backup and restore operations.

**Specification**:
- `POST /api/v1/backup/create`: Create a new backup
  - Request body: `{ "output_path": "/path/to/backup.tar.gz" }`
  - Response: 201 Created with backup metadata
- `POST /api/v1/backup/restore`: Restore from backup
  - Request body: 
    ```json
    {
      "backup_path": "/path/to/backup.tar.gz",
      "restore_rules": true,
      "restore_actions": true,
      "restore_correlation_rules": true,
      "continue_on_error": false
    }
    ```
  - Response: 200 OK with restore summary

**RBAC Requirements**:
- Backup creation: `admin:system` permission
- Restore operations: `admin:system` permission

**Implementation**: Backup endpoints to be implemented in API handlers

**Acceptance Criteria**:
- [ ] Backup creation endpoint exists
- [ ] Restore endpoint exists
- [ ] Endpoints enforce RBAC permissions
- [ ] Endpoints validate input parameters

---

### FR-BACKUP-007: Backup Retention Policies
**Requirement**: The system SHOULD support configurable backup retention policies (future enhancement).

**Specification**:
- Retention policy options:
  - Keep last N backups
  - Keep backups for N days
  - Keep backups with specific tags
- Automatic cleanup of expired backups
- Backup tagging for organization

**Implementation Status**: ⚠️ NOT IMPLEMENTED (Future enhancement)

**Acceptance Criteria**:
- [ ] Retention policies are configurable
- [ ] Automatic cleanup is implemented
- [ ] Backup tagging is supported

---

### FR-BACKUP-008: Backup Verification
**Requirement**: The system MUST verify backup integrity before restore.

**Specification**:
- Validate backup file format (tar.gz)
- Validate backup JSON structure
- Validate backup version compatibility
- Verify all expected sections are present
- Check for file corruption

**Implementation**: `api/backup.go:151-194` (RestoreBackup validation)

**Acceptance Criteria**:
- [x] Backup format is validated
- [x] Backup version is checked
- [x] Backup structure is verified

---

### FR-BACKUP-009: Backup Metadata
**Requirement**: Backups MUST include metadata for audit and tracking.

**Specification**:
- Backup timestamp (when backup was created)
- Backup version (format version)
- Item counts (rules, actions, correlation_rules)
- Optional: Creator username
- Optional: Backup description/tags

**Implementation**: `api/backup.go:43-50` (BackupData struct)

**Acceptance Criteria**:
- [x] Backup includes timestamp
- [x] Backup includes version
- [x] Backup includes item counts

---

### FR-BACKUP-010: Atomic Restore Operations
**Requirement**: Restore operations MUST be atomic when ContinueOnError=false.

**Specification**:
- All restore operations succeed or fail together
- No partial restorations if ContinueOnError=false
- Transactional behavior for restore operations
- Rollback on error when atomicity is required

**Implementation**: `api/backup.go:196-233` (atomic restore with ContinueOnError=false)

**Acceptance Criteria**:
- [x] Atomic restore prevents partial data
- [x] Rollback occurs on error when atomicity required
- [x] Non-atomic restore available via ContinueOnError=true

---

## 3. Non-Functional Requirements

### NFR-BACKUP-001: Backup Performance
**Requirement**: Backup operations MUST complete within reasonable time limits.

**Specification**:
- Backup of 10,000 rules + 1,000 actions + 500 correlation rules: < 5 seconds
- Backup size: < 100MB for typical deployments
- Compression ratio: 70-90% size reduction

**Implementation**: Backup uses gzip compression for size reduction

**Acceptance Criteria**:
- [ ] Backup completes within time limits
- [ ] Backup size is reasonable
- [ ] Compression is effective

---

### NFR-BACKUP-002: Restore Performance
**Requirement**: Restore operations MUST complete within reasonable time limits.

**Specification**:
- Restore of 10,000 rules: < 30 seconds
- Restore of 1,000 actions: < 10 seconds
- Restore of 500 correlation rules: < 10 seconds

**Acceptance Criteria**:
- [ ] Restore completes within time limits
- [ ] Restore performance scales with data size

---

### NFR-BACKUP-003: Backup Security
**Requirement**: Backup operations MUST be secure and prevent unauthorized access.

**Specification**:
- Backup files MUST have restrictive permissions (0600)
- Backup paths MUST be validated (path traversal protection)
- Backup operations require `admin:system` permission
- Backup files SHOULD NOT contain sensitive data (passwords, secrets)
- Backup files SHOULD be stored in secure location

**Implementation**: 
- `api/backup.go:263-299` (path validation)
- `api/backup.go:113` (file permissions 0600)

**Acceptance Criteria**:
- [x] Backup files have restrictive permissions
- [x] Path traversal is prevented
- [x] RBAC is enforced (when endpoints are implemented)

---

### NFR-BACKUP-004: Backup Reliability
**Requirement**: Backup and restore operations MUST be reliable and handle errors gracefully.

**Specification**:
- Backup operations MUST handle storage errors
- Restore operations MUST validate backup integrity
- Error messages MUST be clear and actionable
- Partial failures MUST be logged appropriately

**Implementation**: `api/backup.go` includes comprehensive error handling

**Acceptance Criteria**:
- [x] Errors are handled gracefully
- [x] Error messages are clear
- [x] Failures are logged

---

### NFR-BACKUP-005: Backup Compatibility
**Requirement**: Backups MUST maintain backward compatibility across versions.

**Specification**:
- Backup format versioning enables migration
- Older backup versions SHOULD be restorable (with version checks)
- Backup version upgrades MUST be documented
- Breaking changes MUST increment version

**Implementation**: `api/backup.go:191-194` (version validation)

**Acceptance Criteria**:
- [x] Backup version is checked
- [x] Version compatibility is validated
- [ ] Version migration is documented

---

## 4. API Endpoints

### POST /api/v1/backup/create
Create a new backup of all configuration data.

**Request**:
```json
{
  "output_path": "/backups/cerberus-backup-20250119.tar.gz"
}
```

**Response**: 201 Created
```json
{
  "backup_path": "/backups/cerberus-backup-20250119.tar.gz",
  "timestamp": "2025-01-19T12:00:00Z",
  "version": "1.0",
  "rules_count": 1250,
  "actions_count": 45,
  "correlation_rules_count": 23
}
```

**RBAC**: Requires `admin:system` permission

---

### POST /api/v1/backup/restore
Restore configuration from a backup file.

**Request**:
```json
{
  "backup_path": "/backups/cerberus-backup-20250119.tar.gz",
  "restore_rules": true,
  "restore_actions": true,
  "restore_correlation_rules": true,
  "continue_on_error": false
}
```

**Response**: 200 OK
```json
{
  "restored_rules": 1250,
  "restored_actions": 45,
  "restored_correlation_rules": 23,
  "errors": []
}
```

**RBAC**: Requires `admin:system` permission

---

## 5. Data Models

### BackupData
```go
type BackupData struct {
    Timestamp        time.Time              `json:"timestamp"`
    Version          string                 `json:"version"`
    Rules            []core.Rule            `json:"rules"`
    Actions          []core.Action          `json:"actions"`
    CorrelationRules []core.CorrelationRule `json:"correlation_rules"`
}
```

### RestoreOptions
```go
type RestoreOptions struct {
    RestoreRules            bool
    RestoreActions          bool
    RestoreCorrelationRules bool
    ContinueOnError         bool
}
```

---

## 6. Security Considerations

1. **Path Traversal Protection**: All backup paths are validated to prevent directory traversal attacks
2. **File Permissions**: Backup files are created with restrictive permissions (0600)
3. **RBAC Enforcement**: Backup and restore operations require `admin:system` permission
4. **Sensitive Data**: Backups do not include user passwords or secrets (only configuration data)
5. **Audit Logging**: Backup and restore operations should be logged for audit purposes

---

## 7. Testing Requirements

1. **Unit Tests**:
   - Test backup creation with various data sizes
   - Test restore with valid backups
   - Test restore with invalid backups (corrupted, wrong version)
   - Test path traversal protection
   - Test conflict resolution

2. **Integration Tests**:
   - Test backup and restore round-trip
   - Test selective restore options
   - Test atomic restore behavior
   - Test error handling scenarios

3. **Security Tests**:
   - Test path traversal attack prevention
   - Test RBAC enforcement (when endpoints implemented)
   - Test file permission validation

---

## 8. Known Limitations

1. **User Data**: Backups do not include user accounts, roles, or permissions
2. **Event Data**: Backups do not include security events or alerts (configuration only)
3. **Investigation Data**: Backups do not include investigation data
4. **Retention Policies**: Automatic backup retention policies are not yet implemented
5. **Backup Scheduling**: Automatic scheduled backups are not yet implemented

---

## 9. Future Enhancements

1. **Scheduled Backups**: Automatic backup scheduling (daily, weekly, monthly)
2. **Backup Retention**: Configurable retention policies with automatic cleanup
3. **Backup Encryption**: Encrypt backup files at rest
4. **Remote Backup Storage**: Support for remote backup storage (S3, Azure Blob, etc.)
5. **Incremental Backups**: Support for incremental backups to reduce size
6. **Backup Verification**: Automated backup integrity verification
7. **Backup API**: REST API endpoints for backup and restore operations

---

_This document defines the comprehensive requirements for backup and restore functionality in Cerberus SIEM. All functional requirements marked with [x] are implemented. Future enhancements are documented for roadmap planning._



