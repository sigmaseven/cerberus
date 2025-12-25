package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// FieldMapping represents a field normalization mapping configuration
type FieldMapping struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Mappings         map[string]string `json:"mappings"` // raw_field -> SIGMAField
	IsBuiltin        bool              `json:"is_builtin"`
	LifecycleStatus  string            `json:"lifecycle_status"`  // experimental, test, stable, deprecated, archived
	DeprecatedAt     *time.Time        `json:"deprecated_at,omitempty"`
	DeprecatedReason string            `json:"deprecated_reason,omitempty"`
	DeprecatedBy     string            `json:"deprecated_by,omitempty"`
	SunsetDate       *time.Time        `json:"sunset_date,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// FieldMappingWithLifecycle represents a field mapping with parsed lifecycle fields
type FieldMappingWithLifecycle struct {
	*FieldMapping
	DeprecatedAtSQL NullTime `json:"-"`
	SunsetDateSQL   NullTime `json:"-"`
}

// NullTime wraps sql.NullTime for easier handling
type NullTime struct {
	Time  time.Time
	Valid bool
}

// FieldMappingStorage interface for managing field mappings
type FieldMappingStorage interface {
	Create(mapping *FieldMapping) error
	Get(id string) (*FieldMapping, error)
	GetByName(name string) (*FieldMapping, error)
	List() ([]*FieldMapping, error)
	Update(mapping *FieldMapping) error
	Delete(id string) error
	SeedDefaults(yamlPath string) error
	// Lifecycle management methods (TASK 185)
	GetWithLifecycle(id string) (*FieldMappingWithLifecycle, error)
	UpdateLifecycleStatus(id string, status string, deprecatedAt *time.Time, deprecatedReason, deprecatedBy string, sunsetDate *time.Time) error
	IsMappingInUse(id string) (bool, []string, error)
}

// SQLiteFieldMappingStorage implements FieldMappingStorage for SQLite
type SQLiteFieldMappingStorage struct {
	db *sql.DB
}

// NewSQLiteFieldMappingStorage creates a new SQLite field mapping storage
func NewSQLiteFieldMappingStorage(db *sql.DB) (*SQLiteFieldMappingStorage, error) {
	storage := &SQLiteFieldMappingStorage{db: db}
	if err := storage.init(); err != nil {
		return nil, err
	}
	return storage, nil
}

// init creates the field_mappings table
func (s *SQLiteFieldMappingStorage) init() error {
	query := `
	CREATE TABLE IF NOT EXISTS field_mappings (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		mappings TEXT NOT NULL,
		is_builtin BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_field_mappings_name ON field_mappings(name);
	`
	_, err := s.db.Exec(query)
	return err
}

// Create creates a new field mapping
func (s *SQLiteFieldMappingStorage) Create(mapping *FieldMapping) error {
	if mapping.ID == "" {
		mapping.ID = uuid.New().String()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now().UTC()
	}
	mapping.UpdatedAt = time.Now().UTC()

	// Serialize mappings to JSON
	mappingsJSON, err := json.Marshal(mapping.Mappings)
	if err != nil {
		return fmt.Errorf("failed to marshal mappings: %w", err)
	}

	query := `
		INSERT INTO field_mappings (id, name, description, mappings, is_builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err = s.db.Exec(query, mapping.ID, mapping.Name, mapping.Description, string(mappingsJSON), mapping.IsBuiltin, mapping.CreatedAt, mapping.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create field mapping: %w", err)
	}

	return nil
}

// Get retrieves a field mapping by ID
func (s *SQLiteFieldMappingStorage) Get(id string) (*FieldMapping, error) {
	query := `
		SELECT id, name, description, mappings, is_builtin,
		       COALESCE(lifecycle_status, 'experimental') as lifecycle_status,
		       deprecated_at, deprecated_reason, deprecated_by, sunset_date,
		       created_at, updated_at
		FROM field_mappings
		WHERE id = ?
	`
	row := s.db.QueryRow(query, id)

	var mapping FieldMapping
	var mappingsJSON string
	var deprecatedAt, sunsetDate sql.NullString
	var deprecatedReason, deprecatedBy sql.NullString

	err := row.Scan(
		&mapping.ID, &mapping.Name, &mapping.Description, &mappingsJSON, &mapping.IsBuiltin,
		&mapping.LifecycleStatus, &deprecatedAt, &deprecatedReason, &deprecatedBy, &sunsetDate,
		&mapping.CreatedAt, &mapping.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("field mapping not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get field mapping: %w", err)
	}

	// Deserialize mappings from JSON
	if err := json.Unmarshal([]byte(mappingsJSON), &mapping.Mappings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mappings: %w", err)
	}

	// Parse optional datetime fields
	if deprecatedAt.Valid {
		t, err := time.Parse(time.RFC3339, deprecatedAt.String)
		if err == nil {
			mapping.DeprecatedAt = &t
		}
	}
	if sunsetDate.Valid {
		t, err := time.Parse(time.RFC3339, sunsetDate.String)
		if err == nil {
			mapping.SunsetDate = &t
		}
	}
	if deprecatedReason.Valid {
		mapping.DeprecatedReason = deprecatedReason.String
	}
	if deprecatedBy.Valid {
		mapping.DeprecatedBy = deprecatedBy.String
	}

	return &mapping, nil
}

// GetByName retrieves a field mapping by name
func (s *SQLiteFieldMappingStorage) GetByName(name string) (*FieldMapping, error) {
	query := `
		SELECT id, name, description, mappings, is_builtin,
		       COALESCE(lifecycle_status, 'experimental') as lifecycle_status,
		       deprecated_at, deprecated_reason, deprecated_by, sunset_date,
		       created_at, updated_at
		FROM field_mappings
		WHERE name = ?
	`
	row := s.db.QueryRow(query, name)

	var mapping FieldMapping
	var mappingsJSON string
	var deprecatedAt, sunsetDate sql.NullString
	var deprecatedReason, deprecatedBy sql.NullString

	err := row.Scan(
		&mapping.ID, &mapping.Name, &mapping.Description, &mappingsJSON, &mapping.IsBuiltin,
		&mapping.LifecycleStatus, &deprecatedAt, &deprecatedReason, &deprecatedBy, &sunsetDate,
		&mapping.CreatedAt, &mapping.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("field mapping not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get field mapping: %w", err)
	}

	// Deserialize mappings from JSON
	if err := json.Unmarshal([]byte(mappingsJSON), &mapping.Mappings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mappings: %w", err)
	}

	// Parse optional datetime fields
	if deprecatedAt.Valid {
		t, err := time.Parse(time.RFC3339, deprecatedAt.String)
		if err == nil {
			mapping.DeprecatedAt = &t
		}
	}
	if sunsetDate.Valid {
		t, err := time.Parse(time.RFC3339, sunsetDate.String)
		if err == nil {
			mapping.SunsetDate = &t
		}
	}
	if deprecatedReason.Valid {
		mapping.DeprecatedReason = deprecatedReason.String
	}
	if deprecatedBy.Valid {
		mapping.DeprecatedBy = deprecatedBy.String
	}

	return &mapping, nil
}

// List retrieves all field mappings
func (s *SQLiteFieldMappingStorage) List() ([]*FieldMapping, error) {
	query := `
		SELECT id, name, description, mappings, is_builtin,
		       COALESCE(lifecycle_status, 'experimental') as lifecycle_status,
		       deprecated_at, deprecated_reason, deprecated_by, sunset_date,
		       created_at, updated_at
		FROM field_mappings
		ORDER BY is_builtin DESC, name ASC
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list field mappings: %w", err)
	}
	defer rows.Close()

	var mappings []*FieldMapping
	for rows.Next() {
		var mapping FieldMapping
		var mappingsJSON string
		var deprecatedAt, sunsetDate sql.NullString
		var deprecatedReason, deprecatedBy sql.NullString

		err := rows.Scan(
			&mapping.ID, &mapping.Name, &mapping.Description, &mappingsJSON, &mapping.IsBuiltin,
			&mapping.LifecycleStatus, &deprecatedAt, &deprecatedReason, &deprecatedBy, &sunsetDate,
			&mapping.CreatedAt, &mapping.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan field mapping: %w", err)
		}

		// Deserialize mappings from JSON
		if err := json.Unmarshal([]byte(mappingsJSON), &mapping.Mappings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mappings: %w", err)
		}

		// Parse optional datetime fields
		if deprecatedAt.Valid {
			t, err := time.Parse(time.RFC3339, deprecatedAt.String)
			if err == nil {
				mapping.DeprecatedAt = &t
			}
		}
		if sunsetDate.Valid {
			t, err := time.Parse(time.RFC3339, sunsetDate.String)
			if err == nil {
				mapping.SunsetDate = &t
			}
		}
		if deprecatedReason.Valid {
			mapping.DeprecatedReason = deprecatedReason.String
		}
		if deprecatedBy.Valid {
			mapping.DeprecatedBy = deprecatedBy.String
		}

		mappings = append(mappings, &mapping)
	}

	return mappings, nil
}

// Update updates an existing field mapping
func (s *SQLiteFieldMappingStorage) Update(mapping *FieldMapping) error {
	// Check if it's a builtin mapping
	existing, err := s.Get(mapping.ID)
	if err != nil {
		return err
	}
	if existing.IsBuiltin {
		return fmt.Errorf("cannot update builtin field mapping: %s", mapping.Name)
	}

	mapping.UpdatedAt = time.Now().UTC()

	// Serialize mappings to JSON
	mappingsJSON, err := json.Marshal(mapping.Mappings)
	if err != nil {
		return fmt.Errorf("failed to marshal mappings: %w", err)
	}

	query := `
		UPDATE field_mappings
		SET name = ?, description = ?, mappings = ?, updated_at = ?
		WHERE id = ?
	`
	_, err = s.db.Exec(query, mapping.Name, mapping.Description, string(mappingsJSON), mapping.UpdatedAt, mapping.ID)
	if err != nil {
		return fmt.Errorf("failed to update field mapping: %w", err)
	}

	return nil
}

// Delete deletes a field mapping
func (s *SQLiteFieldMappingStorage) Delete(id string) error {
	// Check if it's a builtin mapping
	existing, err := s.Get(id)
	if err != nil {
		return err
	}
	if existing.IsBuiltin {
		return fmt.Errorf("cannot delete builtin field mapping: %s", existing.Name)
	}

	// TODO: Check if any listeners are using this mapping
	// This would require a join query with the listeners table

	query := `DELETE FROM field_mappings WHERE id = ?`
	_, err = s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete field mapping: %w", err)
	}

	return nil
}

// SeedDefaults loads default field mappings from YAML file
func (s *SQLiteFieldMappingStorage) SeedDefaults(yamlPath string) error {
	// Read YAML file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read field mappings file: %w", err)
	}

	// Parse YAML
	var yamlMappings map[string]map[string]string
	if err := yaml.Unmarshal(data, &yamlMappings); err != nil {
		return fmt.Errorf("failed to parse field mappings YAML: %w", err)
	}

	// Create "sigma" mapping (no normalization)
	sigmaMapping := &FieldMapping{
		ID:          "sigma",
		Name:        "sigma",
		Description: "Native SIGMA field names (no normalization required)",
		Mappings:    make(map[string]string),
		IsBuiltin:   true,
	}
	if err := s.createIfNotExists(sigmaMapping); err != nil {
		return fmt.Errorf("failed to seed sigma mapping: %w", err)
	}

	// Create mappings from YAML
	for name, mappings := range yamlMappings {
		description := getDescriptionForMapping(name)
		mapping := &FieldMapping{
			ID:          name,
			Name:        name,
			Description: description,
			Mappings:    mappings,
			IsBuiltin:   true,
		}
		if err := s.createIfNotExists(mapping); err != nil {
			return fmt.Errorf("failed to seed %s mapping: %w", name, err)
		}
	}

	return nil
}

// createIfNotExists creates a mapping only if it doesn't already exist
func (s *SQLiteFieldMappingStorage) createIfNotExists(mapping *FieldMapping) error {
	// Check if mapping exists
	_, err := s.GetByName(mapping.Name)
	if err == nil {
		// Mapping already exists, skip
		return nil
	}

	// Create mapping
	return s.Create(mapping)
}

// getDescriptionForMapping returns a human-readable description for a mapping
func getDescriptionForMapping(name string) string {
	descriptions := map[string]string{
		"sigma":            "Native SIGMA field names (no normalization required)",
		"windows_sysmon":   "Windows Sysmon event logs",
		"windows_security": "Windows Security event logs",
		"linux_auditd":     "Linux auditd logs",
		"powershell":       "PowerShell logs",
		"firewall":         "Generic firewall logs (Cisco, Palo Alto, etc.)",
		"dns":              "DNS query logs",
		"webserver":        "Web server logs (nginx, Apache, IIS)",
		"syslog":           "CEF/Syslog formatted logs",
		"aws_cloudtrail":   "AWS CloudTrail logs",
		"azure_ad":         "Azure Active Directory logs",
		"gcp_audit":        "Google Cloud Platform audit logs",
		"generic":          "Generic field mappings (fallback)",
	}
	if desc, ok := descriptions[name]; ok {
		return desc
	}
	return fmt.Sprintf("Custom field mapping for %s", name)
}

// TASK 185: Lifecycle management methods

// GetWithLifecycle retrieves a field mapping with lifecycle fields
func (s *SQLiteFieldMappingStorage) GetWithLifecycle(id string) (*FieldMappingWithLifecycle, error) {
	mapping, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	result := &FieldMappingWithLifecycle{
		FieldMapping: mapping,
	}

	// Parse SQL nullable times
	if mapping.DeprecatedAt != nil {
		result.DeprecatedAtSQL = NullTime{Time: *mapping.DeprecatedAt, Valid: true}
	}
	if mapping.SunsetDate != nil {
		result.SunsetDateSQL = NullTime{Time: *mapping.SunsetDate, Valid: true}
	}

	return result, nil
}

// UpdateLifecycleStatus updates lifecycle status and related fields
func (s *SQLiteFieldMappingStorage) UpdateLifecycleStatus(id string, status string, deprecatedAt *time.Time, deprecatedReason, deprecatedBy string, sunsetDate *time.Time) error {
	now := time.Now().UTC()

	// Build update query dynamically
	query := "UPDATE field_mappings SET lifecycle_status = ?, updated_at = ?"
	args := []interface{}{status, now.Format(time.RFC3339)}

	if status == "deprecated" {
		query += ", deprecated_at = ?, deprecated_reason = ?, deprecated_by = ?"
		if deprecatedAt != nil {
			args = append(args, deprecatedAt.UTC().Format(time.RFC3339))
		} else {
			args = append(args, now.Format(time.RFC3339))
		}
		args = append(args, deprecatedReason, deprecatedBy)

		if sunsetDate != nil {
			query += ", sunset_date = ?"
			args = append(args, sunsetDate.UTC().Format(time.RFC3339))
		}
	} else if status != "deprecated" {
		// Clear deprecation fields when leaving deprecated state
		query += ", deprecated_at = NULL, deprecated_reason = NULL, deprecated_by = NULL, sunset_date = NULL"
	}

	query += " WHERE id = ?"
	args = append(args, id)

	result, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update lifecycle status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("field mapping not found: %s", id)
	}

	return nil
}

// IsMappingInUse checks if a field mapping is referenced by any listeners
func (s *SQLiteFieldMappingStorage) IsMappingInUse(id string) (bool, []string, error) {
	// Query listeners table for references to this mapping
	query := `
		SELECT l.id, l.name
		FROM listeners l
		WHERE l.field_mapping_id = ? OR l.field_mapping = ?
	`
	rows, err := s.db.Query(query, id, id)
	if err != nil {
		// If listeners table doesn't exist, mapping is not in use
		if strings.Contains(err.Error(), "no such table") {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("failed to check mapping usage: %w", err)
	}
	defer rows.Close()

	var listenerNames []string
	for rows.Next() {
		var listenerID, listenerName string
		if err := rows.Scan(&listenerID, &listenerName); err != nil {
			return false, nil, fmt.Errorf("failed to scan listener: %w", err)
		}
		if listenerName == "" {
			listenerName = listenerID
		}
		listenerNames = append(listenerNames, listenerName)
	}

	return len(listenerNames) > 0, listenerNames, nil
}

// GetDB returns the underlying database connection
func (s *SQLiteFieldMappingStorage) GetDB() *sql.DB {
	return s.db
}
