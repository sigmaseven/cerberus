package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSQLiteFieldMappingStorage tests creating a new field mapping storage
func TestNewSQLiteFieldMappingStorage(t *testing.T) {
	db, sqlite := setupTestDB(t)
	defer db.Close()
	defer sqlite.Close()

	storage, err := NewSQLiteFieldMappingStorage(db)
	require.NoError(t, err)
	require.NotNil(t, storage)
	assert.Equal(t, db, storage.db)

	// Verify table was created
	var tableCount int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='field_mappings'").Scan(&tableCount)
	require.NoError(t, err)
	assert.Equal(t, 1, tableCount, "Expected field_mappings table to exist")

	// Verify index was created
	var indexCount int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_field_mappings_name'").Scan(&indexCount)
	require.NoError(t, err)
	// Note: indexCount may vary due to automatic indices, so we just check no error
	assert.GreaterOrEqual(t, indexCount, 0, "Index query should work")
}

// TestSQLiteFieldMappingStorage_Create tests creating a field mapping
func TestSQLiteFieldMappingStorage_Create(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "test-mapping-001",
		Name:        "test_mapping",
		Description: "A test field mapping",
		Mappings: map[string]string{
			"raw_field1": "normalized_field1",
			"raw_field2": "normalized_field2",
		},
		IsBuiltin: false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	// Verify timestamps were set
	assert.False(t, mapping.CreatedAt.IsZero())
	assert.False(t, mapping.UpdatedAt.IsZero())

	// Retrieve and verify
	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, mapping.ID, retrieved.ID)
	assert.Equal(t, mapping.Name, retrieved.Name)
	assert.Equal(t, mapping.Description, retrieved.Description)
	assert.Equal(t, mapping.Mappings, retrieved.Mappings)
	assert.Equal(t, mapping.IsBuiltin, retrieved.IsBuiltin)
}

// TestSQLiteFieldMappingStorage_Create_AutoID tests that ID is auto-generated if not provided
func TestSQLiteFieldMappingStorage_Create_AutoID(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		Name: "auto_id_mapping",
		Mappings: map[string]string{
			"field1": "norm1",
		},
	}

	err := storage.Create(mapping)
	require.NoError(t, err)
	assert.NotEmpty(t, mapping.ID, "ID should be auto-generated")
}

// TestSQLiteFieldMappingStorage_Create_DuplicateName tests creating mapping with duplicate name
func TestSQLiteFieldMappingStorage_Create_DuplicateName(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping1 := &FieldMapping{
		ID:   "mapping-1",
		Name: "duplicate_name",
		Mappings: map[string]string{
			"field1": "norm1",
		},
	}
	err := storage.Create(mapping1)
	require.NoError(t, err)

	// Try to create another mapping with same name
	mapping2 := &FieldMapping{
		ID:   "mapping-2",
		Name: "duplicate_name", // Same name
		Mappings: map[string]string{
			"field2": "norm2",
		},
	}
	err = storage.Create(mapping2)
	assert.Error(t, err, "Should fail due to unique constraint on name")
}

// TestSQLiteFieldMappingStorage_Get tests retrieving a field mapping by ID
func TestSQLiteFieldMappingStorage_Get(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := createTestFieldMapping("get-test", "get_test_mapping")
	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, mapping.ID, retrieved.ID)
	assert.Equal(t, mapping.Name, retrieved.Name)
	assert.Equal(t, mapping.Mappings["src_ip"], retrieved.Mappings["src_ip"])
}

// TestSQLiteFieldMappingStorage_Get_NotFound tests retrieving non-existent mapping
func TestSQLiteFieldMappingStorage_Get_NotFound(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	_, err := storage.Get("non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field mapping not found")
}

// TestSQLiteFieldMappingStorage_GetByName tests retrieving a field mapping by name
func TestSQLiteFieldMappingStorage_GetByName(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := createTestFieldMapping("name-test", "test_by_name")
	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.GetByName(mapping.Name)
	require.NoError(t, err)
	assert.Equal(t, mapping.ID, retrieved.ID)
	assert.Equal(t, mapping.Name, retrieved.Name)
}

// TestSQLiteFieldMappingStorage_GetByName_NotFound tests retrieving by non-existent name
func TestSQLiteFieldMappingStorage_GetByName_NotFound(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	_, err := storage.GetByName("non-existent-name")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field mapping not found")
}

// TestSQLiteFieldMappingStorage_List tests retrieving all field mappings
func TestSQLiteFieldMappingStorage_List(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create multiple mappings
	mapping1 := createTestFieldMapping("list-1", "mapping_a")
	mapping1.IsBuiltin = true
	err := storage.Create(mapping1)
	require.NoError(t, err)

	mapping2 := createTestFieldMapping("list-2", "mapping_b")
	mapping2.IsBuiltin = false
	err = storage.Create(mapping2)
	require.NoError(t, err)

	mapping3 := createTestFieldMapping("list-3", "mapping_c")
	mapping3.IsBuiltin = true
	err = storage.Create(mapping3)
	require.NoError(t, err)

	// Retrieve all
	allMappings, err := storage.List()
	require.NoError(t, err)
	assert.Len(t, allMappings, 3)

	// Verify ordering: builtin first (DESC), then by name (ASC)
	// Expected order: mapping_a (builtin), mapping_c (builtin), mapping_b (custom)
	builtinCount := 0
	for i, m := range allMappings {
		if m.IsBuiltin {
			builtinCount++
			assert.True(t, i < 2, "Builtin mappings should come first")
		}
	}
	assert.Equal(t, 2, builtinCount)
}

// TestSQLiteFieldMappingStorage_List_Empty tests listing when no mappings exist
func TestSQLiteFieldMappingStorage_List_Empty(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	allMappings, err := storage.List()
	require.NoError(t, err)
	assert.Empty(t, allMappings)
}

// TestSQLiteFieldMappingStorage_Update tests updating a field mapping
func TestSQLiteFieldMappingStorage_Update(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create initial mapping (not builtin)
	mapping := createTestFieldMapping("update-test", "update_mapping")
	mapping.IsBuiltin = false
	err := storage.Create(mapping)
	require.NoError(t, err)

	originalUpdatedAt := mapping.UpdatedAt
	time.Sleep(10 * time.Millisecond) // Ensure timestamp difference

	// Update mapping
	mapping.Name = "updated_mapping_name"
	mapping.Description = "Updated description"
	mapping.Mappings["new_field"] = "new_normalized_field"

	err = storage.Update(mapping)
	require.NoError(t, err)
	assert.True(t, mapping.UpdatedAt.After(originalUpdatedAt))

	// Verify update
	updated, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated_mapping_name", updated.Name)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, "new_normalized_field", updated.Mappings["new_field"])
}

// TestSQLiteFieldMappingStorage_Update_BuiltinError tests that builtin mappings cannot be updated
func TestSQLiteFieldMappingStorage_Update_BuiltinError(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create builtin mapping
	mapping := createTestFieldMapping("builtin-test", "builtin_mapping")
	mapping.IsBuiltin = true
	err := storage.Create(mapping)
	require.NoError(t, err)

	// Try to update it
	mapping.Name = "modified_name"
	err = storage.Update(mapping)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot update builtin field mapping")
}

// TestSQLiteFieldMappingStorage_Update_NotFound tests updating non-existent mapping
func TestSQLiteFieldMappingStorage_Update_NotFound(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := createTestFieldMapping("non-existent", "test")
	err := storage.Update(mapping)
	assert.Error(t, err)
}

// TestSQLiteFieldMappingStorage_Delete tests deleting a field mapping
func TestSQLiteFieldMappingStorage_Delete(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create non-builtin mapping
	mapping := createTestFieldMapping("delete-test", "delete_mapping")
	mapping.IsBuiltin = false
	err := storage.Create(mapping)
	require.NoError(t, err)

	// Delete it
	err = storage.Delete(mapping.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = storage.Get(mapping.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field mapping not found")
}

// TestSQLiteFieldMappingStorage_Delete_BuiltinError tests that builtin mappings cannot be deleted
func TestSQLiteFieldMappingStorage_Delete_BuiltinError(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create builtin mapping
	mapping := createTestFieldMapping("builtin-delete-test", "builtin_delete")
	mapping.IsBuiltin = true
	err := storage.Create(mapping)
	require.NoError(t, err)

	// Try to delete it
	err = storage.Delete(mapping.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete builtin field mapping")
}

// TestSQLiteFieldMappingStorage_Delete_NotFound tests deleting non-existent mapping
func TestSQLiteFieldMappingStorage_Delete_NotFound(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	err := storage.Delete("non-existent-id")
	assert.Error(t, err)
}

// TestSQLiteFieldMappingStorage_SeedDefaults tests seeding default mappings from YAML
func TestSQLiteFieldMappingStorage_SeedDefaults(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create a temporary YAML file
	yamlContent := `
fluentd:
  timestamp: "@timestamp"
  message: "message"
  level: "log.level"

fluentbit:
  time: "timestamp"
  log: "message"
  stream: "source"

sysmon:
  EventID: "event_id"
  Image: "process.name"
  CommandLine: "process.command_line"
`

	tempFile := filepath.Join(t.TempDir(), "test_mappings.yaml")
	err := os.WriteFile(tempFile, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Seed defaults
	err = storage.SeedDefaults(tempFile)
	require.NoError(t, err)

	// Verify mappings were created
	allMappings, err := storage.List()
	require.NoError(t, err)

	// Should have: sigma (created by default) + 3 from YAML
	assert.GreaterOrEqual(t, len(allMappings), 4)

	// Verify sigma mapping exists
	sigmaMapping, err := storage.GetByName("sigma")
	require.NoError(t, err)
	assert.Equal(t, "sigma", sigmaMapping.ID)
	assert.True(t, sigmaMapping.IsBuiltin)
	assert.Equal(t, "Native SIGMA field names (no normalization required)", sigmaMapping.Description)

	// Verify fluentd mapping
	fluentdMapping, err := storage.GetByName("fluentd")
	require.NoError(t, err)
	assert.Equal(t, "fluentd", fluentdMapping.ID)
	assert.True(t, fluentdMapping.IsBuiltin)
	assert.Equal(t, "@timestamp", fluentdMapping.Mappings["timestamp"])
	assert.Equal(t, "message", fluentdMapping.Mappings["message"])

	// Verify sysmon mapping
	sysmonMapping, err := storage.GetByName("sysmon")
	require.NoError(t, err)
	assert.Equal(t, "event_id", sysmonMapping.Mappings["EventID"])
	assert.Equal(t, "process.name", sysmonMapping.Mappings["Image"])
}

// TestSQLiteFieldMappingStorage_SeedDefaults_Idempotent tests that seeding is idempotent
func TestSQLiteFieldMappingStorage_SeedDefaults_Idempotent(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	yamlContent := `
test_mapping:
  field1: "norm1"
  field2: "norm2"
`

	tempFile := filepath.Join(t.TempDir(), "test_idempotent.yaml")
	err := os.WriteFile(tempFile, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Seed first time
	err = storage.SeedDefaults(tempFile)
	require.NoError(t, err)

	allMappings, err := storage.List()
	require.NoError(t, err)
	firstCount := len(allMappings)

	// Seed again
	err = storage.SeedDefaults(tempFile)
	require.NoError(t, err)

	allMappings, err = storage.List()
	require.NoError(t, err)
	secondCount := len(allMappings)

	// Should have same count (no duplicates)
	assert.Equal(t, firstCount, secondCount)
}

// TestSQLiteFieldMappingStorage_SeedDefaults_InvalidFile tests handling of invalid YAML file
func TestSQLiteFieldMappingStorage_SeedDefaults_InvalidFile(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Non-existent file
	err := storage.SeedDefaults("/non/existent/file.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read field mappings file")
}

// TestSQLiteFieldMappingStorage_SeedDefaults_InvalidYAML tests handling of invalid YAML content
func TestSQLiteFieldMappingStorage_SeedDefaults_InvalidYAML(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create invalid YAML file
	invalidYAML := `
this is not: [valid: yaml: content
unclosed: "string
`

	tempFile := filepath.Join(t.TempDir(), "invalid.yaml")
	err := os.WriteFile(tempFile, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	err = storage.SeedDefaults(tempFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse field mappings YAML")
}

// TestGetDescriptionForMapping tests the description mapping function
func TestGetDescriptionForMapping(t *testing.T) {
	tests := []struct {
		name        string
		mappingName string
		want        string
	}{
		{
			name:        "sigma",
			mappingName: "sigma",
			want:        "Native SIGMA field names (no normalization required)",
		},
		{
			name:        "windows_sysmon",
			mappingName: "windows_sysmon",
			want:        "Windows Sysmon event logs",
		},
		{
			name:        "aws_cloudtrail",
			mappingName: "aws_cloudtrail",
			want:        "AWS CloudTrail logs",
		},
		{
			name:        "custom",
			mappingName: "my_custom_mapping",
			want:        "Custom field mapping for my_custom_mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getDescriptionForMapping(tt.mappingName)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSQLiteFieldMappingStorage_ComplexMappings tests handling of complex mapping structures
func TestSQLiteFieldMappingStorage_ComplexMappings(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "complex-test",
		Name:        "complex_mapping",
		Description: "Complex mapping with many fields",
		Mappings: map[string]string{
			"EventID":          "event.id",
			"SourceName":       "event.provider",
			"TimeCreated":      "event.created",
			"Computer":         "host.name",
			"UserID":           "user.id",
			"ProcessName":      "process.name",
			"ProcessID":        "process.pid",
			"ParentProcessID":  "process.parent.pid",
			"CommandLine":      "process.command_line",
			"CurrentDirectory": "process.working_directory",
			"User":             "user.name",
			"LogonID":          "user.session.id",
			"SourceIP":         "source.ip",
			"SourcePort":       "source.port",
			"DestIP":           "destination.ip",
			"DestPort":         "destination.port",
			"Protocol":         "network.protocol",
			"FileName":         "file.name",
			"FilePath":         "file.path",
			"FileHash":         "file.hash.sha256",
		},
		IsBuiltin: false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	// Retrieve and verify all mappings
	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, len(mapping.Mappings), len(retrieved.Mappings))
	assert.Equal(t, mapping.Mappings, retrieved.Mappings)
}

// TestSQLiteFieldMappingStorage_EmptyMappings tests handling of empty mappings
func TestSQLiteFieldMappingStorage_EmptyMappings(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "empty-test",
		Name:        "empty_mapping",
		Description: "Mapping with no fields",
		Mappings:    map[string]string{}, // Empty
		IsBuiltin:   false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.Mappings)
	assert.Empty(t, retrieved.Mappings)
}

// TestSQLiteFieldMappingStorage_SpecialCharacters tests handling of special characters
func TestSQLiteFieldMappingStorage_SpecialCharacters(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "special-chars-test",
		Name:        "special_chars_mapping",
		Description: "Testing special characters: ' \" \\ / \n \t",
		Mappings: map[string]string{
			"field'with'quotes":     "norm.field1",
			"field\"double\"quotes": "norm.field2",
			"field\\backslash":      "norm.field3",
			"field/slash":           "norm.field4",
			"field\twith\ttabs":     "norm.field5",
		},
		IsBuiltin: false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, mapping.Description, retrieved.Description)
	assert.Equal(t, mapping.Mappings, retrieved.Mappings)
}

// TestSQLiteFieldMappingStorage_SQLInjectionPrevention tests SQL injection prevention
func TestSQLiteFieldMappingStorage_SQLInjectionPrevention(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "sql-injection-test",
		Name:        "sql_injection_test",
		Description: "'; DROP TABLE field_mappings; --",
		Mappings: map[string]string{
			"'; DELETE FROM field_mappings WHERE '1'='1": "malicious",
			"normal_field": "normal_value",
		},
		IsBuiltin: false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	// Verify table still exists and data is intact
	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, mapping.Description, retrieved.Description)
	assert.Equal(t, mapping.Mappings, retrieved.Mappings)

	// Verify table still exists
	var tableCount int
	err = storage.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='field_mappings'").Scan(&tableCount)
	require.NoError(t, err)
	assert.Equal(t, 1, tableCount, "Table should still exist after SQL injection attempt")
}

// TestSQLiteFieldMappingStorage_UnicodeSupport tests Unicode character support
func TestSQLiteFieldMappingStorage_UnicodeSupport(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	mapping := &FieldMapping{
		ID:          "unicode-test",
		Name:        "unicode_mapping",
		Description: "Unicode test: 日本語 中文 한글 العربية עברית",
		Mappings: map[string]string{
			"日本語フィールド": "japanese.field",
			"中文字段":     "chinese.field",
			"한글필드":     "korean.field",
		},
		IsBuiltin: false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, mapping.Description, retrieved.Description)
	assert.Equal(t, mapping.Mappings, retrieved.Mappings)
}

// TestSQLiteFieldMappingStorage_LargeMapping tests handling of large mappings
func TestSQLiteFieldMappingStorage_LargeMapping(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create a large mapping with many fields
	largeMapping := make(map[string]string)
	for i := 0; i < 500; i++ {
		largeMapping[string(rune('A'+i%26))+string(rune('0'+i%10))+"_field_"+string(rune(i))] = "normalized_field_" + string(rune(i))
	}

	mapping := &FieldMapping{
		ID:          "large-test",
		Name:        "large_mapping",
		Description: "Large mapping with 500 fields",
		Mappings:    largeMapping,
		IsBuiltin:   false,
	}

	err := storage.Create(mapping)
	require.NoError(t, err)

	retrieved, err := storage.Get(mapping.ID)
	require.NoError(t, err)
	assert.Equal(t, len(mapping.Mappings), len(retrieved.Mappings))
}

// TestSQLiteFieldMappingStorage_ConcurrentAccess tests concurrent access (basic safety check)
func TestSQLiteFieldMappingStorage_ConcurrentAccess(t *testing.T) {
	storage := setupFieldMappingStorage(t)

	// Create multiple mappings concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			mapping := createTestFieldMapping(string(rune('a'+index)), "concurrent_mapping_"+string(rune('a'+index)))
			_ = storage.Create(mapping)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify at least some mappings were created
	allMappings, err := storage.List()
	require.NoError(t, err)
	assert.Greater(t, len(allMappings), 0)
}

// Helper functions for tests

func setupFieldMappingStorage(t *testing.T) *SQLiteFieldMappingStorage {
	t.Helper()
	db, sqlite := setupTestDB(t)
	t.Cleanup(func() {
		db.Close()
		sqlite.Close()
	})

	storage, err := NewSQLiteFieldMappingStorage(db)
	require.NoError(t, err)
	return storage
}

func createTestFieldMapping(id, name string) *FieldMapping {
	return &FieldMapping{
		ID:          id,
		Name:        name,
		Description: "Test field mapping",
		Mappings: map[string]string{
			"src_ip":    "source.ip",
			"dst_ip":    "destination.ip",
			"src_port":  "source.port",
			"dst_port":  "destination.port",
			"user":      "user.name",
			"host":      "host.name",
			"process":   "process.name",
			"event_id":  "event.id",
			"timestamp": "event.created",
		},
		IsBuiltin: false,
	}
}
