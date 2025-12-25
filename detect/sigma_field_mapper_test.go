package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cerberus/core"
)

// TestNewFieldMapper verifies basic initialization
func TestNewFieldMapper(t *testing.T) {
	fm := NewFieldMapper()

	if fm == nil {
		t.Fatal("NewFieldMapper returned nil")
	}

	if fm.mappings == nil {
		t.Error("mappings map not initialized")
	}

	if fm.globalMapping == nil {
		t.Error("globalMapping not initialized")
	}

	if fm.fieldAliases == nil {
		t.Error("fieldAliases not initialized")
	}

	// Should reference core.FieldAliases
	if len(fm.fieldAliases) == 0 {
		t.Error("fieldAliases should be populated from core.FieldAliases")
	}
}

// TestLoadMappings_ValidConfig tests loading a valid configuration
func TestLoadMappings_ValidConfig(t *testing.T) {
	// Create temporary config file
	configContent := `
generic:
  process: Image
  command: CommandLine
  user: User

windows_sysmon:
  image: Image
  command_line: CommandLine
  process_id: ProcessId

dns:
  query: QueryName
  response: QueryResults
`

	tmpFile := createTempYAML(t, configContent)
	defer os.Remove(tmpFile)

	// Load mappings
	fm := NewFieldMapper()
	err := fm.LoadMappings(tmpFile)
	if err != nil {
		t.Fatalf("LoadMappings failed: %v", err)
	}

	// Verify generic mapping
	if len(fm.globalMapping) != 3 {
		t.Errorf("Expected 3 generic mappings, got %d", len(fm.globalMapping))
	}

	if fm.globalMapping["process"] != "Image" {
		t.Error("Generic mapping 'process' -> 'Image' not loaded correctly")
	}

	// Verify logsource-specific mappings
	if len(fm.mappings) != 2 {
		t.Errorf("Expected 2 logsource mappings, got %d", len(fm.mappings))
	}

	winSysmon, exists := fm.mappings["windows_sysmon"]
	if !exists {
		t.Fatal("windows_sysmon mapping not loaded")
	}

	if winSysmon["command_line"] != "CommandLine" {
		t.Error("windows_sysmon mapping 'command_line' -> 'CommandLine' not loaded correctly")
	}
}

// TestLoadMappings_FileNotFound tests handling of missing file
func TestLoadMappings_FileNotFound(t *testing.T) {
	fm := NewFieldMapper()
	err := fm.LoadMappings("/nonexistent/path/to/config.yaml")

	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	if !strings.Contains(err.Error(), "failed to read field mappings config") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestLoadMappings_InvalidYAML tests handling of malformed YAML
func TestLoadMappings_InvalidYAML(t *testing.T) {
	invalidYAML := `
generic:
  field1: mapped1
windows_sysmon:
  - this is not valid yaml structure
  - for our expected format
`

	tmpFile := createTempYAML(t, invalidYAML)
	defer os.Remove(tmpFile)

	fm := NewFieldMapper()
	err := fm.LoadMappings(tmpFile)

	if err == nil {
		t.Error("Expected error for invalid YAML structure, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse field mappings YAML") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestLoadMappings_EmptyConfig tests handling of empty configuration
func TestLoadMappings_EmptyConfig(t *testing.T) {
	tmpFile := createTempYAML(t, "")
	defer os.Remove(tmpFile)

	fm := NewFieldMapper()
	err := fm.LoadMappings(tmpFile)

	if err == nil {
		t.Error("Expected error for empty config, got nil")
	}

	if !strings.Contains(err.Error(), "empty or invalid") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestLoadMappings_YAMLBomb tests protection against YAML bombs
func TestLoadMappings_YAMLBomb(t *testing.T) {
	// Create a file larger than the 5MB limit
	largeContent := strings.Repeat("field: value\n", 500000) // ~6MB

	tmpFile := createTempYAML(t, largeContent)
	defer os.Remove(tmpFile)

	fm := NewFieldMapper()
	err := fm.LoadMappings(tmpFile)

	if err == nil {
		t.Error("Expected error for oversized config, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestLoadMappings_TooManyFields tests limit on fields per logsource
func TestLoadMappings_TooManyFields(t *testing.T) {
	// Create config with too many fields (>1000)
	// Use unique field names to avoid YAML duplicate key errors
	var sb strings.Builder
	sb.WriteString("test_source:\n")
	for i := 0; i < 1001; i++ {
		sb.WriteString("  source_field_")
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString("_")
		sb.WriteString(string(rune('0' + ((i / 10) % 10))))
		sb.WriteString("_")
		sb.WriteString(string(rune('0' + ((i / 100) % 10))))
		sb.WriteString("_")
		sb.WriteString(string(rune('0' + ((i / 1000) % 10))))
		sb.WriteString(": MappedField\n")
	}

	tmpFile := createTempYAML(t, sb.String())
	defer os.Remove(tmpFile)

	fm := NewFieldMapper()
	err := fm.LoadMappings(tmpFile)

	if err == nil {
		t.Error("Expected error for too many fields, got nil")
	}

	if !strings.Contains(err.Error(), "too many field mappings") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestMapField_LogsourceSpecific tests logsource-specific mapping (Level 1)
func TestMapField_LogsourceSpecific(t *testing.T) {
	fm := setupTestFieldMapper(t)

	tests := []struct {
		name      string
		field     string
		logsource map[string]interface{}
		want      string
	}{
		{
			name:  "windows_sysmon exact match",
			field: "image",
			logsource: map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			},
			want: "Image",
		},
		{
			name:  "dns service mapping",
			field: "query",
			logsource: map[string]interface{}{
				"category": "dns",
			},
			want: "QueryName",
		},
		{
			name:  "product+service composite key",
			field: "command_line",
			logsource: map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			},
			want: "CommandLine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fm.MapField(tt.field, tt.logsource)
			if got != tt.want {
				t.Errorf("MapField(%q, %v) = %q, want %q", tt.field, tt.logsource, got, tt.want)
			}
		})
	}
}

// TestMapField_GenericFallback tests generic mapping fallback (Level 2)
func TestMapField_GenericFallback(t *testing.T) {
	fm := setupTestFieldMapper(t)

	logsource := map[string]interface{}{
		"product": "unknown_product",
	}

	// Field exists in generic but not in logsource-specific
	got := fm.MapField("process", logsource)
	want := "Image"

	if got != want {
		t.Errorf("MapField with generic fallback = %q, want %q", got, want)
	}
}

// TestMapField_AliasFallback tests core.FieldAliases fallback (Level 3)
func TestMapField_AliasFallback(t *testing.T) {
	fm := NewFieldMapper()

	logsource := map[string]interface{}{
		"product": "test",
	}

	// Field exists in core.FieldAliases but not in config
	// "pid" should map to "ProcessId" via core.FieldAliases
	got := fm.MapField("pid", logsource)
	want := "ProcessId"

	if got != want {
		t.Errorf("MapField with alias fallback = %q, want %q", got, want)
	}
}

// TestMapField_Passthrough tests pass-through behavior (Level 4)
func TestMapField_Passthrough(t *testing.T) {
	fm := NewFieldMapper()

	logsource := map[string]interface{}{
		"product": "test",
	}

	// Field doesn't exist in any mapping - should return as-is
	field := "CustomFieldName"
	got := fm.MapField(field, logsource)

	if got != field {
		t.Errorf("MapField passthrough = %q, want %q", got, field)
	}
}

// TestMapField_EmptyField tests handling of empty field name
func TestMapField_EmptyField(t *testing.T) {
	fm := NewFieldMapper()

	logsource := map[string]interface{}{
		"product": "windows",
	}

	got := fm.MapField("", logsource)
	if got != "" {
		t.Errorf("MapField with empty field = %q, want empty string", got)
	}
}

// TestMapField_NilLogsource tests handling of nil logsource
func TestMapField_NilLogsource(t *testing.T) {
	fm := setupTestFieldMapper(t)

	// With nil logsource, should fall back to generic/alias/passthrough
	got := fm.MapField("process", nil)
	want := "Image" // Should find in generic mapping

	if got != want {
		t.Errorf("MapField with nil logsource = %q, want %q", got, want)
	}
}

// TestMapField_Whitespace tests whitespace handling
func TestMapField_Whitespace(t *testing.T) {
	fm := setupTestFieldMapper(t)

	logsource := map[string]interface{}{
		"product": "windows",
		"service": "sysmon",
	}

	// Field with leading/trailing whitespace
	got := fm.MapField("  image  ", logsource)
	want := "Image"

	if got != want {
		t.Errorf("MapField with whitespace = %q, want %q", got, want)
	}
}

// TestGetLogsourceKeys tests logsource key generation
func TestGetLogsourceKeys(t *testing.T) {
	fm := NewFieldMapper()

	tests := []struct {
		name      string
		logsource map[string]interface{}
		want      []string
	}{
		{
			name: "product + service",
			logsource: map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			},
			want: []string{"windows_sysmon", "windows", "sysmon"},
		},
		{
			name: "product + category",
			logsource: map[string]interface{}{
				"product":  "windows",
				"category": "process_creation",
			},
			want: []string{"windows_process_creation", "windows", "process_creation"},
		},
		{
			name: "product only",
			logsource: map[string]interface{}{
				"product": "linux",
			},
			want: []string{"linux"},
		},
		{
			name: "category only",
			logsource: map[string]interface{}{
				"category": "dns",
			},
			want: []string{"dns"},
		},
		{
			name: "all three",
			logsource: map[string]interface{}{
				"product":  "windows",
				"service":  "security",
				"category": "authentication",
			},
			want: []string{"windows_security", "windows_authentication", "windows", "security", "authentication"},
		},
		{
			name:      "nil logsource",
			logsource: nil,
			want:      nil,
		},
		{
			name:      "empty logsource",
			logsource: map[string]interface{}{},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fm.getLogsourceKeys(tt.logsource)
			if len(got) != len(tt.want) {
				t.Errorf("getLogsourceKeys() returned %d keys, want %d\nGot: %v\nWant: %v",
					len(got), len(tt.want), got, tt.want)
				return
			}

			for i, key := range got {
				if key != tt.want[i] {
					t.Errorf("getLogsourceKeys()[%d] = %q, want %q", i, key, tt.want[i])
				}
			}
		})
	}
}

// TestGetEventFieldValue tests event field extraction
func TestGetEventFieldValue(t *testing.T) {
	fm := NewFieldMapper()

	timestamp, _ := time.Parse(time.RFC3339, "2024-01-15T10:00:00Z")
	event := &core.Event{
		EventID:      "event-123",
		Timestamp:    timestamp,
		SourceFormat: "sysmon",
		SourceIP:     "192.168.1.100",
		EventType:    "process_creation",
		Severity:     "high",
		Fields: map[string]interface{}{
			"CommandLine": "powershell.exe -enc ...",
			"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"ProcessId":   1234,
			"nested": map[string]interface{}{
				"field": "value",
			},
		},
	}

	tests := []struct {
		name      string
		field     string
		wantValue interface{}
		wantFound bool
	}{
		{
			name:      "top-level field: event_id",
			field:     "event_id",
			wantValue: "event-123",
			wantFound: true,
		},
		{
			name:      "top-level field: source_ip",
			field:     "source_ip",
			wantValue: "192.168.1.100",
			wantFound: true,
		},
		{
			name:      "event fields: CommandLine",
			field:     "CommandLine",
			wantValue: "powershell.exe -enc ...",
			wantFound: true,
		},
		{
			name:      "event fields: ProcessId",
			field:     "ProcessId",
			wantValue: 1234,
			wantFound: true,
		},
		{
			name:      "nested field",
			field:     "nested.field",
			wantValue: "value",
			wantFound: true,
		},
		{
			name:      "non-existent field",
			field:     "NonExistent",
			wantValue: nil,
			wantFound: false,
		},
		{
			name:      "non-existent nested field",
			field:     "nested.nonexistent",
			wantValue: nil,
			wantFound: false,
		},
		{
			name:      "invalid nested path",
			field:     "ProcessId.invalid",
			wantValue: nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotFound := fm.GetEventFieldValue(event, tt.field)

			if gotFound != tt.wantFound {
				t.Errorf("GetEventFieldValue(%q) found = %v, want %v", tt.field, gotFound, tt.wantFound)
			}

			if gotFound && gotValue != tt.wantValue {
				t.Errorf("GetEventFieldValue(%q) value = %v, want %v", tt.field, gotValue, tt.wantValue)
			}
		})
	}
}

// TestGetEventFieldValue_NilEvent tests handling of nil event
func TestGetEventFieldValue_NilEvent(t *testing.T) {
	fm := NewFieldMapper()

	value, found := fm.GetEventFieldValue(nil, "any_field")

	if found {
		t.Error("GetEventFieldValue with nil event should return found=false")
	}

	if value != nil {
		t.Errorf("GetEventFieldValue with nil event should return nil value, got %v", value)
	}
}

// TestMapFieldWithContext tests mapping with context information
func TestMapFieldWithContext(t *testing.T) {
	fm := setupTestFieldMapper(t)

	tests := []struct {
		name       string
		field      string
		logsource  map[string]interface{}
		wantField  string
		wantSource string
	}{
		{
			name:  "logsource-specific mapping",
			field: "image",
			logsource: map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			},
			wantField:  "Image",
			wantSource: "logsource:windows_sysmon",
		},
		{
			name:  "generic mapping",
			field: "process",
			logsource: map[string]interface{}{
				"product": "unknown",
			},
			wantField:  "Image",
			wantSource: "generic",
		},
		{
			name:  "alias mapping",
			field: "pid",
			logsource: map[string]interface{}{
				"product": "unknown",
			},
			wantField:  "ProcessId",
			wantSource: "alias",
		},
		{
			name:  "passthrough",
			field: "CustomField",
			logsource: map[string]interface{}{
				"product": "unknown",
			},
			wantField:  "CustomField",
			wantSource: "passthrough",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotField, gotSource := fm.MapFieldWithContext(tt.field, tt.logsource)

			if gotField != tt.wantField {
				t.Errorf("MapFieldWithContext field = %q, want %q", gotField, tt.wantField)
			}

			if gotSource != tt.wantSource {
				t.Errorf("MapFieldWithContext source = %q, want %q", gotSource, tt.wantSource)
			}
		})
	}
}

// TestGetStats tests mapping statistics
func TestGetStats(t *testing.T) {
	fm := setupTestFieldMapper(t)

	stats := fm.GetStats()

	if stats.LogsourceCount != 2 {
		t.Errorf("LogsourceCount = %d, want 2", stats.LogsourceCount)
	}

	if stats.GenericFieldCount != 3 {
		t.Errorf("GenericFieldCount = %d, want 3", stats.GenericFieldCount)
	}

	// Total should be generic (3) + windows_sysmon (3) + dns (2) = 8
	if stats.TotalFieldMappings != 8 {
		t.Errorf("TotalFieldMappings = %d, want 8", stats.TotalFieldMappings)
	}

	if stats.LogsourceMappings["windows_sysmon"] != 3 {
		t.Errorf("windows_sysmon field count = %d, want 3", stats.LogsourceMappings["windows_sysmon"])
	}
}

// TestValidateMapping tests mapping validation
func TestValidateMapping(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid mapping",
			config: `
generic:
  field1: Field1
  field2: Field2
`,
			expectError: false,
		},
		{
			name:        "empty mapping",
			config:      "",
			expectError: true,
			errorMsg:    "no field mappings loaded",
		},
		{
			name: "pass-through mapping (source == target is valid)",
			config: `
generic:
  field1: field1
  c-ip: c-ip
`,
			expectError: false, // This is valid - indicates field already in correct format
		},
		{
			name: "empty source field",
			config: `
generic:
  "": MappedField
`,
			expectError: true,
			errorMsg:    "empty source field name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFieldMapper()

			if tt.config != "" {
				tmpFile := createTempYAML(t, tt.config)
				defer os.Remove(tmpFile)

				if err := fm.LoadMappings(tmpFile); err != nil && !tt.expectError {
					t.Fatalf("LoadMappings failed: %v", err)
				}
			}

			err := fm.ValidateMapping()

			if tt.expectError && err == nil {
				t.Error("Expected validation error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}

			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Error message %q does not contain %q", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

// TestValidateMapping_ExcessiveFieldLength tests that ValidateMapping rejects
// field names exceeding the maximum allowed length (200 characters)
func TestValidateMapping_ExcessiveFieldLength(t *testing.T) {
	// Create field name exceeding 200 characters
	excessiveFieldName := strings.Repeat("a", 201)

	tests := []struct {
		name        string
		config      string
		expectError bool
		errorMsg    string
	}{
		{
			name: "excessive source field name",
			config: `
generic:
  ` + excessiveFieldName + `: MappedField
`,
			expectError: true,
			errorMsg:    "exceeding max length",
		},
		{
			name: "excessive target field name",
			config: `
generic:
  valid_field: ` + excessiveFieldName + `
`,
			expectError: true,
			errorMsg:    "exceeding max length",
		},
		{
			name: "exactly 200 chars - should pass",
			config: `
generic:
  ` + strings.Repeat("b", 200) + `: ValidTarget
`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFieldMapper()

			tmpFile := createTempYAML(t, tt.config)
			defer os.Remove(tmpFile)

			if err := fm.LoadMappings(tmpFile); err != nil {
				// If loading fails, skip validation test for this case
				if tt.expectError {
					// Loading failure is also acceptable for invalid configs
					return
				}
				t.Fatalf("LoadMappings failed unexpectedly: %v", err)
			}

			err := fm.ValidateMapping()

			if tt.expectError && err == nil {
				t.Error("Expected validation error for excessive field length, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}

			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Error message %q does not contain %q", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

// TestLoadMappings_ExcessiveLogsourceName tests that LoadMappings rejects
// logsource names exceeding the maximum allowed length (100 characters)
func TestLoadMappings_ExcessiveLogsourceName(t *testing.T) {
	// Create logsource name exceeding 100 characters
	excessiveLogsourceName := strings.Repeat("x", 101)

	tests := []struct {
		name        string
		config      string
		expectError bool
		errorMsg    string
	}{
		{
			name: "excessive logsource name (101 chars)",
			config: excessiveLogsourceName + `:
  field1: MappedField1
  field2: MappedField2
`,
			expectError: true,
			errorMsg:    "exceeds maximum length",
		},
		{
			name: "exactly 100 chars - should pass",
			config: strings.Repeat("y", 100) + `:
  field1: MappedField1
`,
			expectError: false,
		},
		{
			name: "multiple logsources with one excessive",
			config: `generic:
  field1: Field1
` + excessiveLogsourceName + `:
  field2: Field2
`,
			expectError: true,
			errorMsg:    "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFieldMapper()

			tmpFile := createTempYAML(t, tt.config)
			defer os.Remove(tmpFile)

			err := fm.LoadMappings(tmpFile)

			if tt.expectError && err == nil {
				t.Error("Expected error for excessive logsource name, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Error message %q does not contain %q", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

// TestInitGlobalFieldMapper tests global singleton initialization
func TestInitGlobalFieldMapper(t *testing.T) {
	// Save and restore global state
	origMapper := globalFieldMapper
	origErr := globalFieldMapperErr
	defer func() {
		globalFieldMapper = origMapper
		globalFieldMapperErr = origErr
		globalFieldMapperOnce = sync.Once{} // Reset for other tests
	}()

	// Reset global state
	globalFieldMapper = nil
	globalFieldMapperErr = nil
	globalFieldMapperOnce = sync.Once{}

	// Create temporary config
	config := `
generic:
  test_field: TestField
`
	tmpFile := createTempYAML(t, config)
	defer os.Remove(tmpFile)

	// Initialize global mapper
	ctx := context.Background()
	err := InitGlobalFieldMapper(ctx, tmpFile)
	if err != nil {
		t.Fatalf("InitGlobalFieldMapper failed: %v", err)
	}

	// Get global mapper
	fm := GetGlobalFieldMapper()
	if fm == nil {
		t.Fatal("GetGlobalFieldMapper returned nil after initialization")
	}

	// Verify it works
	mapped := fm.MapField("test_field", nil)
	if mapped != "TestField" {
		t.Errorf("Global mapper MapField = %q, want %q", mapped, "TestField")
	}
}

// TestInitGlobalFieldMapper_ValidationFailure tests that InitGlobalFieldMapper
// returns an error when validation fails (e.g., config with empty field names)
func TestInitGlobalFieldMapper_ValidationFailure(t *testing.T) {
	// Save and restore global state
	origMapper := globalFieldMapper
	origErr := globalFieldMapperErr
	defer func() {
		globalFieldMapper = origMapper
		globalFieldMapperErr = origErr
		globalFieldMapperOnce = sync.Once{} // Reset for other tests
	}()

	// Reset global state
	globalFieldMapper = nil
	globalFieldMapperErr = nil
	globalFieldMapperOnce = sync.Once{}

	// Create a config file that will pass loading but fail validation
	// Empty target field name triggers validation error
	config := `
generic:
  valid_field: ""
`
	tmpFile := createTempYAML(t, config)
	defer os.Remove(tmpFile)

	// Initialize global mapper - should fail due to validation
	ctx := context.Background()
	err := InitGlobalFieldMapper(ctx, tmpFile)

	if err == nil {
		t.Error("Expected InitGlobalFieldMapper to fail with validation error, got nil")
	}

	if err != nil && !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation failed error, got: %v", err)
	}

	// Global mapper should be nil after failed initialization
	fm := GetGlobalFieldMapper()
	if fm != nil {
		t.Error("GetGlobalFieldMapper should return nil after failed initialization")
	}
}

// TestConcurrentAccess tests thread-safety of field mapper
func TestConcurrentAccess(t *testing.T) {
	fm := setupTestFieldMapper(t)

	const goroutines = 50
	const operations = 100

	done := make(chan bool)

	// Concurrent readers
	for i := 0; i < goroutines; i++ {
		go func() {
			logsource := map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			}

			for j := 0; j < operations; j++ {
				_ = fm.MapField("image", logsource)
				_ = fm.GetStats()
				_, _ = fm.MapFieldWithContext("command_line", logsource)
			}

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestRealWorldConfig tests with actual config file if it exists
func TestRealWorldConfig(t *testing.T) {
	configPath := filepath.Join("..", "config", "sigma_field_mappings.yaml")

	// Skip if file doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("Real config file not found, skipping")
	}

	fm := NewFieldMapper()
	err := fm.LoadMappings(configPath)
	if err != nil {
		t.Fatalf("Failed to load real config: %v", err)
	}

	// Validate it
	err = fm.ValidateMapping()
	if err != nil {
		t.Errorf("Real config validation failed: %v", err)
	}

	// Test some known mappings
	tests := []struct {
		field     string
		logsource map[string]interface{}
		expected  string
	}{
		{
			field: "image",
			logsource: map[string]interface{}{
				"product": "windows",
				"service": "sysmon",
			},
			expected: "Image",
		},
		{
			field: "query",
			logsource: map[string]interface{}{
				"category": "dns",
			},
			expected: "QueryName",
		},
	}

	for _, tt := range tests {
		got := fm.MapField(tt.field, tt.logsource)
		if got != tt.expected {
			t.Errorf("MapField(%q) = %q, want %q", tt.field, got, tt.expected)
		}
	}

	// Print stats for visibility
	stats := fm.GetStats()
	t.Logf("Real config stats: %d logsources, %d generic fields, %d total mappings",
		stats.LogsourceCount, stats.GenericFieldCount, stats.TotalFieldMappings)
}

// Helper functions

// setupTestFieldMapper creates a field mapper with test data
func setupTestFieldMapper(t *testing.T) *FieldMapper {
	t.Helper()

	config := `
generic:
  process: Image
  command: CommandLine
  user: User

windows_sysmon:
  image: Image
  command_line: CommandLine
  process_id: ProcessId

dns:
  query: QueryName
  response: QueryResults
`

	tmpFile := createTempYAML(t, config)
	t.Cleanup(func() { os.Remove(tmpFile) })

	fm := NewFieldMapper()
	if err := fm.LoadMappings(tmpFile); err != nil {
		t.Fatalf("Failed to load test mappings: %v", err)
	}

	return fm
}

// createTempYAML creates a temporary YAML file with the given content
func createTempYAML(t *testing.T, content string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "field_mapping_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}
