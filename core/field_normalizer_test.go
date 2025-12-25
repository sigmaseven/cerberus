package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.5: Comprehensive Field Normalizer Tests
// Tests cover: field normalization, field name standardization, data type conversion,
// vendor-specific field mapping, category detection, hash normalization, timestamp normalization

// TestFieldNormalizer_NormalizeEvent_BasicMapping tests basic field mapping
func TestFieldNormalizer_NormalizeEvent_BasicMapping(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"windows_sysmon": {
				"User":           "User",
				"SourceIp":       "SourceIp",
				"DestinationIp":  "DestinationIp",
				"ProcessCommand": "CommandLine",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	event := map[string]interface{}{
		"User":           "testuser",
		"SourceIp":       "192.168.1.100",
		"DestinationIp":  "10.0.0.1",
		"ProcessCommand": "cmd.exe /c whoami",
	}

	normalized := normalizer.NormalizeEvent(event, "windows_sysmon")

	assert.Equal(t, "testuser", normalized["User"])
	assert.Equal(t, "192.168.1.100", normalized["SourceIp"])
	assert.Equal(t, "10.0.0.1", normalized["DestinationIp"])
	assert.Equal(t, "cmd.exe /c whoami", normalized["CommandLine"])
	assert.NotNil(t, normalized["_raw"], "Original fields should be preserved in _raw")
}

// TestFieldNormalizer_NormalizeEvent_NoMapping tests normalization without mappings
func TestFieldNormalizer_NormalizeEvent_NoMapping(t *testing.T) {
	normalizer := NewFieldNormalizer(nil)

	event := map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
	}

	normalized := normalizer.NormalizeEvent(event, "unknown_source")
	assert.Equal(t, event, normalized, "Without mappings, event should be returned as-is")
}

// TestFieldNormalizer_NormalizeEvent_GenericMapping tests generic mapping fallback
func TestFieldNormalizer_NormalizeEvent_GenericMapping(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"generic": {
				"src_ip": "SourceIp",
				"dst_ip": "DestinationIp",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	event := map[string]interface{}{
		"src_ip": "192.168.1.100",
		"dst_ip": "10.0.0.1",
	}

	// Use unknown source - should fall back to generic
	normalized := normalizer.NormalizeEvent(event, "unknown_source")

	assert.Equal(t, "192.168.1.100", normalized["SourceIp"])
	assert.Equal(t, "10.0.0.1", normalized["DestinationIp"])
}

// TestFieldNormalizer_NormalizeEvent_NestedFields tests nested field access
func TestFieldNormalizer_NormalizeEvent_NestedFields(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {
				"fields.user":     "User",
				"fields.process":  "ProcessName",
				"metadata.source": "Source",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	event := map[string]interface{}{
		"fields": map[string]interface{}{
			"user":    "testuser",
			"process": "cmd.exe",
		},
		"metadata": map[string]interface{}{
			"source": "test-source",
		},
	}

	normalized := normalizer.NormalizeEvent(event, "test_source")

	assert.Equal(t, "testuser", normalized["User"])
	assert.Equal(t, "cmd.exe", normalized["ProcessName"])
	assert.Equal(t, "test-source", normalized["Source"])
}

// TestFieldNormalizer_NormalizeEvent_HashNormalization tests hash format normalization
func TestFieldNormalizer_NormalizeEvent_HashNormalization(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {
				"md5_hash":  "Hashes",
				"sha1_hash": "Hashes",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// MD5 hash (32 hex characters)
	event1 := map[string]interface{}{
		"md5_hash": "a1b2c3d4e5f6789012345678901234ab",
	}
	normalized1 := normalizer.NormalizeEvent(event1, "test_source")
	assert.Equal(t, "MD5=A1B2C3D4E5F6789012345678901234AB", normalized1["Hashes"])

	// SHA1 hash (40 hex characters)
	event2 := map[string]interface{}{
		"sha1_hash": "a1b2c3d4e5f6789012345678901234567890abcd",
	}
	normalized2 := normalizer.NormalizeEvent(event2, "test_source")
	assert.Equal(t, "SHA1=A1B2C3D4E5F6789012345678901234567890ABCD", normalized2["Hashes"])

	// SHA256 hash (64 hex characters)
	event3 := map[string]interface{}{
		"md5_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
	}
	normalized3 := normalizer.NormalizeEvent(event3, "test_source")
	assert.Equal(t, "SHA256=A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456", normalized3["Hashes"])

	// Already normalized hash format
	event4 := map[string]interface{}{
		"md5_hash": "MD5=abc123",
	}
	normalized4 := normalizer.NormalizeEvent(event4, "test_source")
	assert.Equal(t, "MD5=abc123", normalized4["Hashes"])
}

// TestFieldNormalizer_NormalizeEvent_CategoryDetection tests category auto-detection
func TestFieldNormalizer_NormalizeEvent_CategoryDetection(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// Process creation category
	event1 := map[string]interface{}{
		"CommandLine": "cmd.exe /c whoami",
	}
	normalized1 := normalizer.NormalizeEvent(event1, "test_source")
	assert.Equal(t, "process_creation", normalized1["Category"])

	// Network connection category
	event2 := map[string]interface{}{
		"SourceIp":      "192.168.1.100",
		"DestinationIp": "10.0.0.1",
	}
	normalized2 := normalizer.NormalizeEvent(event2, "test_source")
	assert.Equal(t, "network_connection", normalized2["Category"])

	// File event category
	event3 := map[string]interface{}{
		"TargetFilename": "/etc/passwd",
	}
	normalized3 := normalizer.NormalizeEvent(event3, "test_source")
	assert.Equal(t, "file_event", normalized3["Category"])

	// DNS query category
	event4 := map[string]interface{}{
		"QueryName": "example.com",
	}
	normalized4 := normalizer.NormalizeEvent(event4, "test_source")
	assert.Equal(t, "dns_query", normalized4["Category"])

	// Authentication category
	event5 := map[string]interface{}{
		"LogonType": "2",
	}
	normalized5 := normalizer.NormalizeEvent(event5, "test_source")
	assert.Equal(t, "authentication", normalized5["Category"])

	// Generic category (no specific fields)
	event6 := map[string]interface{}{
		"unknown_field": "value",
	}
	normalized6 := normalizer.NormalizeEvent(event6, "test_source")
	assert.Equal(t, "generic", normalized6["Category"])
}

// TestFieldNormalizer_NormalizeEventInPlace tests in-place normalization
func TestFieldNormalizer_NormalizeEventInPlace(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {
				"src_ip": "SourceIp",
				"dst_ip": "DestinationIp",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	event := map[string]interface{}{
		"src_ip": "192.168.1.100",
		"dst_ip": "10.0.0.1",
	}

	// Normalize in place
	normalizer.NormalizeEventInPlace(event, "test_source")

	// Original event should be modified
	assert.Equal(t, "192.168.1.100", event["SourceIp"])
	assert.Equal(t, "10.0.0.1", event["DestinationIp"])
	// Original fields should still exist
	assert.Equal(t, "192.168.1.100", event["src_ip"])
	assert.Equal(t, "10.0.0.1", event["dst_ip"])
}

// TestFieldNormalizer_GetMappingForSource tests mapping retrieval
func TestFieldNormalizer_GetMappingForSource(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"windows_sysmon": {
				"User": "User",
			},
			"generic": {
				"src_ip": "SourceIp",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// Get specific source mapping
	mapping1 := normalizer.GetMappingForSource("windows_sysmon")
	assert.NotNil(t, mapping1)
	assert.Equal(t, "User", mapping1["User"])

	// Get generic mapping fallback
	mapping2 := normalizer.GetMappingForSource("unknown_source")
	assert.NotNil(t, mapping2)
	assert.Equal(t, "SourceIp", mapping2["src_ip"])

	// Get mapping when normalizer has no mappings
	normalizer2 := NewFieldNormalizer(nil)
	mapping3 := normalizer2.GetMappingForSource("test_source")
	assert.Nil(t, mapping3)
}

// TestFieldNormalizer_GetAllMappings tests retrieval of all mappings
func TestFieldNormalizer_GetAllMappings(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"source1": {
				"field1": "Field1",
			},
			"source2": {
				"field2": "Field2",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	allMappings := normalizer.GetAllMappings()
	assert.Len(t, allMappings, 2)
	assert.NotNil(t, allMappings["source1"])
	assert.NotNil(t, allMappings["source2"])
	assert.Equal(t, "Field1", allMappings["source1"]["field1"])
	assert.Equal(t, "Field2", allMappings["source2"]["field2"])

	// Verify it's a deep copy (modifications shouldn't affect original)
	allMappings["source1"]["new_field"] = "NewField"
	mapping := normalizer.GetMappingForSource("source1")
	_, exists := mapping["new_field"]
	assert.False(t, exists, "Modifications to returned mappings shouldn't affect original")
}

// TestFieldNormalizer_UpdateMapping tests mapping updates
func TestFieldNormalizer_UpdateMapping(t *testing.T) {
	normalizer := NewFieldNormalizer(nil)

	newMapping := map[string]string{
		"src_ip": "SourceIp",
		"dst_ip": "DestinationIp",
	}

	normalizer.UpdateMapping("test_source", newMapping)

	mapping := normalizer.GetMappingForSource("test_source")
	assert.NotNil(t, mapping)
	assert.Equal(t, "SourceIp", mapping["src_ip"])
	assert.Equal(t, "DestinationIp", mapping["dst_ip"])
}

// TestFieldNormalizer_DeleteMapping tests mapping deletion
func TestFieldNormalizer_DeleteMapping(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {
				"field1": "Field1",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// Verify mapping exists
	mapping1 := normalizer.GetMappingForSource("test_source")
	assert.NotNil(t, mapping1)

	// Delete mapping
	normalizer.DeleteMapping("test_source")

	// Verify mapping is gone
	mapping2 := normalizer.GetMappingForSource("test_source")
	assert.Nil(t, mapping2, "Deleted mapping should return nil")
}

// TestFieldNormalizer_ListLogSources tests log source listing
func TestFieldNormalizer_ListLogSources(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"source1": {},
			"source2": {},
			"source3": {},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	sources := normalizer.ListLogSources()
	assert.Len(t, sources, 3)
	assert.Contains(t, sources, "source1")
	assert.Contains(t, sources, "source2")
	assert.Contains(t, sources, "source3")

	// Test with no mappings
	normalizer2 := NewFieldNormalizer(nil)
	sources2 := normalizer2.ListLogSources()
	assert.Empty(t, sources2)
}

// TestDetectLogSource tests log source detection
func TestDetectLogSource(t *testing.T) {
	// Windows Sysmon
	event1 := map[string]interface{}{
		"channel": "Microsoft-Windows-Sysmon/Operational",
	}
	assert.Equal(t, "windows_sysmon", DetectLogSource(event1))

	// Windows Security
	event2 := map[string]interface{}{
		"channel": "Security",
	}
	assert.Equal(t, "windows_security", DetectLogSource(event2))

	// PowerShell
	event3 := map[string]interface{}{
		"script_block_text": "Get-Process",
	}
	assert.Equal(t, "powershell", DetectLogSource(event3))

	// Web server (W3C)
	event4 := map[string]interface{}{
		"cs-method": "GET",
	}
	assert.Equal(t, "webserver", DetectLogSource(event4))

	// Linux auditd
	event5 := map[string]interface{}{
		"type": "SYSCALL",
	}
	assert.Equal(t, "linux_auditd", DetectLogSource(event5))

	// DNS
	event6 := map[string]interface{}{
		"query": "example.com",
	}
	assert.Equal(t, "dns", DetectLogSource(event6))

	// AWS CloudTrail
	event7 := map[string]interface{}{
		"user_identity.user_name": "testuser",
	}
	assert.Equal(t, "aws_cloudtrail", DetectLogSource(event7))

	// Generic (unknown)
	event8 := map[string]interface{}{
		"unknown_field": "value",
	}
	assert.Equal(t, "generic", DetectLogSource(event8))
}

// TestNormalizeHashes tests hash normalization function
func TestNormalizeHashes(t *testing.T) {
	// MD5 hash (32 characters)
	md5Hash := "a1b2c3d4e5f6789012345678901234ab"
	assert.Equal(t, "MD5=A1B2C3D4E5F6789012345678901234AB", normalizeHashes(md5Hash))

	// SHA1 hash (40 characters)
	sha1Hash := "a1b2c3d4e5f6789012345678901234567890abcd"
	assert.Equal(t, "SHA1=A1B2C3D4E5F6789012345678901234567890ABCD", normalizeHashes(sha1Hash))

	// SHA256 hash (64 characters)
	sha256Hash := "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
	assert.Equal(t, "SHA256=A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456", normalizeHashes(sha256Hash))

	// Already normalized format
	normalizedHash := "MD5=abc123"
	assert.Equal(t, normalizedHash, normalizeHashes(normalizedHash))

	// Unknown format
	unknownHash := "unknown"
	assert.Equal(t, "unknown", normalizeHashes(unknownHash))

	// Non-string value
	assert.NotEmpty(t, normalizeHashes(123), "Non-string should be converted to string")
}

// TestNormalizeTimestamp tests timestamp normalization
func TestNormalizeTimestamp(t *testing.T) {
	// String timestamp
	timestampStr := "2024-01-01T00:00:00Z"
	assert.Equal(t, timestampStr, normalizeTimestamp(timestampStr))

	// Non-string value
	assert.NotEmpty(t, normalizeTimestamp(1234567890), "Non-string should be converted to string")
}

// TestDetectCategory tests category detection function
func TestDetectCategory(t *testing.T) {
	// Process creation
	event1 := map[string]interface{}{
		"CommandLine": "cmd.exe",
	}
	assert.Equal(t, "process_creation", detectCategory(event1))

	// Network connection
	event2 := map[string]interface{}{
		"SourceIp":      "192.168.1.100",
		"DestinationIp": "10.0.0.1",
	}
	assert.Equal(t, "network_connection", detectCategory(event2))

	// File event
	event3 := map[string]interface{}{
		"TargetFilename": "/etc/passwd",
	}
	assert.Equal(t, "file_event", detectCategory(event3))

	// Registry event
	event4 := map[string]interface{}{
		"TargetObject": "HKLM\\Software",
		"Details":      "test",
	}
	assert.Equal(t, "registry_event", detectCategory(event4))

	// DNS query
	event5 := map[string]interface{}{
		"QueryName": "example.com",
	}
	assert.Equal(t, "dns_query", detectCategory(event5))

	// Authentication
	event6 := map[string]interface{}{
		"LogonType": "2",
	}
	assert.Equal(t, "authentication", detectCategory(event6))

	// Proxy
	event7 := map[string]interface{}{
		"c-uri": "http://example.com",
	}
	assert.Equal(t, "proxy", detectCategory(event7))

	// PowerShell script
	event8 := map[string]interface{}{
		"ScriptBlockText": "Get-Process",
	}
	assert.Equal(t, "ps_script", detectCategory(event8))

	// Service creation
	event9 := map[string]interface{}{
		"ServiceName": "TestService",
	}
	assert.Equal(t, "service_creation", detectCategory(event9))

	// Image load
	event10 := map[string]interface{}{
		"ImageLoaded": "kernel32.dll",
	}
	assert.Equal(t, "image_load", detectCategory(event10))

	// Generic
	event11 := map[string]interface{}{
		"unknown": "field",
	}
	assert.Equal(t, "generic", detectCategory(event11))
}

// TestLoadFieldMappings tests loading mappings from YAML file
func TestLoadFieldMappings(t *testing.T) {
	// Create temporary YAML file
	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "mappings.yaml")
	yamlContent := `
windows_sysmon:
  User: User
  SourceIp: SourceIp
generic:
  src_ip: SourceIp
`

	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	require.NoError(t, err, "Should create temporary YAML file")

	mappings, err := LoadFieldMappings(yamlFile)
	require.NoError(t, err, "Should load mappings from YAML file")
	assert.NotNil(t, mappings)
	assert.NotNil(t, mappings.Mappings["windows_sysmon"])
	assert.Equal(t, "User", mappings.Mappings["windows_sysmon"]["User"])
	assert.NotNil(t, mappings.Mappings["generic"])
}

// TestLoadFieldMappings_PathTraversal tests path traversal prevention
func TestLoadFieldMappings_PathTraversal(t *testing.T) {
	_, err := LoadFieldMappings("../../../etc/passwd")
	require.Error(t, err, "Path traversal should be rejected")
	assert.Contains(t, err.Error(), "path traversal detected")
}

// TestFieldNormalizer_SaveMappings tests saving mappings to YAML file
func TestFieldNormalizer_SaveMappings(t *testing.T) {
	mappings := &FieldMappings{
		Mappings: map[string]map[string]string{
			"test_source": {
				"field1": "Field1",
				"field2": "Field2",
			},
		},
	}

	normalizer := NewFieldNormalizer(mappings)

	// Create temporary file
	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "saved_mappings.yaml")

	err := normalizer.SaveMappings(yamlFile)
	require.NoError(t, err, "Should save mappings to YAML file")

	// Verify file exists and can be loaded
	loadedMappings, err := LoadFieldMappings(yamlFile)
	require.NoError(t, err, "Should load saved mappings")
	assert.NotNil(t, loadedMappings.Mappings["test_source"])
	assert.Equal(t, "Field1", loadedMappings.Mappings["test_source"]["field1"])
}

// TestFieldNormalizer_ReloadMappings tests reloading mappings
func TestFieldNormalizer_ReloadMappings(t *testing.T) {
	// Create initial mappings file
	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "mappings.yaml")
	yamlContent := `
test_source:
  field1: Field1
`
	err := os.WriteFile(yamlFile, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Load initial mappings
	mappings, err := LoadFieldMappings(yamlFile)
	require.NoError(t, err)
	normalizer := NewFieldNormalizer(mappings)

	// Update YAML file
	yamlContent2 := `
test_source:
  field2: Field2
`
	err = os.WriteFile(yamlFile, []byte(yamlContent2), 0644)
	require.NoError(t, err)

	// Reload mappings
	err = normalizer.ReloadMappings(yamlFile)
	require.NoError(t, err, "Should reload mappings from file")

	// Verify updated mappings
	mapping := normalizer.GetMappingForSource("test_source")
	assert.NotNil(t, mapping)
	assert.Equal(t, "Field2", mapping["field2"])
	// Old mapping should be gone
	_, exists := mapping["field1"]
	assert.False(t, exists, "Old mapping field1 should not exist")
}

// TestFieldNormalizer_SaveMappings_NoMappings tests saving without mappings
func TestFieldNormalizer_SaveMappings_NoMappings(t *testing.T) {
	normalizer := NewFieldNormalizer(nil)

	tempDir := t.TempDir()
	yamlFile := filepath.Join(tempDir, "empty_mappings.yaml")

	err := normalizer.SaveMappings(yamlFile)
	require.Error(t, err, "Should error when saving with no mappings")
	assert.Contains(t, err.Error(), "no mappings to save")
}
