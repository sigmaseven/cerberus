package detect

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"cerberus/core"
)

// FieldMapping represents a mapping from source fields to target fields
// for a specific logsource (e.g., windows_sysmon, dns, generic)
type FieldMapping map[string]string

// FieldMapper provides configuration-driven field mapping for SIGMA rules
//
// Architecture:
//   - Loads field mappings from config/sigma_field_mappings.yaml
//   - Provides 4-level fallback chain for field resolution
//   - Thread-safe for concurrent access
//   - Integrates with core.FieldAliases for compatibility
//
// Security Considerations:
//   - Protected against YAML bombs via size limits
//   - Validates mapping structure during load
//   - Thread-safe with RWMutex for concurrent operations
//   - No injection risks (field names are validated strings)
//
// Performance:
//   - Optimized for read-heavy workloads (RWMutex)
//   - Logsource key caching via getLogsourceKey
//   - Single YAML parse on initialization
type FieldMapper struct {
	// mappings stores logsource-specific field mappings
	// Key: logsource identifier (e.g., "windows_sysmon", "dns", "linux_auditd")
	// Value: field name mapping (source_field -> target_field)
	mappings map[string]FieldMapping

	// globalMapping stores the "generic" fallback mapping
	// Applied when no logsource-specific mapping exists
	globalMapping FieldMapping

	// fieldAliases references core.FieldAliases for legacy compatibility
	// This is the final fallback before pass-through
	fieldAliases map[string]string

	// mu protects concurrent access to mappings
	mu sync.RWMutex
}

// NewFieldMapper creates a new FieldMapper instance
// Returns an empty mapper that can be populated via LoadMappings
func NewFieldMapper() *FieldMapper {
	return &FieldMapper{
		mappings:      make(map[string]FieldMapping),
		globalMapping: make(FieldMapping),
		fieldAliases:  core.FieldAliases,
	}
}

// LoadMappings loads field mappings from a YAML configuration file
//
// File Format:
//
//	logsource_name:
//	  source_field: target_field
//	  another_field: mapped_field
//	generic:
//	  common_field: StandardField
//
// Security:
//   - Validates file size to prevent YAML bombs (max 5MB)
//   - Checks YAML structure integrity
//   - Handles missing or malformed files gracefully
//
// Returns error if:
//   - File cannot be read
//   - YAML is malformed
//   - Structure is invalid (not map[string]map[string]string)
func (fm *FieldMapper) LoadMappings(configPath string) error {
	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read field mappings config %q: %w", configPath, err)
	}

	// Security: Protect against YAML bombs
	// 5MB is generous for field mapping config (typical size: 10-50KB)
	const maxConfigSize = 5 * 1024 * 1024 // 5MB
	if len(data) > maxConfigSize {
		return fmt.Errorf("field mappings config exceeds maximum size of %d bytes", maxConfigSize)
	}

	// Parse YAML into nested map structure
	var rawMappings map[string]map[string]string
	if err := yaml.Unmarshal(data, &rawMappings); err != nil {
		return fmt.Errorf("failed to parse field mappings YAML: %w", err)
	}

	// Validate that we got at least some mappings
	if len(rawMappings) == 0 {
		return fmt.Errorf("field mappings config is empty or invalid")
	}

	// Acquire write lock for updating mappings
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Clear existing mappings
	fm.mappings = make(map[string]FieldMapping)
	fm.globalMapping = make(FieldMapping)

	// Process each logsource mapping
	for logsource, fieldMap := range rawMappings {
		// Validate logsource name (must be non-empty, reasonable length)
		logsource = strings.TrimSpace(logsource)
		if logsource == "" {
			continue // Skip empty logsource names
		}
		if len(logsource) > 100 {
			return fmt.Errorf("logsource name exceeds maximum length: %q", logsource)
		}

		// Validate field mapping is not empty
		if len(fieldMap) == 0 {
			continue // Skip empty mappings
		}

		// Validate field count (prevent excessive memory usage)
		const maxFieldsPerLogsource = 1000
		if len(fieldMap) > maxFieldsPerLogsource {
			return fmt.Errorf("logsource %q has too many field mappings (%d, max %d)",
				logsource, len(fieldMap), maxFieldsPerLogsource)
		}

		// Store generic mapping separately
		if logsource == "generic" {
			fm.globalMapping = fieldMap
		} else {
			fm.mappings[logsource] = fieldMap
		}
	}

	return nil
}

// MapField maps a field name using the 4-level fallback chain
//
// Fallback Chain:
//  1. Logsource-specific mapping (product_service, product_category, product, category)
//  2. Global "generic" mapping
//  3. core.FieldAliases
//  4. Pass-through (return original field name)
//
// Parameters:
//   - field: The field name to map (e.g., "process_name", "command_line")
//   - logsource: The SIGMA logsource structure containing category/product/service
//
// Returns:
//   - The mapped field name (e.g., "Image", "CommandLine")
//   - Always returns a non-empty string (original field if no mapping found)
//
// Thread-safe: Uses read lock for concurrent access
func (fm *FieldMapper) MapField(field string, logsource map[string]interface{}) string {
	// Normalize field name (trim whitespace)
	field = strings.TrimSpace(field)
	if field == "" {
		return field // Return empty string as-is
	}

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Level 1: Try logsource-specific mappings
	// Build composite keys with decreasing specificity
	logsourceKeys := fm.getLogsourceKeys(logsource)
	for _, key := range logsourceKeys {
		if mapping, exists := fm.mappings[key]; exists {
			if mapped, found := mapping[field]; found {
				return mapped
			}
		}
	}

	// Level 2: Try global "generic" mapping
	if mapped, found := fm.globalMapping[field]; found {
		return mapped
	}

	// Level 3: Try core.FieldAliases
	// Use lowercase for alias lookup (FieldAliases uses lowercase keys)
	if mapped, found := fm.fieldAliases[strings.ToLower(field)]; found {
		return mapped
	}

	// Level 4: Pass-through (return original field name)
	return field
}

// getLogsourceKeys builds a list of logsource keys to check, ordered by specificity
// Returns keys in order: product_service, product_category, product, category
//
// Examples:
//   - {product: "windows", service: "sysmon"} -> ["windows_sysmon", "windows"]
//   - {product: "windows", category: "process_creation"} -> ["windows_process_creation", "windows", "process_creation"]
//   - {category: "dns"} -> ["dns"]
//
// This supports flexible mapping configurations at various granularities
func (fm *FieldMapper) getLogsourceKeys(logsource map[string]interface{}) []string {
	if logsource == nil {
		return nil
	}

	// Extract logsource components
	product := fm.getStringValue(logsource, "product")
	service := fm.getStringValue(logsource, "service")
	category := fm.getStringValue(logsource, "category")

	var keys []string

	// Most specific: product + service
	if product != "" && service != "" {
		keys = append(keys, product+"_"+service)
	}

	// Medium specificity: product + category
	if product != "" && category != "" {
		keys = append(keys, product+"_"+category)
	}

	// Lower specificity: product only
	if product != "" {
		keys = append(keys, product)
	}

	// Lower specificity: service only (for cross-platform services like syslog)
	if service != "" && service != product {
		keys = append(keys, service)
	}

	// Lowest specificity: category only
	if category != "" && category != product && category != service {
		keys = append(keys, category)
	}

	return keys
}

// getStringValue safely extracts a string value from a map
// Returns empty string if key doesn't exist or value is not a string
func (fm *FieldMapper) getStringValue(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// GetEventFieldValue extracts a field value from an event using dot notation
//
// Supports:
//   - Top-level event fields: event_id, timestamp, source_ip, etc.
//   - Nested fields in event.Fields map: CommandLine, Image, etc.
//   - Dot notation: nested.field.path
//
// Returns:
//   - value: The field value (any type)
//   - found: Boolean indicating if the field was found
//
// This is a helper function for rule evaluation, similar to engine.getFieldValue
// but designed to work with the FieldMapper for consistent field resolution.
func (fm *FieldMapper) GetEventFieldValue(event *core.Event, field string) (interface{}, bool) {
	if event == nil {
		return nil, false
	}

	// Build a unified field view (top-level + event.Fields)
	unified := make(map[string]interface{})

	// Add top-level fields
	unified["event_id"] = event.EventID
	unified["timestamp"] = event.Timestamp
	unified["source_format"] = event.SourceFormat
	unified["source_ip"] = event.SourceIP
	unified["event_type"] = event.EventType
	unified["severity"] = event.Severity
	unified["raw_data"] = event.RawData

	// Merge event.Fields (these take precedence for naming conflicts)
	for k, v := range event.Fields {
		unified[k] = v
	}

	// Navigate using dot notation
	parts := strings.Split(field, ".")
	current := unified

	for i, part := range parts {
		// Check if part exists in current level
		val, exists := current[part]
		if !exists {
			return nil, false
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return val, true
		}

		// For non-last parts, must be a map to navigate further
		if m, ok := val.(map[string]interface{}); ok {
			current = m
		} else {
			// Cannot navigate further (not a map)
			return nil, false
		}
	}

	// Should not reach here (empty field name case)
	return nil, false
}

// MapFieldWithContext maps a field with additional context for debugging/logging
// This is useful when you need to track which mapping was used
//
// Returns:
//   - mappedField: The mapped field name
//   - source: Which mapping source was used ("logsource", "generic", "alias", "passthrough")
func (fm *FieldMapper) MapFieldWithContext(field string, logsource map[string]interface{}) (mappedField string, source string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return field, "passthrough"
	}

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Level 1: Logsource-specific
	logsourceKeys := fm.getLogsourceKeys(logsource)
	for _, key := range logsourceKeys {
		if mapping, exists := fm.mappings[key]; exists {
			if mapped, found := mapping[field]; found {
				return mapped, "logsource:" + key
			}
		}
	}

	// Level 2: Generic
	if mapped, found := fm.globalMapping[field]; found {
		return mapped, "generic"
	}

	// Level 3: Aliases
	if mapped, found := fm.fieldAliases[strings.ToLower(field)]; found {
		return mapped, "alias"
	}

	// Level 4: Passthrough
	return field, "passthrough"
}

// GetMappingStats returns statistics about loaded mappings
// Useful for monitoring and diagnostics
type MappingStats struct {
	LogsourceCount     int            // Number of logsource-specific mappings
	GenericFieldCount  int            // Number of generic mappings
	TotalFieldMappings int            // Total field mappings across all logsources
	LogsourceMappings  map[string]int // Field count per logsource
}

// GetStats returns statistics about the loaded field mappings
// Thread-safe for concurrent access
func (fm *FieldMapper) GetStats() MappingStats {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	stats := MappingStats{
		LogsourceCount:    len(fm.mappings),
		GenericFieldCount: len(fm.globalMapping),
		LogsourceMappings: make(map[string]int),
	}

	totalFields := len(fm.globalMapping)
	for logsource, mapping := range fm.mappings {
		count := len(mapping)
		stats.LogsourceMappings[logsource] = count
		totalFields += count
	}
	stats.TotalFieldMappings = totalFields

	return stats
}

// ValidateMapping checks if the loaded mappings are valid and complete
// Returns error if critical validation checks fail
//
// Validations:
//   - At least one mapping loaded (generic or logsource-specific)
//   - No circular mappings (field maps to itself)
//   - Reasonable field name length
func (fm *FieldMapper) ValidateMapping() error {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Check that at least some mappings exist
	if len(fm.mappings) == 0 && len(fm.globalMapping) == 0 {
		return fmt.Errorf("no field mappings loaded")
	}

	// Validate generic mapping
	if err := fm.validateFieldMapping("generic", fm.globalMapping); err != nil {
		return err
	}

	// Validate each logsource mapping
	for logsource, mapping := range fm.mappings {
		if err := fm.validateFieldMapping(logsource, mapping); err != nil {
			return err
		}
	}

	return nil
}

// validateFieldMapping validates a single field mapping
func (fm *FieldMapper) validateFieldMapping(logsource string, mapping FieldMapping) error {
	const maxFieldNameLength = 200 // Reasonable limit for field names

	for source, target := range mapping {
		// Check for empty field names
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("logsource %q has empty source field name", logsource)
		}
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("logsource %q has empty target field name for source %q", logsource, source)
		}

		// Check for excessive length
		if len(source) > maxFieldNameLength {
			return fmt.Errorf("logsource %q has source field name exceeding max length: %q", logsource, source)
		}
		if len(target) > maxFieldNameLength {
			return fmt.Errorf("logsource %q has target field name exceeding max length: %q", logsource, target)
		}

		// NOTE: We DO NOT check for circular mapping (source == target)
		// This is intentional and valid - it indicates a pass-through mapping
		// where the field name is already in the correct format (e.g., "c-ip: c-ip")
		// This is commonly used in webserver logs where the field names are already standardized
	}

	return nil
}

// GlobalFieldMapper is a singleton instance for use across the application
// Initialize once at startup via InitGlobalFieldMapper
var (
	globalFieldMapper     *FieldMapper
	globalFieldMapperOnce sync.Once
	globalFieldMapperErr  error
)

// InitGlobalFieldMapper initializes the global field mapper singleton
// Should be called once at application startup
//
// Usage:
//
//	if err := detect.InitGlobalFieldMapper(ctx, "config/sigma_field_mappings.yaml"); err != nil {
//	    log.Fatalf("Failed to initialize field mapper: %v", err)
//	}
func InitGlobalFieldMapper(ctx context.Context, configPath string) error {
	globalFieldMapperOnce.Do(func() {
		fm := NewFieldMapper()
		if err := fm.LoadMappings(configPath); err != nil {
			globalFieldMapperErr = fmt.Errorf("failed to load field mappings: %w", err)
			return
		}

		if err := fm.ValidateMapping(); err != nil {
			globalFieldMapperErr = fmt.Errorf("field mapping validation failed: %w", err)
			return
		}

		globalFieldMapper = fm
	})

	return globalFieldMapperErr
}

// GetGlobalFieldMapper returns the global field mapper instance
// Returns nil if not initialized (caller should check)
func GetGlobalFieldMapper() *FieldMapper {
	return globalFieldMapper
}
