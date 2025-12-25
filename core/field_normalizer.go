package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// FieldMappings holds all field mapping configurations
type FieldMappings struct {
	Mappings map[string]map[string]string `yaml:",inline"`
	mu       sync.RWMutex
}

// FieldNormalizer normalizes event fields to SIGMA standard
type FieldNormalizer struct {
	mappings *FieldMappings
}

// LoadFieldMappings loads SIGMA field mappings from YAML file
func LoadFieldMappings(configPath string) (*FieldMappings, error) {
	// SECURITY: Validate file path to prevent path traversal attacks
	cleanPath := filepath.Clean(configPath)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path: path traversal detected")
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read field mappings file: %w", err)
	}

	var mappings FieldMappings
	if err := yaml.Unmarshal(data, &mappings.Mappings); err != nil {
		return nil, fmt.Errorf("failed to parse field mappings YAML: %w", err)
	}

	return &mappings, nil
}

// NewFieldNormalizer creates a new field normalizer
func NewFieldNormalizer(mappings *FieldMappings) *FieldNormalizer {
	return &FieldNormalizer{
		mappings: mappings,
	}
}

// NormalizeEvent normalizes event fields to SIGMA standard
// Returns a new map with SIGMA field names while preserving original fields
func (n *FieldNormalizer) NormalizeEvent(event map[string]interface{}, logSource string) map[string]interface{} {
	if n.mappings == nil {
		return event
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	// Get mapping for this log source
	mapping := n.mappings.Mappings[logSource]
	if mapping == nil {
		// Try generic mapping as fallback
		mapping = n.mappings.Mappings["generic"]
		if mapping == nil {
			return event
		}
	}

	// Create normalized event (preserves original + adds SIGMA fields)
	normalized := make(map[string]interface{})

	// Copy original fields to _raw namespace for preservation
	originalFields := make(map[string]interface{})
	for k, v := range event {
		originalFields[k] = v
		// Also keep in main namespace initially
		normalized[k] = v
	}
	normalized["_raw"] = originalFields

	// Apply field mappings
	for rawField, sigmaField := range mapping {
		// Handle nested fields (e.g., "fields.user" -> value)
		value := getNestedField(event, rawField)
		if value != nil {
			// Set SIGMA field
			normalized[sigmaField] = value

			// Also handle special cases
			switch sigmaField {
			case "Hashes":
				// Normalize hash format: "MD5=...,SHA256=..." or individual fields
				normalized[sigmaField] = normalizeHashes(value)
			case "EventTime":
				// Ensure timestamp is in ISO format
				normalized[sigmaField] = normalizeTimestamp(value)
			}
		}
	}

	// Auto-detect and set log source category if not already set
	if _, exists := normalized["Category"]; !exists {
		normalized["Category"] = detectCategory(normalized)
	}

	return normalized
}

// NormalizeEventInPlace normalizes fields in-place (modifies the original map)
// DEPRECATED: Use NormalizeToSIGMA for cleaner SIGMA-only output
func (n *FieldNormalizer) NormalizeEventInPlace(event map[string]interface{}, logSource string) {
	if n.mappings == nil {
		return
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	mapping := n.mappings.Mappings[logSource]
	if mapping == nil {
		mapping = n.mappings.Mappings["generic"]
		if mapping == nil {
			return
		}
	}

	// Apply mappings
	for rawField, sigmaField := range mapping {
		value := getNestedField(event, rawField)
		if value != nil {
			event[sigmaField] = value

			// Special handling
			switch sigmaField {
			case "Hashes":
				event[sigmaField] = normalizeHashes(value)
			case "EventTime":
				event[sigmaField] = normalizeTimestamp(value)
			}
		}
	}

	// Auto-detect category
	if _, exists := event["Category"]; !exists {
		event["Category"] = detectCategory(event)
	}
}

// NormalizeToSIGMA converts event fields to SIGMA-standard field names only.
// Original field names are replaced with their SIGMA equivalents.
// Fields without a mapping are passed through unchanged.
// This is the preferred method for ingestion-time normalization.
func (n *FieldNormalizer) NormalizeToSIGMA(event map[string]interface{}, logSource string) map[string]interface{} {
	if n.mappings == nil || event == nil {
		return event
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	// Get mapping for this log source, fallback to generic
	mapping := n.mappings.Mappings[logSource]
	if mapping == nil {
		mapping = n.mappings.Mappings["generic"]
	}

	// Build reverse mapping: original field name -> SIGMA field name
	reverseMapping := make(map[string]string)
	if mapping != nil {
		for rawField, sigmaField := range mapping {
			reverseMapping[rawField] = sigmaField
		}
	}

	// Create normalized result with SIGMA field names
	normalized := make(map[string]interface{})

	for originalField, value := range event {
		// Check if this field has a SIGMA mapping
		if sigmaField, hasMmapping := reverseMapping[originalField]; hasMmapping {
			// Use SIGMA field name
			// Special handling for certain field types
			switch sigmaField {
			case "Hashes":
				normalized[sigmaField] = normalizeHashes(value)
			case "EventTime":
				normalized[sigmaField] = normalizeTimestamp(value)
			default:
				normalized[sigmaField] = value
			}
		} else {
			// No mapping - pass through with original name
			// But check if the original name IS a SIGMA field (already normalized)
			normalized[originalField] = value
		}
	}

	// Auto-detect category if not present
	if _, exists := normalized["Category"]; !exists {
		normalized["Category"] = detectCategory(normalized)
	}

	return normalized
}

// getNestedField retrieves a value from a nested field path (e.g., "fields.user")
func getNestedField(data map[string]interface{}, fieldPath string) interface{} {
	parts := strings.Split(fieldPath, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - return the value
			return current[part]
		}

		// Navigate deeper
		next, ok := current[part]
		if !ok {
			return nil
		}

		// Check if next level is a map
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil
		}
		current = nextMap
	}

	return nil
}

// normalizeHashes converts various hash formats to SIGMA format
func normalizeHashes(value interface{}) string {
	str, ok := value.(string)
	if !ok {
		return fmt.Sprintf("%v", value)
	}

	// If already in SIGMA format (MD5=...,SHA256=...), return as-is
	if strings.Contains(str, "=") {
		return str
	}

	// If it's just a hash value, try to detect type by length
	str = strings.TrimSpace(str)
	switch len(str) {
	case 32:
		// MD5
		return "MD5=" + strings.ToUpper(str)
	case 40:
		// SHA1
		return "SHA1=" + strings.ToUpper(str)
	case 64:
		// SHA256
		return "SHA256=" + strings.ToUpper(str)
	default:
		// Unknown format, return as-is
		return str
	}
}

// normalizeTimestamp ensures timestamp is in ISO 8601 format
func normalizeTimestamp(value interface{}) string {
	str, ok := value.(string)
	if !ok {
		return fmt.Sprintf("%v", value)
	}
	// For now, return as-is. Could add more sophisticated parsing here.
	return str
}

// detectCategory auto-detects SIGMA category based on fields present
func detectCategory(event map[string]interface{}) string {
	// Check for process creation indicators
	if hasField(event, "CommandLine") || hasField(event, "ParentImage") {
		return "process_creation"
	}

	// Check for network connection indicators
	if hasField(event, "SourceIp") && hasField(event, "DestinationIp") {
		return "network_connection"
	}

	// Check for file event indicators
	if hasField(event, "TargetFilename") {
		return "file_event"
	}

	// Check for registry indicators
	if hasField(event, "TargetObject") && hasField(event, "Details") {
		return "registry_event"
	}

	// Check for DNS indicators
	if hasField(event, "QueryName") {
		return "dns_query"
	}

	// Check for authentication indicators
	if hasField(event, "LogonType") || hasField(event, "AuthenticationPackageName") {
		return "authentication"
	}

	// Check for web/proxy indicators
	if hasField(event, "c-uri") || hasField(event, "cs-method") {
		return "proxy"
	}

	// Check for PowerShell indicators
	if hasField(event, "ScriptBlockText") {
		return "ps_script"
	}

	// Check for service indicators
	if hasField(event, "ServiceName") || hasField(event, "ServiceFileName") {
		return "service_creation"
	}

	// Check for driver/image load indicators
	if hasField(event, "ImageLoaded") {
		return "image_load"
	}

	// Default to generic
	return "generic"
}

// hasField checks if a field exists in the event
func hasField(event map[string]interface{}, field string) bool {
	_, exists := event[field]
	return exists
}

// GetMappingForSource returns the field mapping for a specific log source
func (n *FieldNormalizer) GetMappingForSource(logSource string) map[string]string {
	if n.mappings == nil {
		return nil
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	mapping := n.mappings.Mappings[logSource]
	if mapping == nil {
		return n.mappings.Mappings["generic"]
	}
	return mapping
}

// DetectLogSource attempts to detect the log source type from event fields
func DetectLogSource(event map[string]interface{}) string {
	// Check for Sysmon
	if channel, ok := event["channel"].(string); ok {
		if strings.Contains(strings.ToLower(channel), "sysmon") {
			return "windows_sysmon"
		}
		if strings.Contains(strings.ToLower(channel), "security") {
			return "windows_security"
		}
	}

	// Check for provider
	if provider, ok := event["provider"].(string); ok {
		if strings.Contains(strings.ToLower(provider), "sysmon") {
			return "windows_sysmon"
		}
		if strings.Contains(strings.ToLower(provider), "security") {
			return "windows_security"
		}
	}

	// Check for PowerShell
	if _, ok := event["script_block_text"]; ok {
		return "powershell"
	}

	// Check for web server (W3C format)
	if _, ok := event["cs-method"]; ok {
		return "webserver"
	}

	// Check for Linux auditd
	if eventType, ok := event["type"].(string); ok {
		if strings.HasPrefix(eventType, "SYSCALL") || strings.HasPrefix(eventType, "EXECVE") {
			return "linux_auditd"
		}
	}

	// Check for firewall
	if _, ok := event["action"]; ok {
		if _, ok2 := event["direction"]; ok2 {
			return "firewall"
		}
	}

	// Check for DNS
	if _, ok := event["query"]; ok {
		return "dns"
	}

	// Check for cloud providers
	if _, ok := event["user_identity.user_name"]; ok {
		return "aws_cloudtrail"
	}
	if _, ok := event["principal_email"]; ok {
		return "gcp_audit"
	}
	if _, ok := event["user_principal_name"]; ok {
		return "azure_ad"
	}

	// Default to generic
	return "generic"
}

// GetAllMappings returns all field mappings (for API/UI access)
func (n *FieldNormalizer) GetAllMappings() map[string]map[string]string {
	if n.mappings == nil {
		return make(map[string]map[string]string)
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	// Create a deep copy to prevent external modifications
	result := make(map[string]map[string]string)
	for source, mapping := range n.mappings.Mappings {
		sourceCopy := make(map[string]string)
		for k, v := range mapping {
			sourceCopy[k] = v
		}
		result[source] = sourceCopy
	}
	return result
}

// UpdateMapping updates the field mapping for a specific log source
func (n *FieldNormalizer) UpdateMapping(logSource string, mapping map[string]string) {
	if n.mappings == nil {
		n.mappings = &FieldMappings{
			Mappings: make(map[string]map[string]string),
		}
	}

	n.mappings.mu.Lock()
	defer n.mappings.mu.Unlock()

	n.mappings.Mappings[logSource] = mapping
}

// DeleteMapping removes the field mapping for a specific log source
func (n *FieldNormalizer) DeleteMapping(logSource string) {
	if n.mappings == nil {
		return
	}

	n.mappings.mu.Lock()
	defer n.mappings.mu.Unlock()

	delete(n.mappings.Mappings, logSource)
}

// SaveMappings saves current mappings to a YAML file
func (n *FieldNormalizer) SaveMappings(configPath string) error {
	if n.mappings == nil {
		return fmt.Errorf("no mappings to save")
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	data, err := yaml.Marshal(n.mappings.Mappings)
	if err != nil {
		return fmt.Errorf("failed to marshal mappings to YAML: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write mappings file: %w", err)
	}

	return nil
}

// ReloadMappings reloads mappings from the YAML file
func (n *FieldNormalizer) ReloadMappings(configPath string) error {
	newMappings, err := LoadFieldMappings(configPath)
	if err != nil {
		return err
	}

	// Replace mappings atomically
	if n.mappings == nil {
		n.mappings = newMappings
	} else {
		n.mappings.mu.Lock()
		n.mappings.Mappings = newMappings.Mappings
		n.mappings.mu.Unlock()
	}

	return nil
}

// ListLogSources returns a list of all configured log source types
func (n *FieldNormalizer) ListLogSources() []string {
	if n.mappings == nil {
		return []string{}
	}

	n.mappings.mu.RLock()
	defer n.mappings.mu.RUnlock()

	sources := make([]string, 0, len(n.mappings.Mappings))
	for source := range n.mappings.Mappings {
		sources = append(sources, source)
	}
	return sources
}
