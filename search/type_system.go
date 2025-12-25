package search

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FieldType represents the data type of a field
type FieldType string

const (
	FieldTypeString  FieldType = "string"
	FieldTypeInt     FieldType = "int"
	FieldTypeFloat   FieldType = "float"
	FieldTypeBool    FieldType = "bool"
	FieldTypeTime    FieldType = "timestamp"
	FieldTypeArray   FieldType = "array"
	FieldTypeUnknown FieldType = "unknown"
)

// FieldTypeRegistry maps field names to their types
// TASK 4.4: Field type detection and automatic type casting
type FieldTypeRegistry struct {
	// Direct field mappings
	fieldTypes map[string]FieldType
	// Common numeric field patterns (e.g., fields ending with "_count", "_size")
	numericPatterns []string
	// Common timestamp field patterns
	timestampPatterns []string
}

// NewFieldTypeRegistry creates a new field type registry with default mappings
func NewFieldTypeRegistry() *FieldTypeRegistry {
	registry := &FieldTypeRegistry{
		fieldTypes: make(map[string]FieldType),
		numericPatterns: []string{
			"_count", "_size", "_bytes", "_port", "_id",
			"count", "size", "bytes", "port", "id",
		},
		timestampPatterns: []string{
			"timestamp", "time", "_at", "_date", "@timestamp",
		},
	}

	// Register known fields from ClickHouse schema
	registry.registerSchemaFields()

	return registry
}

// registerSchemaFields registers fields from the ClickHouse events table schema
func (r *FieldTypeRegistry) registerSchemaFields() {
	// Core event fields
	r.fieldTypes["event_id"] = FieldTypeString
	r.fieldTypes["id"] = FieldTypeString
	r.fieldTypes["timestamp"] = FieldTypeTime
	r.fieldTypes["@timestamp"] = FieldTypeTime
	r.fieldTypes["ingested_at"] = FieldTypeTime
	r.fieldTypes["listener_id"] = FieldTypeString
	r.fieldTypes["listener_name"] = FieldTypeString
	r.fieldTypes["source"] = FieldTypeString
	r.fieldTypes["source_format"] = FieldTypeString
	r.fieldTypes["raw_data"] = FieldTypeString
	r.fieldTypes["raw_log"] = FieldTypeString
	r.fieldTypes["fields"] = FieldTypeString

	// Common event fields (from Fields JSON)
	r.fieldTypes["source_ip"] = FieldTypeString
	r.fieldTypes["SourceIP"] = FieldTypeString
	r.fieldTypes["dest_ip"] = FieldTypeString
	r.fieldTypes["dest_port"] = FieldTypeInt
	r.fieldTypes["port"] = FieldTypeInt
	r.fieldTypes["source_port"] = FieldTypeInt
	r.fieldTypes["severity"] = FieldTypeString
	r.fieldTypes["event_type"] = FieldTypeString
	r.fieldTypes["message"] = FieldTypeString
	r.fieldTypes["bytes_sent"] = FieldTypeInt
	r.fieldTypes["bytes_received"] = FieldTypeInt
	r.fieldTypes["bytes"] = FieldTypeInt
	r.fieldTypes["count"] = FieldTypeInt
}

// DetectFieldType detects the type of a field using registry and heuristics
// TASK 4.4: Field type detection using schema introspection or type inference
func (r *FieldTypeRegistry) DetectFieldType(field string) FieldType {
	// Normalize field name (lowercase, remove dots for lookup)
	normalized := strings.ToLower(field)

	// Direct lookup
	if fieldType, ok := r.fieldTypes[normalized]; ok {
		return fieldType
	}

	// Handle nested fields (e.g., "user.name" -> check "user.name" and "name")
	parts := strings.Split(normalized, ".")
	if len(parts) > 1 {
		// Check nested field name (e.g., "name")
		if fieldType, ok := r.fieldTypes[parts[len(parts)-1]]; ok {
			return fieldType
		}
	}

	// Pattern-based detection for numeric fields
	fieldLower := strings.ToLower(field)
	for _, pattern := range r.numericPatterns {
		if strings.Contains(fieldLower, pattern) || strings.HasSuffix(fieldLower, pattern) {
			return FieldTypeInt
		}
	}

	// Pattern-based detection for timestamp fields
	for _, pattern := range r.timestampPatterns {
		if strings.Contains(fieldLower, pattern) || strings.HasSuffix(fieldLower, pattern) {
			return FieldTypeTime
		}
	}

	// Default to string for unknown fields
	return FieldTypeUnknown
}

// CastValue casts a value to the target type
// TASK 4.4: Automatic type casting to ensure correct SQL comparisons
func (r *FieldTypeRegistry) CastValue(value interface{}, targetType FieldType) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	switch targetType {
	case FieldTypeString:
		return castToString(value)

	case FieldTypeInt:
		return castToInt(value)

	case FieldTypeFloat:
		return castToFloat(value)

	case FieldTypeBool:
		return castToBool(value)

	case FieldTypeTime:
		return castToTime(value)

	case FieldTypeArray:
		return castToArray(value)

	case FieldTypeUnknown:
		// For unknown types, try to infer from value
		return value, nil

	default:
		return value, nil
	}
}

// GetSQLCast generates appropriate SQL cast expression for ClickHouse
// TASK 4.4: Generate SQL casts (toInt64(), toFloat64(), toString(), toDateTime())
func (r *FieldTypeRegistry) GetSQLCast(fieldRef string, targetType FieldType) string {
	switch targetType {
	case FieldTypeInt:
		return fmt.Sprintf("toInt64OrNull(%s)", fieldRef)
	case FieldTypeFloat:
		return fmt.Sprintf("toFloat64OrNull(%s)", fieldRef)
	case FieldTypeString:
		return fmt.Sprintf("toString(%s)", fieldRef)
	case FieldTypeTime:
		return fmt.Sprintf("toDateTimeOrNull(%s)", fieldRef)
	case FieldTypeBool:
		return fmt.Sprintf("toUInt8OrNull(%s)", fieldRef)
	default:
		return fieldRef // No cast needed
	}
}

// ShouldCast determines if a field should be cast based on operator and value type
// TASK 4.4: Handle type mismatches gracefully with automatic casting
func (r *FieldTypeRegistry) ShouldCast(field string, operator string, value interface{}) bool {
	fieldType := r.DetectFieldType(field)

	// Never cast for string operators (contains, startswith, endswith, matches)
	if operator == "contains" || operator == "startswith" || operator == "endswith" || operator == "matches" || operator == "~=" {
		return false
	}

	// Never cast for exists/not exists
	if operator == "exists" || operator == "not exists" {
		return false
	}

	// For comparison operators (>, <, >=, <=), cast if field type is numeric and value is string
	if operator == ">" || operator == "<" || operator == ">=" || operator == "<=" {
		if fieldType == FieldTypeInt || fieldType == FieldTypeFloat {
			// Check if value is a numeric string that could be parsed
			if str, ok := value.(string); ok {
				if _, err := strconv.ParseFloat(str, 64); err == nil {
					return true // Can cast numeric string to number
				}
			}
			// Value is already numeric, no cast needed
			return false
		}
	}

	// For equals/not_equals with numeric fields, cast if value is string
	if operator == "=" || operator == "equals" || operator == "!=" || operator == "not_equals" {
		if fieldType == FieldTypeInt || fieldType == FieldTypeFloat {
			if _, ok := value.(string); ok {
				// Try to parse as number
				if _, err := strconv.ParseFloat(value.(string), 64); err == nil {
					return true
				}
			}
		}
	}

	return false
}

// Helper functions for type casting

func castToString(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v), nil
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v), nil
	case float32, float64:
		return fmt.Sprintf("%g", v), nil
	case bool:
		return fmt.Sprintf("%t", v), nil
	case time.Time:
		return v.Format(time.RFC3339), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

func castToInt(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		if v > 9223372036854775807 { // Max int64
			return 0, fmt.Errorf("value %d exceeds int64 max", v)
		}
		return int64(v), nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot convert string '%s' to int: %w", v, err)
		}
		return parsed, nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

func castToFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float32:
		return float64(v), nil
	case float64:
		return v, nil
	case int, int8, int16, int32, int64:
		return float64(reflectToInt64(v)), nil
	case uint, uint8, uint16, uint32, uint64:
		return float64(reflectToUint64(v)), nil
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot convert string '%s' to float: %w", v, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float", value)
	}
}

func castToBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case int, int8, int16, int32, int64:
		return reflectToInt64(v) != 0, nil
	case uint, uint8, uint16, uint32, uint64:
		return reflectToUint64(v) != 0, nil
	case float32:
		return v != 0.0, nil
	case float64:
		return v != 0.0, nil
	case string:
		str := strings.ToLower(strings.TrimSpace(v))
		if str == "true" || str == "1" || str == "yes" || str == "on" {
			return true, nil
		}
		if str == "false" || str == "0" || str == "no" || str == "off" {
			return false, nil
		}
		return false, fmt.Errorf("cannot convert string '%s' to bool", v)
	default:
		return false, fmt.Errorf("cannot convert %T to bool", value)
	}
}

func castToTime(value interface{}) (time.Time, error) {
	switch v := value.(type) {
	case time.Time:
		return v, nil
	case string:
		// Try various time formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, v); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("cannot parse time string '%s'", v)
	case int64:
		// Unix timestamp
		return time.Unix(v, 0), nil
	case float64:
		// Unix timestamp with fractional seconds
		sec := int64(v)
		nsec := int64((v - float64(sec)) * 1e9)
		return time.Unix(sec, nsec), nil
	default:
		return time.Time{}, fmt.Errorf("cannot convert %T to time", value)
	}
}

func castToArray(value interface{}) ([]interface{}, error) {
	switch v := value.(type) {
	case []interface{}:
		return v, nil
	case []string:
		result := make([]interface{}, len(v))
		for i, s := range v {
			result[i] = s
		}
		return result, nil
	case []int:
		result := make([]interface{}, len(v))
		for i, n := range v {
			result[i] = n
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot convert %T to array", value)
	}
}

// Helper to convert interface{} to int64 using reflection
func reflectToInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int:
		return int64(val)
	case int8:
		return int64(val)
	case int16:
		return int64(val)
	case int32:
		return int64(val)
	case int64:
		return val
	default:
		return 0
	}
}

// Helper to convert interface{} to uint64 using reflection
func reflectToUint64(v interface{}) uint64 {
	switch val := v.(type) {
	case uint:
		return uint64(val)
	case uint8:
		return uint64(val)
	case uint16:
		return uint64(val)
	case uint32:
		return uint64(val)
	case uint64:
		return val
	default:
		return 0
	}
}
