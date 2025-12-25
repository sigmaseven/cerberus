package search

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFieldTypeRegistry_DetectFieldType tests field type detection
// TASK 4.4: Type detection tests
func TestFieldTypeRegistry_DetectFieldType(t *testing.T) {
	registry := NewFieldTypeRegistry()

	tests := []struct {
		name     string
		field    string
		expected FieldType
	}{
		{"timestamp field", "timestamp", FieldTypeTime},
		{"@timestamp field", "@timestamp", FieldTypeTime},
		{"event_id field", "event_id", FieldTypeString},
		{"source_ip field", "source_ip", FieldTypeString},
		{"port field", "port", FieldTypeInt},
		{"dest_port field", "dest_port", FieldTypeInt},
		{"bytes_sent field", "bytes_sent", FieldTypeInt},
		{"nested timestamp", "user.created_at", FieldTypeTime},
		{"nested port", "connection.port", FieldTypeInt},
		{"unknown field", "unknown_field", FieldTypeUnknown},
		{"numeric pattern", "event_count", FieldTypeInt},
		{"timestamp pattern", "updated_at", FieldTypeTime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fieldType := registry.DetectFieldType(tt.field)
			assert.Equal(t, tt.expected, fieldType, "Field type mismatch for %s", tt.field)
		})
	}
}

// TestFieldTypeRegistry_CastValue tests type casting
// TASK 4.4: Type casting tests
func TestFieldTypeRegistry_CastValue(t *testing.T) {
	registry := NewFieldTypeRegistry()

	tests := []struct {
		name        string
		value       interface{}
		targetType  FieldType
		expected    interface{}
		shouldError bool
	}{
		// String casting
		{"string to string", "test", FieldTypeString, "test", false},
		{"int to string", 42, FieldTypeString, "42", false},
		{"float to string", 3.14, FieldTypeString, "3.14", false},
		{"bool to string", true, FieldTypeString, "true", false},

		// Int casting
		{"int to int", 42, FieldTypeInt, int64(42), false},
		{"string to int", "42", FieldTypeInt, int64(42), false},
		{"float to int", 3.14, FieldTypeInt, int64(3), false},
		{"bool to int", true, FieldTypeInt, int64(1), false},
		{"invalid string to int", "abc", FieldTypeInt, nil, true},

		// Float casting
		{"float to float", 3.14, FieldTypeFloat, 3.14, false},
		{"int to float", 42, FieldTypeFloat, 42.0, false},
		{"string to float", "3.14", FieldTypeFloat, 3.14, false},
		{"invalid string to float", "abc", FieldTypeFloat, nil, true},

		// Bool casting
		{"bool to bool", true, FieldTypeBool, true, false},
		{"int to bool", 1, FieldTypeBool, true, false},
		{"int zero to bool", 0, FieldTypeBool, false, false},
		{"string true to bool", "true", FieldTypeBool, true, false},
		{"string false to bool", "false", FieldTypeBool, false, false},
		{"string 1 to bool", "1", FieldTypeBool, true, false},
		{"invalid string to bool", "maybe", FieldTypeBool, nil, true},

		// Time casting
		{"time to time", time.Now(), FieldTypeTime, time.Time{}, false}, // Can't compare exact times
		{"RFC3339 string to time", "2025-01-16T12:00:00Z", FieldTypeTime, time.Time{}, false},
		{"invalid string to time", "not a time", FieldTypeTime, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := registry.CastValue(tt.value, tt.targetType)

			if tt.shouldError {
				assert.Error(t, err, "Expected error for %s", tt.name)
			} else {
				require.NoError(t, err, "Unexpected error for %s", tt.name)
				if tt.targetType == FieldTypeTime {
					// For time, just check it's a time.Time
					_, ok := result.(time.Time)
					assert.True(t, ok, "Result should be time.Time for %s", tt.name)
				} else {
					assert.Equal(t, tt.expected, result, "Cast result mismatch for %s", tt.name)
				}
			}
		})
	}
}

// TestFieldTypeRegistry_GetSQLCast tests SQL cast generation
// TASK 4.4: SQL cast generation tests
func TestFieldTypeRegistry_GetSQLCast(t *testing.T) {
	registry := NewFieldTypeRegistry()

	tests := []struct {
		name      string
		fieldRef  string
		fieldType FieldType
		expected  string
	}{
		{"int cast", "field", FieldTypeInt, "toInt64OrNull(field)"},
		{"float cast", "field", FieldTypeFloat, "toFloat64OrNull(field)"},
		{"string cast", "field", FieldTypeString, "toString(field)"},
		{"time cast", "field", FieldTypeTime, "toDateTimeOrNull(field)"},
		{"bool cast", "field", FieldTypeBool, "toUInt8OrNull(field)"},
		{"unknown cast", "field", FieldTypeUnknown, "field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			castSQL := registry.GetSQLCast(tt.fieldRef, tt.fieldType)
			assert.Equal(t, tt.expected, castSQL, "SQL cast mismatch for %s", tt.name)
		})
	}
}

// TestFieldTypeRegistry_ShouldCast tests casting decision logic
// TASK 4.4: Type mismatch handling tests
func TestFieldTypeRegistry_ShouldCast(t *testing.T) {
	registry := NewFieldTypeRegistry()

	tests := []struct {
		name     string
		field    string
		operator string
		value    interface{}
		expected bool
	}{
		{"numeric field with numeric value", "port", ">", 1024, false},
		{"numeric field with string numeric value", "port", ">", "1024", true},
		{"numeric field with string non-numeric", "port", ">", "abc", false},
		{"string field with string value", "source_ip", "=", "192.168.1.1", false},
		{"contains operator (no cast)", "message", "contains", "error", false},
		{"exists operator (no cast)", "source_ip", "exists", nil, false},
		{"equals with numeric string", "port", "=", "443", true},
		{"equals with numeric value", "port", "=", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldCast := registry.ShouldCast(tt.field, tt.operator, tt.value)
			assert.Equal(t, tt.expected, shouldCast, "Casting decision mismatch for %s", tt.name)
		})
	}
}

// TestFieldTypeRegistry_ImplicitConversions tests implicit type conversions
// TASK 4.4: Support implicit conversions (string->int for numeric strings)
func TestFieldTypeRegistry_ImplicitConversions(t *testing.T) {
	registry := NewFieldTypeRegistry()

	tests := []struct {
		name   string
		value  interface{}
		target FieldType
		check  func(t *testing.T, result interface{})
	}{
		{
			name:   "numeric string to int",
			value:  "123",
			target: FieldTypeInt,
			check: func(t *testing.T, result interface{}) {
				i, ok := result.(int64)
				require.True(t, ok)
				assert.Equal(t, int64(123), i)
			},
		},
		{
			name:   "numeric string to float",
			value:  "3.14",
			target: FieldTypeFloat,
			check: func(t *testing.T, result interface{}) {
				f, ok := result.(float64)
				require.True(t, ok)
				assert.InDelta(t, 3.14, f, 0.001)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := registry.CastValue(tt.value, tt.target)
			require.NoError(t, err)
			tt.check(t, result)
		})
	}
}
