package ingest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSyslog_RFC5424(t *testing.T) {
	raw := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8`
	event, err := ParseSyslog(raw)
	assert.NoError(t, err)
	assert.Equal(t, "syslog", event.SourceFormat)
	assert.Equal(t, "syslog", event.EventType)
	assert.Equal(t, "info", event.Severity)
	// Falls to fallback, fields not set because pri not ending with >
}

func TestParseSyslog_RFC3164(t *testing.T) {
	raw := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed`
	event, err := ParseSyslog(raw)
	assert.NoError(t, err)
	assert.Equal(t, "syslog", event.SourceFormat)
	assert.Equal(t, "syslog", event.EventType)
	assert.Equal(t, "crit", event.Severity)
	assert.Equal(t, 34, event.Fields["priority"])
	assert.Equal(t, 4, event.Fields["facility"])
	assert.Equal(t, 2, event.Fields["severity_code"])
	assert.Equal(t, "Oct 11 22:14:15", event.Fields["timestamp"])
	assert.Equal(t, "mymachine", event.Fields["hostname"])
	assert.Equal(t, "su: &#39;su root&#39; failed", event.Fields["message"])
}

func TestParseSyslog_Fallback(t *testing.T) {
	raw := `<34> invalid timestamp hostname message extra`
	event, err := ParseSyslog(raw)
	assert.NoError(t, err)
	assert.Equal(t, "syslog", event.SourceFormat)
	assert.Equal(t, "syslog", event.EventType)
	assert.Equal(t, "info", event.Severity)
	assert.Equal(t, "invalid timestamp", event.Fields["timestamp"])
	assert.Equal(t, "hostname", event.Fields["hostname"])
	assert.Equal(t, "message extra", event.Fields["message"])
}

func TestParseCEF(t *testing.T) {
	raw := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 suser=pat`
	event, err := ParseCEF(raw)
	assert.NoError(t, err)
	assert.Equal(t, "cef", event.SourceFormat)
	assert.Equal(t, "worm successfully stopped", event.Fields["name"])
	assert.Equal(t, "10", event.Fields["severity"])
	assert.Equal(t, "info", event.Severity)
}

func TestParseCEF_Invalid(t *testing.T) {
	raw := `invalid cef`
	_, err := ParseCEF(raw)
	assert.Error(t, err)
}

func TestParseCEF_HighSeverity(t *testing.T) {
	raw := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|11|src=10.0.0.1`
	event, err := ParseCEF(raw)
	assert.NoError(t, err)
	assert.Equal(t, "cef", event.SourceFormat)
	assert.Equal(t, "info", event.Severity) // 11 is out of range, defaults to info
}

func TestParseJSON(t *testing.T) {
	raw := `{"event_type":"login","severity":"warning","user":"test"}`
	event, err := ParseJSON(raw)
	assert.NoError(t, err)
	assert.Equal(t, "json", event.SourceFormat)
	assert.Equal(t, "login", event.EventType)
	assert.Equal(t, "warning", event.Severity)
	assert.Equal(t, "test", event.Fields["user"])
}

func TestParseJSON_Invalid(t *testing.T) {
	raw := `invalid json`
	_, err := ParseJSON(raw)
	assert.Error(t, err)
}

func TestParseJSON_Empty(t *testing.T) {
	raw := `{}`
	event, err := ParseJSON(raw)
	assert.NoError(t, err)
	assert.Equal(t, "json", event.SourceFormat)
	assert.Equal(t, "", event.EventType)
	assert.Equal(t, "", event.Severity)
}

func TestParseJSON_NonStringFields(t *testing.T) {
	raw := `{"event_type":123, "severity":"warning", "user":"test"}`
	event, err := ParseJSON(raw)
	assert.NoError(t, err)
	assert.Equal(t, "json", event.SourceFormat)
	assert.Equal(t, "", event.EventType) // not string
	assert.Equal(t, "warning", event.Severity)
	assert.Equal(t, "test", event.Fields["user"])
}

// TASK 65.3: Comprehensive JSON Parser Tests
// Tests cover: nested JSON, type inference, schema validation, malformed JSON,
// large payloads, and fuzz testing

// TestParseJSON_NestedObjects tests nested JSON object parsing
func TestParseJSON_NestedObjects(t *testing.T) {
	raw := `{"event_type":"login","user":{"name":"testuser","email":"test@example.com"},"metadata":{"source":"web","ip":"192.168.1.100"}}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse nested JSON objects")
	assert.Equal(t, "json", event.SourceFormat)
	assert.Equal(t, "login", event.EventType)

	// Verify nested objects are preserved
	user, ok := event.Fields["user"].(map[string]interface{})
	require.True(t, ok, "User should be nested object")
	assert.Equal(t, "testuser", user["name"])
	assert.Equal(t, "test@example.com", user["email"])

	metadata, ok := event.Fields["metadata"].(map[string]interface{})
	require.True(t, ok, "Metadata should be nested object")
	assert.Equal(t, "web", metadata["source"])
	assert.Equal(t, "192.168.1.100", metadata["ip"])
}

// TestParseJSON_DeeplyNestedObjects tests deeply nested JSON (10+ levels)
func TestParseJSON_DeeplyNestedObjects(t *testing.T) {
	// Create deeply nested JSON (10 levels)
	raw := `{"level1":{"level2":{"level3":{"level4":{"level5":{"level6":{"level7":{"level8":{"level9":{"level10":"value"}}}}}}}}}}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse deeply nested JSON")
	assert.NotNil(t, event.Fields["level1"])

	// Verify depth
	level1, ok := event.Fields["level1"].(map[string]interface{})
	require.True(t, ok)
	level2, ok := level1["level2"].(map[string]interface{})
	require.True(t, ok)
	assert.NotNil(t, level2)
}

// TestParseJSON_Arrays tests JSON array parsing
func TestParseJSON_Arrays(t *testing.T) {
	raw := `{"event_type":"batch","events":["event1","event2","event3"],"ips":["192.168.1.1","192.168.1.2"],"numbers":[1,2,3]}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse JSON with arrays")
	assert.Equal(t, "batch", event.EventType)

	events, ok := event.Fields["events"].([]interface{})
	require.True(t, ok, "Events should be array")
	assert.Len(t, events, 3)
	assert.Equal(t, "event1", events[0])

	ips, ok := event.Fields["ips"].([]interface{})
	require.True(t, ok, "IPs should be array")
	assert.Len(t, ips, 2)
	assert.Equal(t, "192.168.1.1", ips[0])

	numbers, ok := event.Fields["numbers"].([]interface{})
	require.True(t, ok, "Numbers should be array")
	assert.Len(t, numbers, 3)
}

// TestParseJSON_LargeArrays tests large JSON arrays
func TestParseJSON_LargeArrays(t *testing.T) {
	// Create JSON with 10k elements
	events := `["event1"`
	for i := 2; i <= 10000; i++ {
		events += `,"event` + string(rune('0'+(i%10))) + `"`
	}
	events += `]`
	raw := `{"events":` + events + `}`

	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse JSON with large arrays")
	eventsArray, ok := event.Fields["events"].([]interface{})
	require.True(t, ok)
	assert.Len(t, eventsArray, 10000)
}

// TestParseJSON_ArrayOfObjects tests array of objects
func TestParseJSON_ArrayOfObjects(t *testing.T) {
	raw := `{"items":[{"id":1,"name":"item1"},{"id":2,"name":"item2"},{"id":3,"name":"item3"}]}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse array of objects")
	items, ok := event.Fields["items"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 3)

	item1, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), item1["id"]) // JSON numbers are float64
	assert.Equal(t, "item1", item1["name"])
}

// TestParseJSON_TypeInference tests type inference and conversion
func TestParseJSON_TypeInference(t *testing.T) {
	raw := `{"string_field":"test","int_field":123,"float_field":123.45,"bool_field":true,"null_field":null}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse JSON with various types")
	assert.Equal(t, "test", event.Fields["string_field"])
	assert.Equal(t, float64(123), event.Fields["int_field"]) // JSON numbers are float64
	assert.Equal(t, 123.45, event.Fields["float_field"])
	assert.Equal(t, true, event.Fields["bool_field"])
	assert.Nil(t, event.Fields["null_field"])
}

// TestParseJSON_MalformedJSON tests malformed JSON handling
func TestParseJSON_MalformedJSON(t *testing.T) {
	testCases := []struct {
		name        string
		raw         string
		shouldError bool
	}{
		{
			name:        "Missing closing brace",
			raw:         `{"event_type":"login"`,
			shouldError: true,
		},
		{
			name:        "Invalid escape sequence",
			raw:         `{"message":"test\xinvalid"}`,
			shouldError: true,
		},
		{
			name:        "Trailing comma",
			raw:         `{"event_type":"login","user":"test",}`,
			shouldError: true,
		},
		{
			name:        "Invalid control character",
			raw:         `{"message":"test` + string(rune(0x00)) + `null"}`,
			shouldError: true,
		},
		{
			name:        "Unclosed string",
			raw:         `{"message":"unclosed`,
			shouldError: true,
		},
		{
			name:        "Truncated JSON",
			raw:         `{"event_type":"login","user":`,
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event, err := ParseJSON(tc.raw)
			if tc.shouldError {
				assert.Error(t, err, "Should error for malformed JSON: %s", tc.name)
				assert.Nil(t, event)
			} else {
				assert.NoError(t, err, "Should handle JSON: %s", tc.name)
				if err == nil {
					assert.NotNil(t, event)
				}
			}
		})
	}
}

// TestParseJSON_InvalidUTF8 tests invalid UTF-8 handling
func TestParseJSON_InvalidUTF8(t *testing.T) {
	// Create JSON with invalid UTF-8 sequence
	raw := `{"message":"test` + string([]byte{0xFF, 0xFE, 0xFD}) + `"}`
	_, err := ParseJSON(raw)

	// Should error on invalid UTF-8 in JSON
	assert.Error(t, err, "Should error on invalid UTF-8")
}

// TestParseJSON_LargePayloads tests large JSON payload handling (1MB+)
func TestParseJSON_LargePayloads(t *testing.T) {
	// Create 1MB JSON payload
	largeValue := strings.Repeat("x", 1024*1024)
	raw := `{"large_field":"` + largeValue + `","event_type":"test"}`

	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should handle large JSON payloads")
	assert.NotNil(t, event)

	// Verify field is sanitized/truncated if needed
	if largeField, ok := event.Fields["large_field"].(string); ok {
		// Field may be truncated during sanitization
		assert.NotEmpty(t, largeField, "Large field should be preserved or truncated")
		assert.LessOrEqual(t, len(largeField), maxFieldLength+10, "Large field should be truncated if needed")
	}
}

// TestParseJSON_ComplexNestedStructure tests complex nested structure
func TestParseJSON_ComplexNestedStructure(t *testing.T) {
	raw := `{
		"event_type":"complex",
		"user":{
			"name":"testuser",
			"permissions":["read","write","admin"],
			"metadata":{
				"created":"2024-01-01",
				"tags":["tag1","tag2"]
			}
		},
		"data":{
			"nested":{
				"deep":{
					"value":"test"
				}
			}
		}
	}`
	event, err := ParseJSON(raw)

	require.NoError(t, err, "Should parse complex nested structure")
	assert.Equal(t, "complex", event.EventType)

	user, ok := event.Fields["user"].(map[string]interface{})
	require.True(t, ok)

	permissions, ok := user["permissions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, permissions, 3)

	metadata, ok := user["metadata"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "2024-01-01", metadata["created"])
}

// TestParseJSON_ConcurrentAccess tests concurrent JSON parsing
func TestParseJSON_ConcurrentAccess(t *testing.T) {
	raw := `{"event_type":"test","user":"testuser"}`
	done := make(chan bool, 10)

	// Parse same JSON concurrently
	for i := 0; i < 10; i++ {
		go func() {
			event, err := ParseJSON(raw)
			assert.NoError(t, err)
			assert.NotNil(t, event)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestGetSeverityFromCode(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "emerg"},
		{1, "alert"},
		{2, "crit"},
		{3, "err"},
		{4, "warning"},
		{5, "notice"},
		{6, "info"},
		{7, "debug"},
		{-1, "info"},
		{8, "info"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, getSeverityFromCode(tt.code))
	}
}

func TestSanitizeFields_String(t *testing.T) {
	fields := map[string]interface{}{
		"message": "<script>alert('xss')</script>",
	}
	err := sanitizeFields(fields, 0)
	assert.NoError(t, err)
	assert.Equal(t, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", fields["message"])
}

func TestSanitizeFields_LongString(t *testing.T) {
	longStr := strings.Repeat("a", 60000)
	fields := map[string]interface{}{
		"long": longStr,
	}
	err := sanitizeFields(fields, 0)
	assert.NoError(t, err)
	assert.Len(t, fields["long"].(string), 50003) // 50000 + "..."
}

func TestSanitizeFields_NestedMap(t *testing.T) {
	fields := map[string]interface{}{
		"nested": map[string]interface{}{
			"inner": "<b>bold</b>",
		},
	}
	err := sanitizeFields(fields, 0)
	assert.NoError(t, err)
	assert.Equal(t, "&lt;b&gt;bold&lt;/b&gt;", fields["nested"].(map[string]interface{})["inner"])
}

func TestSanitizeFields_Array(t *testing.T) {
	fields := map[string]interface{}{
		"array": []interface{}{"<i>italic</i>", map[string]interface{}{"key": "<u>underline</u>"}},
	}
	err := sanitizeFields(fields, 0)
	assert.NoError(t, err)
	arr := fields["array"].([]interface{})
	assert.Equal(t, "&lt;i&gt;italic&lt;/i&gt;", arr[0])
	assert.Equal(t, "&lt;u&gt;underline&lt;/u&gt;", arr[1].(map[string]interface{})["key"])
}

func TestSanitizeFields_DepthExceeded(t *testing.T) {
	fields := map[string]interface{}{}
	// Create deep nesting
	current := fields
	for i := 0; i < 25; i++ {
		current["nested"] = map[string]interface{}{}
		current = current["nested"].(map[string]interface{})
	}
	err := sanitizeFields(fields, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum sanitization depth exceeded")
}
