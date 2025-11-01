package ingest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
