package ingest

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"

	"cerberus/core"
)

const maxFieldLength = 50000
const maxSanitizeDepth = 20

// sanitizeFields sanitizes event fields for security
func sanitizeFields(fields map[string]interface{}, depth int) error {
	if depth > maxSanitizeDepth {
		return fmt.Errorf("maximum sanitization depth exceeded")
	}
	for k, v := range fields {
		switch val := v.(type) {
		case string:
			// Escape HTML to prevent XSS
			sanitized := html.EscapeString(val)
			// Limit length to prevent DoS
			if len(sanitized) > maxFieldLength {
				sanitized = sanitized[:maxFieldLength] + "..."
			}
			fields[k] = sanitized
		case map[string]interface{}:
			// Recursively sanitize nested maps
			if err := sanitizeFields(val, depth+1); err != nil {
				return err
			}
		case []interface{}:
			// Recursively sanitize array elements
			for i, elem := range val {
				if elemMap, ok := elem.(map[string]interface{}); ok {
					if err := sanitizeFields(elemMap, depth+1); err != nil {
						return err
					}
				} else if elemStr, ok := elem.(string); ok {
					sanitized := html.EscapeString(elemStr)
					if len(sanitized) > maxFieldLength {
						sanitized = sanitized[:maxFieldLength] + "..."
					}
					val[i] = sanitized
				}
			}
		}
	}
	return nil
}

// ParseSyslog parses a raw Syslog string into an Event
func ParseSyslog(raw string) (*core.Event, error) {
	event := core.NewEvent()
	event.SourceFormat = "syslog"
	event.RawData = raw

	event.Fields = map[string]interface{}{
		"raw": raw,
	}

	// RFC3164 syslog regex: <pri>timestamp hostname message
	// pri: <number>, timestamp: MMM dd hh:mm:ss, hostname: string, message: rest
	re := regexp.MustCompile(`^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$`)
	matches := re.FindStringSubmatch(raw)
	if len(matches) == 5 {
		pri, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid priority in syslog message: %w", err)
		}
		facility := pri / 8
		severity := pri % 8
		event.Fields["priority"] = pri
		event.Fields["facility"] = facility
		event.Fields["severity_code"] = severity
		event.Fields["timestamp"] = matches[2]
		event.Fields["hostname"] = matches[3]
		event.Fields["message"] = matches[4]
		event.Severity = getSeverityFromCode(severity)
	} else {
		// Fallback to simple parsing if regex fails
		parts := strings.Fields(raw)
		if len(parts) >= 4 && strings.HasPrefix(parts[0], "<") && strings.HasSuffix(parts[0], ">") {
			event.Fields["timestamp"] = parts[1] + " " + parts[2]
			event.Fields["hostname"] = parts[3]
			event.Fields["message"] = strings.Join(parts[4:], " ")
		}
		event.Severity = "info"
	}

	if err := sanitizeFields(event.Fields, 0); err != nil {
		return nil, err
	}
	event.EventType = "syslog"
	return event, nil
}

// getSeverityFromCode converts syslog severity code to string
func getSeverityFromCode(code int) string {
	severities := []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
	if code >= 0 && code < len(severities) {
		return severities[code]
	}
	return "info"
}

// getSeverityFromCEFCode converts CEF severity code (0-10) to string
func getSeverityFromCEFCode(code int) string {
	cefSeverities := []string{"unknown", "low", "warning", "average", "high", "very-high", "critical", "error", "warning", "notice", "info"}
	if code >= 0 && code < len(cefSeverities) {
		return cefSeverities[code]
	}
	return "info"
}

// ParseCEF parses a raw CEF string into an Event
func ParseCEF(raw string) (*core.Event, error) {
	event := core.NewEvent()
	event.SourceFormat = "cef"
	event.RawData = raw

	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
	parts := strings.SplitN(raw, "|", 8)
	if len(parts) < 8 || !strings.HasPrefix(parts[0], "CEF:") {
		return nil, fmt.Errorf("invalid CEF format")
	}

	severityCode, err := strconv.Atoi(parts[6])
	if err != nil {
		severityCode = 6 // default to info
	}
	event.Fields = map[string]interface{}{
		"cef_version":    strings.TrimPrefix(parts[0], "CEF:"),
		"device_vendor":  parts[1],
		"device_product": parts[2],
		"device_version": parts[3],
		"event_class_id": parts[4],
		"name":           parts[5],
		"severity":       parts[6],
		"severity_code":  severityCode,
	}

	// Parse extension field: key=value pairs separated by spaces
	extensionParts := strings.Fields(parts[7])
	for _, part := range extensionParts {
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			event.Fields[kv[0]] = kv[1]
		}
	}
	if err := sanitizeFields(event.Fields, 0); err != nil {
		return nil, err
	}
	event.EventType = "cef"
	event.Severity = getSeverityFromCEFCode(severityCode)
	return event, nil
}

// ParseJSON parses a raw JSON string into an Event
func ParseJSON(raw string) (*core.Event, error) {
	event := core.NewEvent()
	event.SourceFormat = "json"
	event.RawData = raw

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	event.Fields = data
	if err := sanitizeFields(event.Fields, 0); err != nil {
		return nil, err
	}
	if et, ok := data["event_type"].(string); ok {
		event.EventType = et
	}
	if sev, ok := data["severity"].(string); ok {
		event.Severity = sev
	}
	return event, nil
}
