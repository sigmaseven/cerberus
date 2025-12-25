package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"cerberus/core"
)

// =============================================================================
// JSON Feed Handler
// =============================================================================

// JSONHandler implements IOCFeedHandler for JSON feeds
type JSONHandler struct {
	httpClient *http.Client
}

// NewJSONHandler creates a new JSON feed handler
func NewJSONHandler() *JSONHandler {
	return &JSONHandler{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Type returns the feed type this handler supports
func (h *JSONHandler) Type() IOCFeedType {
	return IOCFeedTypeJSON
}

// Validate checks if the feed configuration is valid
func (h *JSONHandler) Validate(feed *IOCFeed) error {
	if feed.URL == "" && feed.Path == "" {
		return ErrMissingURL
	}
	return nil
}

// Test verifies connectivity to the feed source without full sync
func (h *JSONHandler) Test(ctx context.Context, feed *IOCFeed) error {
	if err := h.Validate(feed); err != nil {
		return err
	}

	// Try to read and parse the JSON
	data, err := h.fetchData(ctx, feed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Verify it's valid JSON
	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("%w: invalid JSON: %v", ErrConnectionFailed, err)
	}

	return nil
}

// FetchIOCs retrieves IOCs from the JSON feed
func (h *JSONHandler) FetchIOCs(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*FetchedIOC, error) {
	if err := h.Validate(feed); err != nil {
		return nil, err
	}

	data, err := h.fetchData(ctx, feed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	iocs, err := h.parseJSON(data, feed)
	if err != nil {
		return nil, err
	}

	if len(iocs) == 0 {
		return nil, ErrNoIOCsFound
	}

	return iocs, nil
}

// Close releases any resources held by the handler
func (h *JSONHandler) Close() error {
	h.httpClient.CloseIdleConnections()
	return nil
}

// =============================================================================
// Internal Methods
// =============================================================================

// fetchData retrieves the JSON data from URL or file
func (h *JSONHandler) fetchData(ctx context.Context, feed *IOCFeed) ([]byte, error) {
	if feed.URL != "" {
		return h.fetchFromURL(ctx, feed)
	}
	return h.readFromFile(feed)
}

// fetchFromURL retrieves JSON from a URL
func (h *JSONHandler) fetchFromURL(ctx context.Context, feed *IOCFeed) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication
	h.addAuth(req, feed)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, ErrAuthFailed
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

// readFromFile reads JSON from a local file
func (h *JSONHandler) readFromFile(feed *IOCFeed) ([]byte, error) {
	return os.ReadFile(feed.Path)
}

// parseJSON parses JSON data into FetchedIOC slice
func (h *JSONHandler) parseJSON(data []byte, feed *IOCFeed) ([]*FetchedIOC, error) {
	// Try to unmarshal as different structures
	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var records []map[string]interface{}

	switch v := result.(type) {
	case []interface{}:
		// Array of objects
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				records = append(records, obj)
			}
		}
	case map[string]interface{}:
		// Single object or object with data array
		// Check for common data field names
		dataFields := []string{"data", "items", "results", "indicators", "iocs", "records", "objects"}
		found := false
		for _, field := range dataFields {
			if arr, ok := v[field].([]interface{}); ok {
				for _, item := range arr {
					if obj, ok := item.(map[string]interface{}); ok {
						records = append(records, obj)
					}
				}
				found = true
				break
			}
		}
		if !found {
			// Treat as single record
			records = append(records, v)
		}
	default:
		return nil, fmt.Errorf("unexpected JSON structure: %T", result)
	}

	var iocs []*FetchedIOC
	for i, record := range records {
		ioc, err := h.parseRecord(record, feed, i)
		if err != nil {
			continue // Skip invalid records
		}
		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

// parseRecord converts a JSON object to FetchedIOC
func (h *JSONHandler) parseRecord(record map[string]interface{}, feed *IOCFeed, index int) (*FetchedIOC, error) {
	// Determine field mappings
	mappings := h.getFieldMappings(feed)

	// Get IOC value
	value := h.extractString(record, mappings["value"])
	if value == "" {
		// Try common field names
		commonValueFields := []string{"value", "indicator", "ioc", "pattern", "observable", "data"}
		for _, field := range commonValueFields {
			if v := h.extractString(record, field); v != "" {
				value = v
				break
			}
		}
	}
	if value == "" {
		return nil, fmt.Errorf("no IOC value found")
	}

	// Get IOC type
	var iocType core.IOCType
	typeStr := h.extractString(record, mappings["type"])
	if typeStr == "" {
		commonTypeFields := []string{"type", "indicator_type", "ioc_type", "observable_type"}
		for _, field := range commonTypeFields {
			if v := h.extractString(record, field); v != "" {
				typeStr = v
				break
			}
		}
	}
	if typeStr != "" {
		iocType = h.parseIOCType(typeStr)
	}
	if iocType == "" && feed.DefaultType != "" {
		iocType = feed.DefaultType
	}
	if iocType == "" {
		iocType = core.DetectIOCType(value)
	}
	if iocType == "" {
		return nil, fmt.Errorf("cannot determine IOC type for: %s", value)
	}

	ioc := &FetchedIOC{
		Type:       iocType,
		Value:      value,
		ExternalID: h.extractString(record, mappings["external_id"]),
		RawData:    record,
	}

	// Set external ID if not found
	if ioc.ExternalID == "" {
		if id := h.extractString(record, "id"); id != "" {
			ioc.ExternalID = id
		} else {
			ioc.ExternalID = fmt.Sprintf("index-%d", index)
		}
	}

	// Extract optional fields
	ioc.Description = h.extractString(record, mappings["description"])
	if ioc.Description == "" {
		ioc.Description = h.extractString(record, "description")
	}

	// Severity
	if sevStr := h.extractString(record, mappings["severity"]); sevStr != "" {
		ioc.Severity = h.parseSeverity(sevStr)
	} else if sevStr := h.extractString(record, "severity"); sevStr != "" {
		ioc.Severity = h.parseSeverity(sevStr)
	}

	// Confidence
	if conf := h.extractFloat(record, mappings["confidence"]); conf != nil {
		ioc.Confidence = conf
	} else if conf := h.extractFloat(record, "confidence"); conf != nil {
		ioc.Confidence = conf
	}

	// Tags
	if tags := h.extractStringSlice(record, mappings["tags"]); len(tags) > 0 {
		ioc.Tags = tags
	} else if tags := h.extractStringSlice(record, "tags"); len(tags) > 0 {
		ioc.Tags = tags
	}

	// References
	if refs := h.extractStringSlice(record, mappings["references"]); len(refs) > 0 {
		ioc.References = refs
	} else if refs := h.extractStringSlice(record, "references"); len(refs) > 0 {
		ioc.References = refs
	}

	// Timestamps
	if t := h.extractTime(record, mappings["first_seen"]); t != nil {
		ioc.FirstSeen = t
	} else if t := h.extractTime(record, "first_seen"); t != nil {
		ioc.FirstSeen = t
	}

	if t := h.extractTime(record, mappings["last_seen"]); t != nil {
		ioc.LastSeen = t
	} else if t := h.extractTime(record, "last_seen"); t != nil {
		ioc.LastSeen = t
	}

	if t := h.extractTime(record, mappings["expires_at"]); t != nil {
		ioc.ExpiresAt = t
	} else if t := h.extractTime(record, "expires_at"); t != nil {
		ioc.ExpiresAt = t
	}

	return ioc, nil
}

// getFieldMappings returns field mappings with defaults
func (h *JSONHandler) getFieldMappings(feed *IOCFeed) map[string]string {
	mappings := map[string]string{
		"value":       "value",
		"type":        "type",
		"external_id": "id",
		"description": "description",
		"severity":    "severity",
		"confidence":  "confidence",
		"tags":        "tags",
		"references":  "references",
		"first_seen":  "first_seen",
		"last_seen":   "last_seen",
		"expires_at":  "expires_at",
	}

	// Override with feed-specific mappings
	if feed.FieldMapping != nil {
		for k, v := range feed.FieldMapping {
			mappings[k] = v
		}
	}

	return mappings
}

// extractString extracts a string value from a nested path (e.g., "data.value")
func (h *JSONHandler) extractString(record map[string]interface{}, path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, ".")
	current := interface{}(record)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return ""
		}
	}

	switch v := current.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	default:
		if current != nil {
			return fmt.Sprintf("%v", current)
		}
		return ""
	}
}

// extractFloat extracts a float value
func (h *JSONHandler) extractFloat(record map[string]interface{}, path string) *float64 {
	if path == "" {
		return nil
	}

	parts := strings.Split(path, ".")
	current := interface{}(record)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	switch v := current.(type) {
	case float64:
		return &v
	case int:
		f := float64(v)
		return &f
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return &f
		}
	}
	return nil
}

// extractStringSlice extracts a string slice value
func (h *JSONHandler) extractStringSlice(record map[string]interface{}, path string) []string {
	if path == "" {
		return nil
	}

	parts := strings.Split(path, ".")
	current := interface{}(record)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	switch v := current.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, strings.TrimSpace(s))
			}
		}
		return result
	case []string:
		return v
	case string:
		// Handle comma-separated values
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// extractTime extracts a time value
func (h *JSONHandler) extractTime(record map[string]interface{}, path string) *time.Time {
	if path == "" {
		return nil
	}

	parts := strings.Split(path, ".")
	current := interface{}(record)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	var t time.Time
	var err error

	switch v := current.(type) {
	case string:
		// Try various time formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, format := range formats {
			if t, err = time.Parse(format, v); err == nil {
				return &t
			}
		}
	case float64:
		// Unix timestamp
		t = time.Unix(int64(v), 0)
		return &t
	case int64:
		t = time.Unix(v, 0)
		return &t
	}
	return nil
}

// parseIOCType converts a string to IOCType
func (h *JSONHandler) parseIOCType(typeStr string) core.IOCType {
	typeStr = strings.ToLower(strings.TrimSpace(typeStr))

	// Handle STIX-style patterns
	if strings.HasPrefix(typeStr, "[") {
		if strings.Contains(typeStr, "ipv4-addr") || strings.Contains(typeStr, "ipv6-addr") {
			return core.IOCTypeIP
		}
		if strings.Contains(typeStr, "domain-name") {
			return core.IOCTypeDomain
		}
		if strings.Contains(typeStr, "url") {
			return core.IOCTypeURL
		}
		if strings.Contains(typeStr, "file:hashes") {
			return core.IOCTypeHash
		}
		if strings.Contains(typeStr, "email-addr") {
			return core.IOCTypeEmail
		}
	}

	switch typeStr {
	case "ip", "ipv4", "ipv6", "ip-dst", "ip-src", "ipaddress", "ip-address",
		"ipv4-addr", "ipv6-addr", "IPv4", "IPv6":
		return core.IOCTypeIP
	case "domain", "hostname", "fqdn", "domain-name":
		return core.IOCTypeDomain
	case "url", "uri", "link":
		return core.IOCTypeURL
	case "hash", "md5", "sha1", "sha256", "sha512", "file-hash", "filehash",
		"hash-md5", "hash-sha1", "hash-sha256":
		return core.IOCTypeHash
	case "email", "email-src", "email-dst", "email-addr", "email-address":
		return core.IOCTypeEmail
	case "filename", "file", "filepath", "file-name", "file-path":
		return core.IOCTypeFilename
	case "registry", "regkey", "registry-key", "windows-registry-key":
		return core.IOCTypeRegistry
	case "cve", "vulnerability":
		return core.IOCTypeCVE
	case "cidr", "ip-range", "subnet":
		return core.IOCTypeCIDR
	case "useragent", "user-agent":
		return core.IOCTypeUserAgent
	default:
		return ""
	}
}

// parseSeverity converts a string to IOCSeverity
func (h *JSONHandler) parseSeverity(s string) core.IOCSeverity {
	s = strings.ToLower(strings.TrimSpace(s))

	// Handle numeric values
	if n, err := strconv.Atoi(s); err == nil {
		switch {
		case n >= 90:
			return core.IOCSeverityCritical
		case n >= 70:
			return core.IOCSeverityHigh
		case n >= 50:
			return core.IOCSeverityMedium
		case n >= 30:
			return core.IOCSeverityLow
		default:
			return core.IOCSeverityInformational
		}
	}

	switch s {
	case "critical", "crit", "5", "very-high", "veryhigh":
		return core.IOCSeverityCritical
	case "high", "4":
		return core.IOCSeverityHigh
	case "medium", "med", "3", "moderate":
		return core.IOCSeverityMedium
	case "low", "2":
		return core.IOCSeverityLow
	case "informational", "info", "1", "none", "unknown":
		return core.IOCSeverityInformational
	default:
		return core.IOCSeverityMedium
	}
}

// addAuth adds authentication headers based on feed configuration
func (h *JSONHandler) addAuth(req *http.Request, feed *IOCFeed) {
	if feed.AuthConfig == nil {
		return
	}

	// API Key auth
	if apiKey, ok := feed.AuthConfig["api_key"].(string); ok && apiKey != "" {
		headerName := "X-API-Key"
		if name, ok := feed.AuthConfig["api_key_header"].(string); ok && name != "" {
			headerName = name
		}
		req.Header.Set(headerName, apiKey)
	}

	// Basic auth
	if username, ok := feed.AuthConfig["username"].(string); ok {
		if password, ok := feed.AuthConfig["password"].(string); ok {
			req.SetBasicAuth(username, password)
		}
	}

	// Bearer token
	if token, ok := feed.AuthConfig["bearer_token"].(string); ok && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// Ensure JSONHandler satisfies interface at compile time
var _ IOCFeedHandler = (*JSONHandler)(nil)

// Ensure CSVHandler satisfies interface at compile time
var _ IOCFeedHandler = (*CSVHandler)(nil)

// Note: The reflect import is needed for potential future use
var _ = reflect.TypeOf
