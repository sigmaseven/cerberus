package feeds

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"cerberus/core"
)

// =============================================================================
// CSV Feed Handler
// =============================================================================

// CSVHandler implements IOCFeedHandler for CSV feeds
type CSVHandler struct {
	httpClient *http.Client
}

// NewCSVHandler creates a new CSV feed handler
func NewCSVHandler() *CSVHandler {
	return &CSVHandler{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Type returns the feed type this handler supports
func (h *CSVHandler) Type() IOCFeedType {
	return IOCFeedTypeCSV
}

// Validate checks if the feed configuration is valid
func (h *CSVHandler) Validate(feed *IOCFeed) error {
	if feed.URL == "" && feed.Path == "" {
		return ErrMissingURL
	}

	// Validate delimiter if specified
	if feed.Delimiter != "" && len(feed.Delimiter) != 1 {
		return fmt.Errorf("%w: delimiter must be a single character", ErrInvalidConfig)
	}

	return nil
}

// Test verifies connectivity to the feed source without full sync
func (h *CSVHandler) Test(ctx context.Context, feed *IOCFeed) error {
	if err := h.Validate(feed); err != nil {
		return err
	}

	// Try to read just the first few bytes to verify connectivity
	reader, cleanup, err := h.getReader(ctx, feed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer cleanup()

	// Try to read at least one record
	csvReader := csv.NewReader(reader)
	h.configureReader(csvReader, feed)

	_, err = csvReader.Read()
	if err != nil && err != io.EOF {
		return fmt.Errorf("%w: failed to parse CSV: %v", ErrConnectionFailed, err)
	}

	return nil
}

// FetchIOCs retrieves IOCs from the CSV feed
func (h *CSVHandler) FetchIOCs(ctx context.Context, feed *IOCFeed, since *time.Time) ([]*FetchedIOC, error) {
	if err := h.Validate(feed); err != nil {
		return nil, err
	}

	reader, cleanup, err := h.getReader(ctx, feed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer cleanup()

	// Wrap reader to filter out comment lines if comment_char is set
	var csvInput io.Reader = reader
	if feed.CommentChar != "" && len(feed.CommentChar) > 0 {
		csvInput = newCommentFilterReader(reader, feed.CommentChar[0])
	}

	csvReader := csv.NewReader(csvInput)
	h.configureReader(csvReader, feed)

	var iocs []*FetchedIOC
	lineNum := 0

	// Skip header if configured
	if feed.SkipHeader {
		_, err := csvReader.Read()
		if err != nil {
			if err == io.EOF {
				return nil, ErrNoIOCsFound
			}
			return nil, fmt.Errorf("failed to read CSV header: %w", err)
		}
		lineNum++
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Log error and continue
			continue
		}
		lineNum++

		ioc, err := h.parseRecord(record, feed, lineNum)
		if err != nil {
			continue // Skip invalid records
		}

		iocs = append(iocs, ioc)
	}

	if len(iocs) == 0 {
		return nil, ErrNoIOCsFound
	}

	return iocs, nil
}

// commentFilterReader filters out lines starting with a comment character
type commentFilterReader struct {
	scanner     *bufio.Scanner
	commentChar byte
	buf         []byte
	pos         int
}

// newCommentFilterReader creates a reader that skips lines starting with commentChar
func newCommentFilterReader(r io.Reader, commentChar byte) *commentFilterReader {
	return &commentFilterReader{
		scanner:     bufio.NewScanner(r),
		commentChar: commentChar,
	}
}

// Read implements io.Reader, filtering out comment lines
func (r *commentFilterReader) Read(p []byte) (n int, err error) {
	// Return any buffered data first
	if r.pos < len(r.buf) {
		n = copy(p, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}

	// Scan for the next non-comment line
	for r.scanner.Scan() {
		line := r.scanner.Text()
		// Skip empty lines and comment lines
		if len(line) == 0 || line[0] == r.commentChar {
			continue
		}
		// Found a non-comment line, buffer it with newline
		r.buf = append([]byte(line), '\n')
		r.pos = 0
		n = copy(p, r.buf)
		r.pos = n
		return n, nil
	}

	if err := r.scanner.Err(); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

// Close releases any resources held by the handler
func (h *CSVHandler) Close() error {
	h.httpClient.CloseIdleConnections()
	return nil
}

// =============================================================================
// Internal Methods
// =============================================================================

// getReader returns an io.Reader for the CSV data and a cleanup function
func (h *CSVHandler) getReader(ctx context.Context, feed *IOCFeed) (io.Reader, func(), error) {
	if feed.URL != "" {
		return h.getHTTPReader(ctx, feed)
	}
	return h.getFileReader(feed)
}

// getHTTPReader fetches CSV from a URL
func (h *CSVHandler) getHTTPReader(ctx context.Context, feed *IOCFeed) (io.Reader, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, nil, err
	}

	// Add authentication if configured
	h.addAuth(req, feed)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, nil, ErrAuthFailed
		}
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	cleanup := func() {
		resp.Body.Close()
	}

	return resp.Body, cleanup, nil
}

// getFileReader opens a local file
func (h *CSVHandler) getFileReader(feed *IOCFeed) (io.Reader, func(), error) {
	file, err := os.Open(feed.Path)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		file.Close()
	}

	return file, cleanup, nil
}

// configureReader sets up the CSV reader with feed-specific configuration
func (h *CSVHandler) configureReader(reader *csv.Reader, feed *IOCFeed) {
	// Set delimiter
	if feed.Delimiter != "" {
		reader.Comma = rune(feed.Delimiter[0])
	}

	// Be lenient with field counts
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
}

// parseRecord converts a CSV record to a FetchedIOC
func (h *CSVHandler) parseRecord(record []string, feed *IOCFeed, lineNum int) (*FetchedIOC, error) {
	if len(record) == 0 {
		return nil, fmt.Errorf("empty record")
	}

	// Get IOC value
	valueIdx := feed.ValueColumn
	if valueIdx < 0 || valueIdx >= len(record) {
		valueIdx = 0 // Default to first column
	}
	value := strings.TrimSpace(record[valueIdx])
	if value == "" {
		return nil, fmt.Errorf("empty IOC value")
	}

	// Determine IOC type
	var iocType core.IOCType
	if feed.TypeColumn >= 0 && feed.TypeColumn < len(record) {
		typeStr := strings.TrimSpace(record[feed.TypeColumn])
		iocType = h.parseIOCType(typeStr)
	}
	if iocType == "" {
		if feed.DefaultType != "" {
			iocType = feed.DefaultType
		} else {
			// Try to auto-detect
			iocType = core.DetectIOCType(value)
		}
	}
	if iocType == "" {
		return nil, fmt.Errorf("cannot determine IOC type for: %s", value)
	}

	ioc := &FetchedIOC{
		Type:       iocType,
		Value:      value,
		ExternalID: fmt.Sprintf("line-%d", lineNum),
	}

	// Apply field mappings if configured
	if feed.FieldMapping != nil {
		h.applyFieldMappings(ioc, record, feed.FieldMapping)
	}

	return ioc, nil
}

// parseIOCType converts a string to IOCType
func (h *CSVHandler) parseIOCType(typeStr string) core.IOCType {
	typeStr = strings.ToLower(strings.TrimSpace(typeStr))

	switch typeStr {
	case "ip", "ipv4", "ip-dst", "ip-src", "ipaddress":
		return core.IOCTypeIP
	case "domain", "hostname", "fqdn":
		return core.IOCTypeDomain
	case "url", "uri", "link":
		return core.IOCTypeURL
	case "hash", "md5", "sha1", "sha256", "sha512", "file-hash", "filehash":
		return core.IOCTypeHash
	case "email", "email-src", "email-dst", "email-addr":
		return core.IOCTypeEmail
	case "filename", "file", "filepath":
		return core.IOCTypeFilename
	case "registry", "regkey", "registry-key":
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

// applyFieldMappings applies configured field mappings to the IOC
func (h *CSVHandler) applyFieldMappings(ioc *FetchedIOC, record []string, mappings map[string]string) {
	for fieldName, columnSpec := range mappings {
		// Column spec can be an index (e.g., "2") or column name (would need header)
		idx, err := strconv.Atoi(columnSpec)
		if err != nil || idx < 0 || idx >= len(record) {
			continue
		}
		value := strings.TrimSpace(record[idx])
		if value == "" {
			continue
		}

		switch strings.ToLower(fieldName) {
		case "description":
			ioc.Description = value
		case "severity":
			ioc.Severity = h.parseSeverity(value)
		case "confidence":
			if conf, err := strconv.ParseFloat(value, 64); err == nil {
				ioc.Confidence = &conf
			}
		case "tags":
			ioc.Tags = strings.Split(value, ",")
			for i := range ioc.Tags {
				ioc.Tags[i] = strings.TrimSpace(ioc.Tags[i])
			}
		case "external_id", "externalid", "id":
			ioc.ExternalID = value
		case "first_seen", "firstseen":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				ioc.FirstSeen = &t
			}
		case "last_seen", "lastseen":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				ioc.LastSeen = &t
			}
		case "expires_at", "expiresat", "expires":
			if t, err := time.Parse(time.RFC3339, value); err == nil {
				ioc.ExpiresAt = &t
			}
		}
	}
}

// parseSeverity converts a string to IOCSeverity
func (h *CSVHandler) parseSeverity(s string) core.IOCSeverity {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "crit", "5":
		return core.IOCSeverityCritical
	case "high", "4":
		return core.IOCSeverityHigh
	case "medium", "med", "3":
		return core.IOCSeverityMedium
	case "low", "2":
		return core.IOCSeverityLow
	case "informational", "info", "1":
		return core.IOCSeverityInformational
	default:
		return core.IOCSeverityMedium
	}
}

// addAuth adds authentication headers based on feed configuration
func (h *CSVHandler) addAuth(req *http.Request, feed *IOCFeed) {
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
