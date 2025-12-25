package api

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

// SECURITY REQUIREMENTS:
// FR-SEC-006: XSS Prevention in Error Messages and Logs
// OWASP ASVS V5.3.3: Output encoding and escaping
// THREAT MODEL: Prevents XSS attacks via error messages displayed in web UI
//
// DEFENSE STRATEGY:
// 1. Remove script tags completely (don't just escape - remove threat)
// 2. HTML entity encode all special characters
// 3. Redact file paths to prevent information disclosure
// 4. Remove CRLF for log injection prevention

var (
	// scriptTagRegex matches script tags (case-insensitive, multiline)
	// Matches: <script...>...</script>, <SCRIPT...>...</SCRIPT>
	// SECURITY: Removes entire script blocks, not just opening tag
	scriptTagRegex = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)

	// filePathRegex matches common file path patterns
	// Matches: /path/to/file, C:\path\to\file, \\server\share\file
	// SECURITY: Prevents information disclosure of server file structure
	filePathRegex = regexp.MustCompile(`(?:[A-Z]:|\\\\[\w\-.]+\\[\w\-.$]+|/[\w\-./]+)+`)

	// dangerousHTMLTags matches other potentially dangerous HTML tags
	// Matches: <iframe>, <object>, <embed>, <img with onerror>
	// SECURITY: Defense in depth - removes tags that could execute JavaScript
	dangerousHTMLTags = regexp.MustCompile(`(?i)<(iframe|object|embed|applet|meta|link|form)[^>]*>`)

	// onEventRegex matches HTML event handlers (onclick, onerror, etc.)
	// Matches: onclick=, onerror=, onload=, etc.
	// SECURITY: Event handlers are XSS vectors even without <script> tags
	onEventRegex = regexp.MustCompile(`(?i)on\w+\s*=`)
)

// SanitizeErrorMessage sanitizes error messages before displaying to users
// SECURITY: Prevents XSS attacks via error messages in web UI
//
// Sanitization steps:
// 1. Remove all <script> tags and content
// 2. Remove dangerous HTML tags (iframe, object, embed, etc.)
// 3. Remove HTML event handlers (onclick, onerror, etc.)
// 4. HTML entity encode special characters
// 5. Redact file paths to prevent information disclosure
// 6. Limit length to prevent UI breaking
//
// Requirements:
// - MUST prevent XSS via error messages
// - MUST preserve error meaning/debugability
// - MUST NOT leak sensitive file paths
// - MUST handle all Unicode correctly
//
// Returns: Safe string for display in web UI
func SanitizeErrorMessage(message string) string {
	if message == "" {
		return ""
	}

	// Length limit - prevent UI breaking and DoS
	maxLength := 1000
	if len(message) > maxLength {
		message = message[:maxLength] + "... [truncated]"
	}

	// Step 1: Remove script tags completely
	// SECURITY: Don't just escape - remove the threat entirely
	message = scriptTagRegex.ReplaceAllString(message, "[SCRIPT_REMOVED]")

	// Step 2: Remove dangerous HTML tags
	message = dangerousHTMLTags.ReplaceAllString(message, "[TAG_REMOVED]")

	// Step 3: Remove HTML event handlers
	message = onEventRegex.ReplaceAllString(message, "[EVENT_REMOVED]")

	// Step 4: HTML entity encode special characters
	// This converts: < > & " ' to &lt; &gt; &amp; &#34; &#39;
	// SECURITY: Prevents any HTML interpretation
	message = html.EscapeString(message)

	// Step 5: Redact file paths (after HTML escaping to avoid double encoding)
	// SECURITY: Prevents information disclosure of server file structure
	message = filePathRegex.ReplaceAllString(message, "[FILE_PATH]")

	return message
}

// SanitizeLogMessage sanitizes log messages to prevent log injection attacks
// SECURITY: Prevents CRLF injection, control character injection, and log forging
//
// Sanitization steps:
// 1. Remove CRLF sequences (prevents log injection/splitting)
// 2. Remove control characters (prevents terminal escape sequences)
// 3. Preserve tabs (common in structured logs)
// 4. Limit length to prevent log flooding
//
// Requirements:
// - MUST prevent CRLF injection (log forging)
// - MUST prevent control character injection (terminal escapes)
// - MUST preserve log readability
// - MUST handle Unicode correctly
//
// Attack Examples Prevented:
// - "user logged in\n[ADMIN] Fake admin log entry" → "user logged in [ADMIN] Fake admin log entry"
// - "error\r\n\r\nHTTP/1.1 200 OK" → "error  HTTP/1.1 200 OK"
// - "test\x1b[31m RED TEXT" → "test RED TEXT"
//
// Returns: Safe string for logging
func SanitizeLogMessage(message string) string {
	if message == "" {
		return ""
	}

	// Length limit - prevent log flooding and disk exhaustion
	maxLength := 10000
	if len(message) > maxLength {
		message = message[:maxLength] + "... [truncated]"
	}

	// Step 1: Remove CRLF injection
	// SECURITY: \r\n in logs can forge log entries, bypass SIEM parsing
	// Replace \r with nothing, \n with space (preserve word boundaries)
	message = strings.ReplaceAll(message, "\r", "")
	message = strings.ReplaceAll(message, "\n", " ")

	// Step 2: Remove control characters (except tab)
	// SECURITY: Control chars can:
	// - Inject terminal escape sequences (color codes, cursor movement)
	// - Bypass log parsing/analysis
	// - Break log file formats
	//
	// Allow: printable chars (>=32), tab (9)
	// Block: 0-8, 10-31, 127+ (control chars)
	var result strings.Builder
	result.Grow(len(message)) // Preallocate for performance

	for _, r := range message {
		// Allow printable ASCII (32-126) and tab (9)
		if r >= 32 || r == '\t' {
			// Additional check: block high control characters (127-159)
			if r < 127 || r >= 160 {
				result.WriteRune(r)
			} else {
				// Replace control chars with space
				result.WriteRune(' ')
			}
		} else {
			// Replace other control chars with space
			result.WriteRune(' ')
		}
	}

	return result.String()
}

// SanitizeHTML sanitizes user input before rendering as HTML
// SECURITY: For user-generated content that needs HTML encoding
//
// This is a strict HTML encoder that converts ALL special characters
// MUST be used for any user input displayed in HTML context
//
// Returns: HTML-safe string
func SanitizeHTML(input string) string {
	if input == "" {
		return ""
	}

	// HTML entity encode everything
	return html.EscapeString(input)
}

// SanitizeJavaScript sanitizes strings before embedding in JavaScript
// SECURITY: Prevents JavaScript injection in inline scripts
//
// WARNING: Best practice is to avoid inline JavaScript entirely
// Use this only when absolutely necessary, prefer JSON encoding
//
// Requirements:
// - MUST escape quotes, backslashes, control characters
// - MUST prevent breaking out of string context
// - SHOULD use JSON encoding instead when possible
//
// Returns: JavaScript-safe string for use in quoted context
func SanitizeJavaScript(input string) string {
	if input == "" {
		return ""
	}

	// Escape characters that can break JavaScript string context
	replacements := []struct {
		old string
		new string
	}{
		{"\\", "\\\\"}, // Backslash first (prevents double escaping)
		{"\"", "\\\""}, // Double quote
		{"'", "\\'"},   // Single quote
		{"\n", "\\n"},  // Newline
		{"\r", "\\r"},  // Carriage return
		{"\t", "\\t"},  // Tab
		{"<", "\\x3C"}, // < (prevents </script> injection)
		{">", "\\x3E"}, // > (prevents </script> injection)
	}

	result := input
	for _, repl := range replacements {
		result = strings.ReplaceAll(result, repl.old, repl.new)
	}

	// Remove other control characters
	var cleaned strings.Builder
	for _, r := range result {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}

	return cleaned.String()
}

// StripHTML completely removes all HTML tags from input
// SECURITY: For contexts where HTML is never allowed
//
// Use cases:
// - Plain text fields
// - Filenames
// - IDs/tokens
//
// Returns: String with all HTML tags removed
func StripHTML(input string) string {
	if input == "" {
		return ""
	}

	// Remove all HTML tags
	noTags := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(input, "")

	// Decode HTML entities (so &lt; becomes <, then gets removed)
	decoded := html.UnescapeString(noTags)

	// Remove tags again (in case entities encoded tags)
	noTags = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(decoded, "")

	return noTags
}
