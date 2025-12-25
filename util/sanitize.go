package util

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// MaxSanitizeLength is the maximum input length to prevent DoS attacks
	// Input longer than this will be truncated before sanitization
	MaxSanitizeLength = 1024 * 1024 // 1MB
)

// SanitizeError sanitizes an error message to remove sensitive information
// before logging. It redacts passwords, tokens, API keys, and other secrets.
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return SanitizeString(err.Error())
}

// SanitizeString sanitizes a string to remove sensitive information
// Input is truncated to MaxSanitizeLength to prevent DoS attacks via huge inputs
func SanitizeString(s string) string {
	if s == "" {
		return ""
	}

	// Truncate oversized input to prevent DoS via memory exhaustion
	if len(s) > MaxSanitizeLength {
		s = s[:MaxSanitizeLength] + "... [truncated]"
	}

	// Pattern replacements for common sensitive data patterns
	patterns := []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
		// Password patterns
		{regexp.MustCompile(`(?i)(password|passwd|pwd)[\s:=]+[^\s\n]+`), "$1=REDACTED"},
		{regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]+"`), `"password":"REDACTED"`},
		{regexp.MustCompile(`(?i)'password'\s*:\s*'[^']+' `), `'password':'REDACTED'`},

		// Token patterns
		{regexp.MustCompile(`(?i)(token|auth|authorization)[\s:=]+[^\s\n]+`), "$1=REDACTED"},
		{regexp.MustCompile(`(?i)"token"\s*:\s*"[^"]+"`), `"token":"REDACTED"`},
		{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`), "bearer REDACTED"},

		// API Key patterns
		{regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\s:=]+[^\s\n]+`), "$1=REDACTED"},
		{regexp.MustCompile(`(?i)"api[_-]?key"\s*:\s*"[^"]+"`), `"api_key":"REDACTED"`},

		// Secret patterns
		{regexp.MustCompile(`(?i)(secret|client[_-]?secret)[\s:=]+[^\s\n]+`), "$1=REDACTED"},
		{regexp.MustCompile(`(?i)"secret"\s*:\s*"[^"]+"`), `"secret":"REDACTED"`},

		// AWS credentials
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "REDACTED_AWS_KEY"},
		{regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key[\s:=]+[^\s\n]+`), "aws_secret_access_key=REDACTED"},

		// JWT tokens (looks like xxx.yyy.zzz format)
		{regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`), "REDACTED_JWT"},

		// Credit card patterns (basic pattern, not comprehensive)
		{regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), "REDACTED_CC"},

		// SSH private keys ((?s) flag makes . match newlines for multiline keys)
		{regexp.MustCompile(`(?s)-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`), "REDACTED_PRIVATE_KEY"},
	}

	result := s
	for _, p := range patterns {
		result = p.pattern.ReplaceAllString(result, p.replacement)
	}

	return result
}

// SanitizeMap sanitizes values in a map to remove sensitive information
// It redacts known sensitive keys like "password", "token", "api_key", etc.
func SanitizeMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	sensitiveKeys := map[string]bool{
		"password":              true,
		"passwd":                true,
		"pwd":                   true,
		"token":                 true,
		"auth":                  true,
		"authorization":         true,
		"api_key":               true,
		"apikey":                true,
		"api-key":               true,
		"secret":                true,
		"client_secret":         true,
		"client-secret":         true,
		"access_token":          true,
		"refresh_token":         true,
		"private_key":           true,
		"aws_secret_access_key": true,
		"credential":            true,
		"credentials":           true,
	}

	result := make(map[string]interface{})
	for k, v := range m {
		lowerKey := strings.ToLower(k)
		if sensitiveKeys[lowerKey] {
			result[k] = "REDACTED"
		} else if nestedMap, ok := v.(map[string]interface{}); ok {
			// Recursively sanitize nested maps
			result[k] = SanitizeMap(nestedMap)
		} else {
			result[k] = v
		}
	}

	return result
}

// SafeErrorFormat formats an error for logging, sanitizing sensitive data
// Use this instead of fmt.Sprintf("%v", err) when logging errors
func SafeErrorFormat(format string, args ...interface{}) string {
	// Format the string first
	formatted := fmt.Sprintf(format, args...)
	// Then sanitize it
	return SanitizeString(formatted)
}
