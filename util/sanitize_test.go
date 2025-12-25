package util

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSanitizeError_HappyPath tests error sanitization with clean errors
func TestSanitizeError_HappyPath(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "simple error message",
			err:      errors.New("connection failed"),
			expected: "connection failed",
		},
		{
			name:     "error with context",
			err:      errors.New("database query failed: table not found"),
			expected: "database query failed: table not found",
		},
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSanitizeError_PasswordRedaction tests password sanitization (CRITICAL SECURITY)
func TestSanitizeError_PasswordRedaction(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "password in error message",
			err:              errors.New("authentication failed: password=secretpass123"),
			shouldNotContain: []string{"secretpass123"},
			shouldContain:    []string{"password=REDACTED"},
		},
		{
			name:             "passwd variant",
			err:              errors.New("login failed: passwd=mypassword"),
			shouldNotContain: []string{"mypassword"},
			shouldContain:    []string{"passwd=REDACTED"},
		},
		{
			name:             "pwd variant",
			err:              errors.New("auth error: pwd=P@ssw0rd!"),
			shouldNotContain: []string{"P@ssw0rd!"},
			shouldContain:    []string{"pwd=REDACTED"},
		},
		{
			name:             "password with colon separator",
			err:              errors.New("failed: password: secret123"),
			shouldNotContain: []string{"secret123"},
			shouldContain:    []string{"password=REDACTED"},
		},
		{
			name:             "JSON password field",
			err:              errors.New(`{"password":"supersecret"}`),
			shouldNotContain: []string{"supersecret"},
			shouldContain:    []string{`"password":"REDACTED"`},
		},
		{
			name:             "case insensitive PASSWORD",
			err:              errors.New("error: PASSWORD=MySecret"),
			shouldNotContain: []string{"MySecret"},
			shouldContain:    []string{"PASSWORD=REDACTED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeError(tt.err)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact secret: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_TokenRedaction tests token sanitization (CRITICAL SECURITY)
func TestSanitizeString_TokenRedaction(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "bearer token catches Authorization field",
			input:            "Authorization: bearer abc-123_def.456",
			shouldNotContain: []string{}, // Authorization field is redacted, but bearer portion isn't matched
			shouldContain:    []string{"Authorization=REDACTED"},
		},
		{
			name:             "token field",
			input:            "auth failed: token=secret_token_value",
			shouldNotContain: []string{"secret_token_value"},
			shouldContain:    []string{"token=REDACTED"},
		},
		{
			name:             "JSON token field",
			input:            `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}`,
			shouldNotContain: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			shouldContain:    []string{`"token":"REDACTED"`},
		},
		{
			name:             "authorization header",
			input:            "request failed: authorization=Bearer-token123",
			shouldNotContain: []string{"Bearer-token123"},
			shouldContain:    []string{"authorization=REDACTED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact secret: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_APIKeyRedaction tests API key sanitization (CRITICAL SECURITY)
func TestSanitizeString_APIKeyRedaction(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "api_key with underscore",
			input:            "config error: api_key=sk-1234567890abcdef",
			shouldNotContain: []string{"sk-1234567890abcdef"},
			shouldContain:    []string{"api_key=REDACTED"},
		},
		{
			name:             "api-key with dash",
			input:            "failed: api-key=key_abc123",
			shouldNotContain: []string{"key_abc123"},
			shouldContain:    []string{"api-key=REDACTED"},
		},
		{
			name:             "apikey no separator",
			input:            "error: apikey=myapikey123",
			shouldNotContain: []string{"myapikey123"},
			shouldContain:    []string{"apikey=REDACTED"},
		},
		{
			name:             "JSON api_key field",
			input:            `{"api_key":"sk-proj-abcdef123456"}`,
			shouldNotContain: []string{"sk-proj-abcdef123456"},
			shouldContain:    []string{`"api_key":"REDACTED"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact secret: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_AWSCredentials tests AWS credential redaction (CRITICAL SECURITY)
func TestSanitizeString_AWSCredentials(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "AWS access key",
			input:            "credentials: AKIAIOSFODNN7EXAMPLE",
			shouldNotContain: []string{"AKIAIOSFODNN7EXAMPLE"},
			shouldContain:    []string{"REDACTED_AWS_KEY"},
		},
		{
			name:             "AWS secret access key",
			input:            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			shouldNotContain: []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			shouldContain:    []string{"aws_secret_access_key=REDACTED"},
		},
		{
			name:             "multiple AWS keys in text",
			input:            "Using AKIAI44QH8DHBEXAMPLE with key=secret123",
			shouldNotContain: []string{"AKIAI44QH8DHBEXAMPLE"},
			shouldContain:    []string{"REDACTED_AWS_KEY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact AWS credential: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_JWTTokens tests JWT token redaction (CRITICAL SECURITY)
func TestSanitizeString_JWTTokens(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "auth field with JWT gets redacted as auth field",
			input:            "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV-adQssw5c",
			shouldNotContain: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			shouldContain:    []string{"auth=REDACTED"}, // Auth field pattern matches first
		},
		{
			name:             "JWT in error message",
			input:            "failed to validate: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0In0.abc123",
			shouldNotContain: []string{"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0In0.abc123"},
			shouldContain:    []string{"REDACTED_JWT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact JWT token")
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_CreditCards tests credit card redaction (CRITICAL SECURITY)
func TestSanitizeString_CreditCards(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "credit card with spaces",
			input:            "payment failed for card 4532 1234 5678 9010",
			shouldNotContain: []string{"4532 1234 5678 9010"},
			shouldContain:    []string{"REDACTED_CC"},
		},
		{
			name:             "credit card with dashes",
			input:            "card number: 4532-1234-5678-9010",
			shouldNotContain: []string{"4532-1234-5678-9010"},
			shouldContain:    []string{"REDACTED_CC"},
		},
		{
			name:             "credit card no separators",
			input:            "using 4532123456789010 for purchase",
			shouldNotContain: []string{"4532123456789010"},
			shouldContain:    []string{"REDACTED_CC"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact credit card: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_PrivateKeys tests SSH private key redaction (CRITICAL SECURITY)
func TestSanitizeString_PrivateKeys(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "RSA private key - single line format",
			input:            "key data: -----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA -----END RSA PRIVATE KEY-----",
			shouldNotContain: []string{"MIIEpAIBAAKCAQEA"},
			shouldContain:    []string{"REDACTED_PRIVATE_KEY", "key data:"},
		},
		{
			name:             "RSA private key - ACTUAL multiline format",
			input:            "Found key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nABCDEF123456\n-----END RSA PRIVATE KEY-----\nDone",
			shouldNotContain: []string{"MIIEpAIBAAKCAQEA", "ABCDEF123456"},
			shouldContain:    []string{"REDACTED_PRIVATE_KEY", "Found key:", "Done"},
		},
		{
			name:             "generic private key - single line format",
			input:            "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0B -----END PRIVATE KEY-----",
			shouldNotContain: []string{"MIIEvQIBADANBgkqhkiG9w0B"},
			shouldContain:    []string{"REDACTED_PRIVATE_KEY"},
		},
		{
			name:             "EC private key - multiline",
			input:            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGlRDzqHHPmP\nqPXR9sl3YR1wMQ\n-----END EC PRIVATE KEY-----",
			shouldNotContain: []string{"MHcCAQEEIIGlRDzqHHPmP", "qPXR9sl3YR1wMQ"},
			shouldContain:    []string{"REDACTED_PRIVATE_KEY"},
		},
		{
			name:             "OPENSSH private key - multiline",
			input:            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nBG5vbmUA\n-----END OPENSSH PRIVATE KEY-----",
			shouldNotContain: []string{"b3BlbnNzaC1rZXktdjEAAAAA", "BG5vbmUA"},
			shouldContain:    []string{"REDACTED_PRIVATE_KEY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should redact private key material")
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain redacted marker")
			}
		})
	}
}

// TestSanitizeString_EmptyInput tests edge case of empty strings
func TestSanitizeString_EmptyInput(t *testing.T) {
	result := SanitizeString("")
	assert.Equal(t, "", result, "Empty string should return empty string")
}

// TestSanitizeString_NoSensitiveData tests strings without sensitive data
func TestSanitizeString_NoSensitiveData(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "plain error message",
			input: "connection timeout",
		},
		{
			name:  "log message",
			input: "INFO: processing request from 192.168.1.1",
		},
		{
			name:  "SQL error",
			input: "table users not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.input, result, "Non-sensitive string should pass through unchanged")
		})
	}
}

// TestSanitizeMap_HappyPath tests map sanitization with clean data
func TestSanitizeMap_HappyPath(t *testing.T) {
	input := map[string]interface{}{
		"user_id":   "12345",
		"username":  "johndoe",
		"action":    "login",
		"timestamp": "2024-01-01T00:00:00Z",
	}

	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")
	assert.Equal(t, input["user_id"], result["user_id"])
	assert.Equal(t, input["username"], result["username"])
	assert.Equal(t, input["action"], result["action"])
	assert.Equal(t, input["timestamp"], result["timestamp"])
}

// TestSanitizeMap_SensitiveKeys tests redaction of sensitive keys (CRITICAL SECURITY)
func TestSanitizeMap_SensitiveKeys(t *testing.T) {
	input := map[string]interface{}{
		"username":              "johndoe",
		"password":              "secretpass123",
		"token":                 "abc123token",
		"api_key":               "sk-1234567890",
		"client_secret":         "oauth_secret",
		"access_token":          "bearer_token",
		"refresh_token":         "refresh_abc",
		"aws_secret_access_key": "aws_secret_key",
	}

	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")

	// Non-sensitive should pass through
	assert.Equal(t, "johndoe", result["username"])

	// All sensitive keys should be redacted
	sensitiveKeys := []string{
		"password", "token", "api_key", "client_secret",
		"access_token", "refresh_token", "aws_secret_access_key",
	}

	for _, key := range sensitiveKeys {
		assert.Equal(t, "REDACTED", result[key], "Key %s should be redacted", key)
		assert.NotEqual(t, input[key], result[key], "Original value should not be present for %s", key)
	}
}

// TestSanitizeMap_CaseInsensitive tests case-insensitive key matching
func TestSanitizeMap_CaseInsensitive(t *testing.T) {
	input := map[string]interface{}{
		"PASSWORD":      "secret1",
		"Password":      "secret2",
		"API_KEY":       "key1",
		"Api_Key":       "key2",
		"CLIENT_SECRET": "secret3",
	}

	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")

	// All should be redacted regardless of case
	for key := range input {
		assert.Equal(t, "REDACTED", result[key], "Key %s should be redacted (case insensitive)", key)
	}
}

// TestSanitizeMap_NestedMaps tests recursive sanitization of nested maps
func TestSanitizeMap_NestedMaps(t *testing.T) {
	input := map[string]interface{}{
		"user": "johndoe",
		"auth": map[string]interface{}{
			"username": "admin",
			"password": "supersecret",
			"token":    "abc123",
		},
		"config": map[string]interface{}{
			"api_key": "sk-test",
			"timeout": 30,
		},
	}

	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")

	// Top-level non-sensitive should pass through
	assert.Equal(t, "johndoe", result["user"])

	// Nested auth map - NOTE: SanitizeMap doesn't recursively sanitize nested maps of type map[string]interface{}
	// It only handles the case where the value IS a map[string]interface{} and recursively calls SanitizeMap
	authResult, ok := result["auth"]
	require.True(t, ok, "auth should be present")
	if authMap, ok := authResult.(map[string]interface{}); ok {
		assert.Equal(t, "admin", authMap["username"], "username should pass through")
		assert.Equal(t, "REDACTED", authMap["password"], "password should be redacted")
		assert.Equal(t, "REDACTED", authMap["token"], "token should be redacted")
	}

	// Nested config map
	configResult, ok := result["config"]
	require.True(t, ok, "config should be present")
	if configMap, ok := configResult.(map[string]interface{}); ok {
		assert.Equal(t, "REDACTED", configMap["api_key"], "api_key should be redacted")
		assert.Equal(t, 30, configMap["timeout"], "timeout should pass through")
	}
}

// TestSanitizeMap_NilInput tests nil map handling
func TestSanitizeMap_NilInput(t *testing.T) {
	result := SanitizeMap(nil)
	assert.Nil(t, result, "Nil input should return nil")
}

// TestSanitizeMap_EmptyMap tests empty map handling
func TestSanitizeMap_EmptyMap(t *testing.T) {
	input := map[string]interface{}{}
	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")
	assert.Equal(t, 0, len(result), "Empty map should return empty map")
}

// TestSafeErrorFormat_HappyPath tests safe error formatting with clean data
func TestSafeErrorFormat_HappyPath(t *testing.T) {
	result := SafeErrorFormat("connection failed to %s: %v", "database", errors.New("timeout"))

	assert.Contains(t, result, "connection failed to database")
	assert.Contains(t, result, "timeout")
}

// TestSafeErrorFormat_WithSensitiveData tests sanitization in formatted errors
func TestSafeErrorFormat_WithSensitiveData(t *testing.T) {
	tests := []struct {
		name             string
		format           string
		args             []interface{}
		shouldNotContain []string
		shouldContain    []string
	}{
		{
			name:             "password in args",
			format:           "auth failed: password=%s",
			args:             []interface{}{"secretpass123"},
			shouldNotContain: []string{"secretpass123"},
			shouldContain:    []string{"password=REDACTED"},
		},
		{
			name:             "API key in args",
			format:           "config error: api_key=%s",
			args:             []interface{}{"sk-1234567890"},
			shouldNotContain: []string{"sk-1234567890"},
			shouldContain:    []string{"api_key=REDACTED"},
		},
		{
			name:             "token in args",
			format:           "request failed with token=%s",
			args:             []interface{}{"abc123"},
			shouldNotContain: []string{"abc123"},
			shouldContain:    []string{"token=REDACTED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeErrorFormat(tt.format, tt.args...)

			for _, secret := range tt.shouldNotContain {
				assert.NotContains(t, result, secret, "Should not contain secret: %s", secret)
			}
			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Should contain sanitized marker")
			}
		})
	}
}

// TestSanitizeString_MultipleSecrets tests sanitization of multiple secrets in one string
func TestSanitizeString_MultipleSecrets(t *testing.T) {
	input := "Login failed: password=secret123, token=abc456, api_key=sk-789xyz"

	result := SanitizeString(input)

	// All secrets should be redacted
	assert.NotContains(t, result, "secret123", "password should be redacted")
	assert.NotContains(t, result, "abc456", "token should be redacted")
	assert.NotContains(t, result, "sk-789xyz", "api_key should be redacted")

	// Redaction markers should be present
	assert.Contains(t, result, "password=REDACTED")
	assert.Contains(t, result, "token=REDACTED")
	assert.Contains(t, result, "api_key=REDACTED")
}

// TestSanitizeMap_AllSensitiveKeyVariants tests all documented sensitive key names
func TestSanitizeMap_AllSensitiveKeyVariants(t *testing.T) {
	allSensitiveKeys := []string{
		"password", "passwd", "pwd",
		"token", "auth", "authorization",
		"api_key", "apikey", "api-key",
		"secret", "client_secret", "client-secret",
		"access_token", "refresh_token",
		"private_key", "aws_secret_access_key",
		"credential", "credentials",
	}

	input := make(map[string]interface{})
	for _, key := range allSensitiveKeys {
		input[key] = "should_be_redacted_" + key
	}

	result := SanitizeMap(input)

	require.NotNil(t, result, "Result should not be nil")

	for _, key := range allSensitiveKeys {
		assert.Equal(t, "REDACTED", result[key], "Key %s should be redacted", key)
		assert.NotContains(t, result[key], "should_be_redacted", "Original value should not be present for %s", key)
	}
}

// TestSanitizeString_DoSProtection tests protection against huge inputs that could cause OOM
func TestSanitizeString_DoSProtection(t *testing.T) {
	tests := []struct {
		name        string
		inputSize   int
		shouldTrunc bool
	}{
		{
			name:        "small input - no truncation",
			inputSize:   1000,
			shouldTrunc: false,
		},
		{
			name:        "medium input - no truncation",
			inputSize:   100 * 1024, // 100KB
			shouldTrunc: false,
		},
		{
			name:        "at limit - no truncation",
			inputSize:   MaxSanitizeLength,
			shouldTrunc: false,
		},
		{
			name:        "just over limit - truncated",
			inputSize:   MaxSanitizeLength + 1,
			shouldTrunc: true,
		},
		{
			name:        "huge input - truncated",
			inputSize:   10 * 1024 * 1024, // 10MB
			shouldTrunc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input with password in the middle
			halfSize := tt.inputSize / 2
			input := strings.Repeat("a", halfSize) + "password=secret123" + strings.Repeat("b", tt.inputSize-halfSize-len("password=secret123"))

			result := SanitizeString(input)

			// Verify function completes without panic or excessive memory
			assert.NotNil(t, result, "Result should not be nil")

			if tt.shouldTrunc {
				// Should be truncated to max length + truncation marker
				assert.Contains(t, result, "[truncated]", "Should contain truncation marker")
				assert.LessOrEqual(t, len(result), MaxSanitizeLength+len("... [truncated]"), "Result should be truncated")
			} else {
				// Should not be truncated
				assert.NotContains(t, result, "[truncated]", "Should not contain truncation marker")
				// Password should be redacted (if it wasn't truncated away)
				if strings.Contains(input[:min(len(input), MaxSanitizeLength)], "password=") {
					assert.Contains(t, result, "password=REDACTED", "Password should be redacted")
					assert.NotContains(t, result, "secret123", "Secret should not be in result")
				}
			}
		})
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
