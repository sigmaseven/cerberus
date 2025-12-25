package api

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestDecodeJSONBody tests JSON body decoding with various inputs
func TestDecodeJSONBody(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	api := &API{logger: logger}

	tests := []struct {
		name        string
		body        string
		expectError bool
	}{
		{
			name:        "Valid JSON",
			body:        `{"name": "test", "value": 123}`,
			expectError: false,
		},
		{
			name:        "Invalid JSON - syntax error",
			body:        `{"name": "test"`,
			expectError: true,
		},
		{
			name:        "Empty JSON",
			body:        `{}`,
			expectError: false,
		},
		{
			name:        "Completely invalid",
			body:        `not json at all`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/test", bytes.NewBufferString(tt.body))
			r.Header.Set("Content-Type", "application/json")

			var result map[string]interface{}
			err := api.decodeJSONBody(w, r, &result)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDecodeJSONBodyWithLimit tests JSON body decoding with size limits
func TestDecodeJSONBodyWithLimit(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	api := &API{logger: logger}

	tests := []struct {
		name        string
		body        string
		limit       int64
		expectError bool
	}{
		{
			name:        "Within limit",
			body:        `{"name": "test"}`,
			limit:       100,
			expectError: false,
		},
		{
			name:        "Exact limit",
			body:        `{"name": "test"}`,
			limit:       17, // Exact length of JSON
			expectError: false,
		},
		{
			name:        "Exceeds limit",
			body:        `{"name": "this is a very long string that exceeds the limit"}`,
			limit:       10,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/test", bytes.NewBufferString(tt.body))
			r.Header.Set("Content-Type", "application/json")

			var result map[string]interface{}
			err := api.decodeJSONBodyWithLimit(w, r, &result, tt.limit)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSanitizeErrorMessage_DatabaseConnections tests database connection sanitization
func TestSanitizeErrorMessage_DatabaseConnections(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "MongoDB connection",
			input:    "Failed to connect to mongodb://user:pass@localhost:27017/db",
			expected: "Failed to connect to [DATABASE_CONNECTION]",
		},
		{
			name:     "PostgreSQL connection",
			input:    "Error: postgres://admin:secret@db.example.com:5432/mydb",
			expected: "Error: [DATABASE_CONNECTION]",
		},
		{
			name:     "MySQL connection",
			input:    "Connection error: mysql://root:password@127.0.0.1:3306/app",
			expected: "Connection error: [DATABASE_CONNECTION]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSanitizeErrorMessage_FilePaths tests file path sanitization
func TestSanitizeErrorMessage_FilePaths(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain string
	}{
		{
			name:             "Unix path with extension",
			input:            "Error reading /var/log/app.log",
			shouldNotContain: "/var/log/app.log",
		},
		{
			name:             "Unix path without extension",
			input:            "Error reading /etc/passwd",
			shouldNotContain: "/etc/passwd",
		},
		{
			name:             "Windows path",
			input:            "Failed to open C:\\Windows\\System32\\config.ini",
			shouldNotContain: "C:\\Windows\\System32\\config.ini",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.input)
			assert.NotContains(t, result, tt.shouldNotContain)
			assert.Contains(t, result, "[FILE_PATH]")
		})
	}
}

// TestSanitizeErrorMessage_Credentials tests credential sanitization
func TestSanitizeErrorMessage_Credentials(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		shouldNotContain string
	}{
		{
			name:             "Password field",
			input:            "Login failed: password=SecretPassword123",
			shouldNotContain: "SecretPassword123",
		},
		{
			name:             "API key",
			input:            "Invalid key: api_key=sk_live_abc123",
			shouldNotContain: "sk_live_abc123",
		},
		{
			name:             "Token",
			input:            "Auth error: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			shouldNotContain: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.input)
			assert.NotContains(t, result, tt.shouldNotContain)
			assert.Contains(t, result, "[REDACTED]")
		})
	}
}

// TestNewAuthManager tests AuthManager initialization
func TestNewAuthManager(t *testing.T) {
	am := NewAuthManager()

	require.NotNil(t, am)
	require.NotNil(t, am.revokedTokens)
	require.NotNil(t, am.authRateLimiter)
	require.NotNil(t, am.authFailures)
	// TASK 138: accountFailures field removed as unused
}

// TestAuthManager_RevokeToken tests token revocation
func TestAuthManager_RevokeToken(t *testing.T) {
	am := NewAuthManager()

	jti := "test-jti-12345"

	// Token should not be revoked initially
	assert.False(t, am.IsTokenRevoked(jti))

	// Revoke token
	am.RevokeToken(jti)

	// Token should now be revoked
	assert.True(t, am.IsTokenRevoked(jti))
}

// TestAuthManager_MultipleTokens tests multiple token revocations
func TestAuthManager_MultipleTokens(t *testing.T) {
	am := NewAuthManager()

	tokens := []string{"jti-1", "jti-2", "jti-3"}

	// Revoke all tokens
	for _, jti := range tokens {
		am.RevokeToken(jti)
	}

	// Verify all are revoked
	for _, jti := range tokens {
		assert.True(t, am.IsTokenRevoked(jti))
	}

	// Verify non-existent token is not revoked
	assert.False(t, am.IsTokenRevoked("jti-4"))
}
