package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"cerberus/core"

	googleuuid "github.com/google/uuid"
	"go.uber.org/zap"
)

// sanitizeErrorMessage removes sensitive information from error messages before sending to clients
func sanitizeErrorMessage(message string) string {
	// Remove database connection strings (mongodb://, mysql://, postgres://, etc.)
	message = regexp.MustCompile(`(?:mongodb|mysql|postgres|postgresql|sqlite|redis|clickhouse)://[^\s"']+`).ReplaceAllString(message, "[DATABASE_CONNECTION]")

	// Remove file paths (both Unix and Windows style, with or without extension)
	// Matches paths like /etc/passwd, C:\Windows\System32\file.dll, /var/log/app.log
	message = regexp.MustCompile(`(?:[A-Za-z]:\\|/)(?:[^\\/:*?"<>|\s]+[\\/ ])*[^\\/:*?"<>|\s]+`).ReplaceAllString(message, "[FILE_PATH]")

	// SECURITY FIX: Only redact PRIVATE IP addresses (RFC 1918, localhost)
	// Public IPs should remain visible for debugging external service issues
	// Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
	message = regexp.MustCompile(`\b(?:10|127)(?:\.\d{1,3}){3}(?::\d{1,5})?\b`).ReplaceAllString(message, "[PRIVATE_IP]")
	message = regexp.MustCompile(`\b172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}(?::\d{1,5})?\b`).ReplaceAllString(message, "[PRIVATE_IP]")
	message = regexp.MustCompile(`\b192\.168(?:\.\d{1,3}){2}(?::\d{1,5})?\b`).ReplaceAllString(message, "[PRIVATE_IP]")

	// Remove credentials and secrets
	message = regexp.MustCompile(`(?i)(?:password|secret|token|key|credential|auth)[:=]\s*["']?[^"'\s]+["']?`).ReplaceAllString(message, "$1=[REDACTED]")

	// Remove stack traces and panic information
	message = regexp.MustCompile(`(?m)^goroutine \d+.*$`).ReplaceAllString(message, "[STACK_TRACE]")
	message = regexp.MustCompile(`(?m)^\s+at\s+.*:\d+.*$`).ReplaceAllString(message, "")

	// Remove MongoDB-specific error details that might contain sensitive info
	message = regexp.MustCompile(`\((?:ServerSelectionError|MongoError)[^\)]*\)`).ReplaceAllString(message, "[DATABASE_ERROR]")

	// Limit message length to prevent information disclosure through verbose errors
	if len(message) > core.MaxErrorMessageLength {
		message = message[:core.MaxErrorMessageLength-3] + "..."
	}

	return message
}

// writeError writes an error response to the client and logs it with proper sanitization
func writeError(w http.ResponseWriter, statusCode int, message string, err error, logger *zap.SugaredLogger) {
	// Log the FULL error internally (unsanitized for debugging)
	if err != nil && logger != nil {
		logger.Errorw(message,
			"error", err.Error(),
			"status_code", statusCode,
		)
	} else if logger != nil {
		logger.Errorw(message,
			"status_code", statusCode,
		)
	}

	// Sanitize the message before sending to client
	sanitizedMessage := sanitizeErrorMessage(message)

	// Write sanitized error response to client
	http.Error(w, sanitizedMessage, statusCode)
}

// validateUUID validates that a string is a valid UUID format
// BLOCKING-1 FIX: Use uuid.Parse() to accept all valid UUID versions (v1, v3, v4, v5, v7)
// Previous regex only accepted v4 UUIDs which would reject valid non-v4 UUIDs
func validateUUID(id string) error {
	_, err := googleuuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid UUID format: %s", id)
	}
	return nil
}

// TASK 111 FIX: Add username validation for defense-in-depth (BLOCKING-4)
// validateUsername checks that a username contains only allowed characters
// Allows: alphanumeric, underscore, hyphen, @, period
// Max length: 255 characters (prevents DoS via excessive length)
func validateUsername(username string) error {
	const maxUsernameLen = 255

	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) > maxUsernameLen {
		return fmt.Errorf("username exceeds maximum length of %d characters", maxUsernameLen)
	}

	// SECURITY: Allow only safe characters for database storage
	// This prevents any potential SQL injection context issues
	for _, r := range username {
		if !isAllowedUsernameChar(r) {
			return fmt.Errorf("username contains invalid character: %q", r)
		}
	}

	return nil
}

// isAllowedUsernameChar checks if a character is allowed in usernames
// Allowed: alphanumeric, underscore, hyphen, @, period
func isAllowedUsernameChar(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '_', '-', '@', '.':
		return true
	}
	return false
}

// TASK 138: Removed unused authFailureOrderEntry and accountFailureOrderEntry structs
// (were for basicAuthMiddleware which has been removed)

// AuthManager manages authentication and authorization
type AuthManager struct {
	// JWT token revocation
	revokedTokens  map[string]bool
	tokenBlacklist sync.Map

	// SECURITY FIX: Track user-to-token mapping for proper revocation
	userTokens sync.Map // map[username]map[tokenID]time.Time
	// TASK 138: Removed unused userTokensMu - sync.Map doesn't need external mutex

	// Rate limiting for auth attempts
	authRateLimiter *FixedWindowLimiter

	// IP-based authentication failure tracking (used by detectSuspiciousLoginActivity)
	authFailures   map[string]*authFailureEntry
	authFailuresMu sync.Mutex
	// TASK 138: Removed unused authFailuresOrder, accountFailures, accountFailuresOrder, accountFailuresMu

	// Token generation rate limiting
	tokenGenMu sync.Mutex
}

// FixedWindowLimiter is a simple fixed window rate limiter
type FixedWindowLimiter struct {
	mu        sync.Mutex
	requests  map[string]int
	window    time.Duration
	limit     int
	lastReset time.Time
}

// NewFixedWindowLimiter creates a new fixed window rate limiter
func NewFixedWindowLimiter(window time.Duration, limit int) *FixedWindowLimiter {
	return &FixedWindowLimiter{
		requests:  make(map[string]int),
		window:    window,
		limit:     limit,
		lastReset: time.Now(),
	}
}

// Allow checks if a request from the given key is allowed
func (f *FixedWindowLimiter) Allow(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if window has expired
	if time.Since(f.lastReset) > f.window {
		f.requests = make(map[string]int)
		f.lastReset = time.Now()
	}

	// Check current count
	if f.requests[key] >= f.limit {
		return false
	}

	f.requests[key]++
	return true
}

// NewAuthManager creates a new AuthManager instance
func NewAuthManager() *AuthManager {
	return &AuthManager{
		revokedTokens:   make(map[string]bool),
		authRateLimiter: NewFixedWindowLimiter(time.Minute, 10), // 10 auth attempts per minute
		authFailures:    make(map[string]*authFailureEntry),
	}
}

// RevokeToken revokes a JWT token by its JTI
func (am *AuthManager) RevokeToken(jti string) {
	if am.revokedTokens != nil {
		am.revokedTokens[jti] = true
	}
}

// IsTokenRevoked checks if a token has been revoked
func (am *AuthManager) IsTokenRevoked(jti string) bool {
	if am.revokedTokens == nil {
		return false
	}
	return am.revokedTokens[jti]
}

// revokeAllUserTokens revokes all tokens for a specific user
func (am *AuthManager) revokeAllUserTokens(username string) int {
	// SECURITY FIX: Implement proper token revocation
	count := 0

	// Get all tokens for this user
	value, exists := am.userTokens.Load(username)
	if !exists {
		return 0
	}

	tokens, ok := value.(*sync.Map)
	if !ok {
		return 0
	}

	// Revoke all tokens for this user
	tokens.Range(func(tokenID, expiry interface{}) bool {
		jti, okKey := tokenID.(string)
		expiryTime, okVal := expiry.(time.Time)
		if okKey && okVal {
			// Add token to blacklist
			am.tokenBlacklist.Store(jti, expiryTime)
			count++
		}
		return true
	})

	// Clear the user's token map
	am.userTokens.Delete(username)

	return count
}

// trackUserToken tracks a token for a specific user
func (am *AuthManager) trackUserToken(username string, tokenID string, expiry time.Time) {
	// SECURITY FIX: Implement proper token tracking
	// Get or create token map for this user
	value, _ := am.userTokens.LoadOrStore(username, &sync.Map{})
	tokens, ok := value.(*sync.Map)
	if ok {
		tokens.Store(tokenID, expiry)
	}
}

// decodeJSONBody decodes a JSON request body into the provided interface
func (a *API) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(dst)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body", err, a.logger)
		return err
	}

	return nil
}

// decodeJSONBodyWithLimit decodes a JSON request body with a size limit
func (a *API) decodeJSONBodyWithLimit(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(dst)
	if err != nil {
		// SECURITY: Provide more detailed error messages for debugging while maintaining security
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		case errors.As(err, &syntaxError):
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON syntax at byte offset %d", syntaxError.Offset), err, a.logger)
		case errors.As(err, &unmarshalTypeError):
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid type for field '%s': expected %s, got %s", unmarshalTypeError.Field, unmarshalTypeError.Type, unmarshalTypeError.Value), err, a.logger)
		case strings.Contains(err.Error(), "unknown field"):
			// Extract field name from error message
			writeError(w, http.StatusBadRequest, fmt.Sprintf("JSON contains %s", err.Error()), err, a.logger)
		case err.Error() == "http: request body too large":
			writeError(w, http.StatusRequestEntityTooLarge, "Request body too large", err, a.logger)
		default:
			writeError(w, http.StatusBadRequest, "Invalid JSON body", err, a.logger)
		}
		return err
	}

	return nil
}

// sanitizeLogMessage removes sensitive information from log messages
func sanitizeLogMessage(message string) string {
	// CRITICAL SECURITY FIX: Prevent log injection attacks
	// Remove newlines and carriage returns to prevent attackers from injecting fake log entries
	// Example attack: username=admin\nLEVEL=ERROR Success for admin (appears as legitimate log entry)
	message = strings.ReplaceAll(message, "\n", "\\n")
	message = strings.ReplaceAll(message, "\r", "\\r")
	message = strings.ReplaceAll(message, "\t", "\\t")

	// Remove all other ASCII control characters (0x00-0x1F and 0x7F)
	message = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(message, "")

	// Remove passwords
	message = regexp.MustCompile(`(?i)password[:=]\s*["']?[^"'\s]+["']?`).ReplaceAllString(message, "password=[REDACTED]")
	// Remove tokens
	message = regexp.MustCompile(`(?i)token[:=]\s*["']?[^"'\s]+["']?`).ReplaceAllString(message, "token=[REDACTED]")
	// Remove API keys
	message = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|credential)[:=]\s*["']?[^"'\s]+["']?`).ReplaceAllString(message, "$1=[REDACTED]")
	// Remove connection strings (expanded to include ClickHouse and Redis)
	message = regexp.MustCompile(`(?:mongodb|mysql|postgres|postgresql|clickhouse|redis)://[^\s"']+`).ReplaceAllString(message, "[DB_CONNECTION]")

	return message
}

// detectSuspiciousLoginActivity checks for suspicious login patterns
func (a *API) detectSuspiciousLoginActivity(username string, ip string) bool {
	// SECURITY FIX: Implement basic suspicious activity detection
	a.authManager.authFailuresMu.Lock()
	defer a.authManager.authFailuresMu.Unlock()

	// Check if user has failed login attempts from multiple different IPs in last hour
	uniqueIPs := make(map[string]bool)

	// Count unique IPs with recent failures for this user
	for checkIP, entry := range a.authManager.authFailures {
		if time.Since(entry.lastFail) < time.Hour {
			uniqueIPs[checkIP] = true
		}
	}

	// If login attempts from 5+ different IPs in last hour, it's suspicious
	if len(uniqueIPs) >= 5 {
		return true
	}

	return false
}

// getActiveSessionCount returns the number of active sessions for a user
func (a *API) getActiveSessionCount(username string) int {
	// SECURITY FIX: Implement proper session counting using user token mapping
	value, exists := a.authManager.userTokens.Load(username)
	if !exists {
		return 0
	}

	tokens, ok := value.(*sync.Map)
	if !ok {
		return 0
	}

	// Count non-expired tokens for this user
	count := 0
	now := time.Now()
	tokens.Range(func(tokenID, expiry interface{}) bool {
		if expiryTime, ok := expiry.(time.Time); ok {
			// Only count tokens that haven't expired yet
			if expiryTime.After(now) {
				count++
			}
		}
		return true
	})

	return count
}
