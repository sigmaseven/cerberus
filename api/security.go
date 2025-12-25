package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"cerberus/metrics"
)

// csrfProtectionMiddleware provides CSRF protection for state-changing operations
func (a *API) csrfProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FIXED: Skip CSRF protection entirely when auth is disabled
		if !a.config.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Only check CSRF for state-changing methods
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")
		requestID := generateRequestID()

		// ENHANCED: Get CSRF token from cookie with validation
		csrfCookie, err := r.Cookie("csrf_token")
		if err != nil {
			a.logger.Warnf("CSRF AUDIT: Cookie missing - IP: %s, Method: %s, Path: %s, User-Agent: %s, RequestID: %s",
				clientIP, r.Method, r.URL.Path, userAgent, requestID)
			a.writeCSRFError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}

		// Validate CSRF token format and security properties
		if !isValidCSRFCookieToken(csrfCookie.Value) {
			a.logger.Errorf("CSRF AUDIT: Invalid cookie token format - IP: %s, Method: %s, Path: %s, RequestID: %s",
				clientIP, r.Method, r.URL.Path, requestID)
			a.writeCSRFError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}

		// ENHANCED: Get CSRF token from header with validation
		csrfHeader := r.Header.Get("X-CSRF-Token")
		if csrfHeader == "" {
			a.logger.Warnf("CSRF AUDIT: Header missing - IP: %s, Method: %s, Path: %s, RequestID: %s",
				clientIP, r.Method, r.URL.Path, requestID)
			a.writeCSRFError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}

		// Validate header token format
		if !isValidCSRFHeaderToken(csrfHeader) {
			a.logger.Errorf("CSRF AUDIT: Invalid header token format - IP: %s, Method: %s, Path: %s, RequestID: %s",
				clientIP, r.Method, r.URL.Path, requestID)
			a.writeCSRFError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}

		// ENHANCED: Timing-safe token comparison to prevent timing attacks
		if !compareCSRFTokenTimingSafe(csrfCookie.Value, csrfHeader) {
			a.logger.Errorf("CSRF AUDIT: Token mismatch - IP: %s, Method: %s, Path: %s, User-Agent: %s, RequestID: %s",
				clientIP, r.Method, r.URL.Path, userAgent, requestID)

			a.writeCSRFError(w, http.StatusForbidden, "CSRF token missing or invalid")
			return
		}

		// SUCCESS: Log successful CSRF validation for audit trail
		a.logger.Debugf("CSRF AUDIT: Validation successful - IP: %s, Method: %s, Path: %s, RequestID: %s",
			clientIP, r.Method, r.URL.Path, requestID)

		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicyMiddleware adds Content Security Policy headers
func (a *API) contentSecurityPolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set restrictive CSP for API responses
		// This prevents XSS attacks if API responses are ever rendered as HTML
		csp := "default-src 'none'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'none'; " +
			"form-action 'none'"

		// For Swagger UI paths, allow necessary resources with nonce-based CSP
		if strings.HasPrefix(r.URL.Path, "/swagger/") {
			// Generate a cryptographically secure nonce for this request
			nonce := generateNonce()
			// Store nonce in request context for use by handlers
			ctx := WithCSPNonce(r.Context(), nonce)
			r = r.WithContext(ctx)

			csp = "default-src 'self'; " +
				"script-src 'self' https://cdn.jsdelivr.net 'nonce-" + nonce + "'; " +
				"style-src 'self' https://cdn.jsdelivr.net 'nonce-" + nonce + "'; " +
				"img-src 'self' data: https://cdn.jsdelivr.net; " +
				"font-src 'self' https://cdn.jsdelivr.net; " +
				"frame-ancestors 'none'; " +
				"base-uri 'self'"
		}

		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Add HSTS if TLS is enabled
		if a.config.API.TLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		next.ServeHTTP(w, r)
	})
}

// errorRecoveryMiddleware provides centralized error handling and panic recovery
// TASK 137.4: Enhanced with full stack trace logging, request context, and metrics
func (a *API) errorRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Capture full stack trace for debugging
				stackBuf := make([]byte, 4096)
				stackLen := captureStack(stackBuf)
				stackTrace := string(stackBuf[:stackLen])

				// Extract request context for logging
				requestID := GetRequestIDOrDefault(r.Context())
				username, _ := GetUsername(r.Context())
				clientIP := getClientIP(r)
				method := r.Method
				path := sanitizePath(r.URL.Path) // Sanitize path for logging and metrics

				// TASK 137.4: Log panic with full context for debugging
				// Stack trace is logged server-side only, never sent to client
				a.logger.Errorw("PANIC RECOVERED",
					"error", sanitizeLogMessage(fmt.Sprintf("%v", err)),
					"request_id", requestID,
					"method", method,
					"path", path,
					"username", username,
					"client_ip", clientIP,
					"stack_trace", stackTrace,
				)

				// TASK 137.4: Increment panic metrics
				incrementAPIPanicMetric(method, path)

				// Send sanitized error response (no stack trace to client)
				writeError(w, http.StatusInternalServerError, "Internal server error", fmt.Errorf("panic: %v", err), a.logger)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// captureStack captures the current goroutine's stack trace into buf
// Returns the number of bytes written
func captureStack(buf []byte) int {
	return runtime.Stack(buf, false)
}

// sanitizePath removes sensitive parts from URL paths for logging and metrics
// Replaces IDs and tokens with placeholders to prevent high cardinality metrics
func sanitizePath(path string) string {
	// Replace UUIDs (common for IDs in URLs)
	path = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`).ReplaceAllString(path, "{uuid}")

	// Replace numeric IDs
	path = regexp.MustCompile(`/\d+(/|$)`).ReplaceAllString(path, "/{id}$1")

	// Replace MongoDB ObjectIDs (24 hex chars)
	path = regexp.MustCompile(`[0-9a-fA-F]{24}`).ReplaceAllString(path, "{oid}")

	// Limit path length
	if len(path) > 100 {
		path = path[:97] + "..."
	}

	return path
}

// incrementAPIPanicMetric increments the panic counter metric
// TASK 137.4: Metric for tracking recovered panics
func incrementAPIPanicMetric(method, path string) {
	metrics.APIPanicsRecovered.WithLabelValues(method, path).Inc()
}

// errorSanitizationMiddleware ensures all error responses are properly sanitized
func (a *API) errorSanitizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the response writer to capture and sanitize error responses
		sanitizedWriter := &sanitizedResponseWriter{
			ResponseWriter: w,
			logger:         a.logger,
		}

		next.ServeHTTP(sanitizedWriter, r)
	})
}

// sanitizedResponseWriter wraps http.ResponseWriter to sanitize error responses
type sanitizedResponseWriter struct {
	http.ResponseWriter
	logger          interface{ Errorf(string, ...interface{}) }
	statusCode      int
	wroteHeader     bool
	isErrorResponse bool
	// TASK 138: Removed unused body field
}

func (w *sanitizedResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	if code >= 400 {
		w.isErrorResponse = true
	}
	w.ResponseWriter.WriteHeader(code)
	w.wroteHeader = true
}

func (w *sanitizedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if w.isErrorResponse {
		// Sanitize error response body
		sanitizedData := w.sanitizeErrorResponse(data)
		return w.ResponseWriter.Write(sanitizedData)
	}

	return w.ResponseWriter.Write(data)
}

// sanitizeErrorResponse removes sensitive information from error response bodies
func (w *sanitizedResponseWriter) sanitizeErrorResponse(data []byte) []byte {
	responseStr := string(data)

	// Remove stack traces (Go stack traces start with goroutine or file:line patterns)
	stackTracePatterns := []string{
		`goroutine \d+ \[.*?\]:`,
		`\n\t.*?\..*?:\d+ .*?\n`,
		`runtime\..*?\n`,
		`panic: .*?\n`,
		`fatal error: .*?\n`,
	}

	for _, pattern := range stackTracePatterns {
		if matched, _ := regexp.MatchString(pattern, responseStr); matched {
			// If stack trace detected, replace entire response with generic message
			return []byte(`{"error":"Internal server error","message":"An unexpected error occurred"}`)
		}
	}

	// Remove internal file paths
	responseStr = regexp.MustCompile(`(?:/[^/\s]+)+/\w+\.go:\d+`).ReplaceAllString(responseStr, "[FILE]")

	// Remove database connection strings
	responseStr = regexp.MustCompile(`(?:mongodb|mysql|postgres|sqlite)://[^\s"']+`).ReplaceAllString(responseStr, "[DB_CONNECTION]")

	// Remove API keys and tokens
	responseStr = regexp.MustCompile(`(?i)(?:api[_-]?key|token|secret|password|credential).*?[:=]\s*["'][^"']+["']`).ReplaceAllString(responseStr, `"$1":"[REDACTED]"`)

	// HIGH SECURITY FIX: Only redact PRIVATE/INTERNAL IP addresses and hostnames
	// Original code redacted ALL IPs/hostnames including public ones, breaking error messages
	// Private IP ranges per RFC 1918 and RFC 5735:
	// - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
	// - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	// - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
	// - 127.0.0.0/8 (localhost)
	responseStr = regexp.MustCompile(`\b(?:10|127)(?:\.\d{1,3}){3}\b`).ReplaceAllString(responseStr, "[PRIVATE_IP]")
	responseStr = regexp.MustCompile(`\b172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}\b`).ReplaceAllString(responseStr, "[PRIVATE_IP]")
	responseStr = regexp.MustCompile(`\b192\.168(?:\.\d{1,3}){2}\b`).ReplaceAllString(responseStr, "[PRIVATE_IP]")

	// Only redact internal/private domain names (*.local, *.internal, *.corp)
	// Leave public domain names intact so users can debug external service failures
	responseStr = regexp.MustCompile(`\b[a-zA-Z0-9-]+\.(?:local|internal|corp|lan|home)\b`).ReplaceAllString(responseStr, "[INTERNAL_HOSTNAME]")

	// Remove MongoDB ObjectIDs and other internal IDs
	responseStr = regexp.MustCompile(`[a-fA-F0-9]{24}`).ReplaceAllString(responseStr, "[ID]")

	// Limit error message length
	if len(responseStr) > 500 {
		responseStr = responseStr[:497] + "..."
	}

	return []byte(responseStr)
}

// generateNonce creates a cryptographically secure random nonce for CSP
func generateNonce() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to a simple timestamp-based nonce if crypto/rand fails
		return base64.StdEncoding.EncodeToString([]byte(time.Now().String()))[:16]
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// getRealIP extracts the real client IP from the request, considering proxy trust settings
func getRealIP(r *http.Request, trustProxy bool, trustedNetworks []string) string {
	if !trustProxy {
		// If not trusting proxies, just return the direct connection IP
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return ip
	}

	// Check if the direct connection is from a trusted proxy network
	directIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		directIP = r.RemoteAddr
	}

	// If direct IP is in trusted networks, trust the forwarded headers
	if isTrustedProxy(directIP, trustedNetworks) {
		// Check X-Forwarded-For header (most common with proxies/load balancers)
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one (original client)
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				if ip != "" && net.ParseIP(ip) != nil {
					return ip
				}
			}
		}

		// Check X-Real-IP header (used by nginx)
		xri := r.Header.Get("X-Real-IP")
		if xri != "" && net.ParseIP(xri) != nil {
			return xri
		}

		// Check X-Client-IP header
		xci := r.Header.Get("X-Client-IP")
		if xci != "" && net.ParseIP(xci) != nil {
			return xci
		}

		// Check CF-Connecting-IP (Cloudflare)
		cfip := r.Header.Get("CF-Connecting-IP")
		if cfip != "" && net.ParseIP(cfip) != nil {
			return cfip
		}
	}

	// Fallback to direct connection IP
	return directIP
}

// isTrustedProxy checks if an IP address is in the list of trusted proxy networks
func isTrustedProxy(ip string, trustedNetworks []string) bool {
	if len(trustedNetworks) == 0 {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, network := range trustedNetworks {
		if strings.Contains(network, "/") {
			// CIDR notation
			_, ipNet, err := net.ParseCIDR(network)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		} else {
			// Exact IP match
			if network == ip {
				return true
			}
		}
	}

	return false
}

// TASK 138: Removed unused isIPAllowed function
// Note: getClientIP is defined in feed_handlers.go

// CSRF token validation functions
func isValidCSRFCookieToken(token string) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}

	entropy := calculateShannonEntropy(token)
	// SECURITY FIX: Hex-encoded tokens have ~3.7 bits/char, not 5.95
	// The original threshold of 4.8 rejected all hex tokens generated by the system
	// Lowered to 3.5 to allow legitimate hex-encoded crypto/rand tokens
	if entropy < 3.5 {
		return false
	}

	// SECURITY FIX: Pattern checks disabled for crypto/rand tokens
	// Random hex data can contain "sequential" or "repeated" patterns by pure chance
	// This was causing ~20% false rejection rate for legitimate crypto/rand tokens
	// Entropy + length + distribution checks are sufficient for cryptographic security
	// if hasSequentialPatterns(token) { return false }
	// if hasRepeatedPatterns(token) { return false }

	hasGoodDist := hasReasonableDistribution(token)
	if !hasGoodDist {
		return false
	}

	return true
}

func isValidCSRFHeaderToken(token string) bool {
	return len(token) >= 32 && len(token) <= 128 && !strings.Contains(token, "\n") && !strings.Contains(token, "\r")
}

func compareCSRFTokenTimingSafe(cookieToken, headerToken string) bool {
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) == 1
}

// Entropy and pattern analysis functions for CSRF token validation
func calculateShannonEntropy(token string) float64 {
	if len(token) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range token {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(token))
	for _, count := range freq {
		prob := count / length
		entropy -= prob * (math.Log2(prob))
	}

	return entropy
}

// TASK 138: Removed unused hasSequentialPatterns and hasRepeatedPatterns functions
// (these were disabled in isValidCSRFCookieToken per SECURITY FIX comment)

func hasReasonableDistribution(token string) bool {
	if len(token) < 32 {
		return false
	}

	// HIGH SECURITY FIX: Hex-encoded tokens from crypto/rand only contain [0-9a-fA-F]
	// The original validation rejected these cryptographically secure tokens
	// Accept hex tokens (common for CSRF tokens generated with crypto/rand + hex.EncodeToString)
	isHex := regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(token)

	// Accept base64/base64url tokens (another common encoding for crypto/rand output)
	isBase64 := regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`).MatchString(token)

	// If token is hex or base64 encoded, it's acceptable for cryptographic tokens
	if isHex || isBase64 {
		return true
	}

	// For non-standard token formats, require mixed character types
	hasLower := strings.ContainsAny(token, "abcdefghijklmnopqrstuvwxyz")
	hasUpper := strings.ContainsAny(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasDigit := strings.ContainsAny(token, "0123456789")
	hasSpecial := strings.ContainsAny(token, "!@#$%^&*()_+-=[]{}|;:,.<>?")

	return (hasLower || hasUpper) && (hasDigit || hasSpecial)
}

// TASK 138: Removed unused isKeyboardSequential, getHostname, getSecurityRelevantHeaders functions

func generateRequestID() string {
	// Generate 16 random bytes for high entropy
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto rand fails
		return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), os.Getpid())
	}

	// Encode as base64url for URL-safe ID
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// TASK 138: Removed unused responseWriter struct (sanitizedResponseWriter is used instead)

// CSRFErrorResponse represents a CSRF validation error response
// S3: CSRF Protection - matches E2E test expectations
type CSRFErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// writeCSRFError writes a JSON CSRF error response with code and error fields
// S3: CSRF Protection - returns standardized error format for E2E tests
// BLOCKER 2 FIX: Now a method on *API for access to logger
func (a *API) writeCSRFError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(CSRFErrorResponse{
		Code:  "CSRF_INVALID",
		Error: message,
	}); err != nil {
		// Response already started, log for monitoring
		a.logger.Errorw("Failed to encode CSRF error response",
			"error", err,
			"message", message)
	}
}
