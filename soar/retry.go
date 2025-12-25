package soar

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// SECURITY REQUIREMENTS:
// FR-SOAR-004: Retry Logic Per Error Type
// - Different retry strategies for different error types
// - Exponential backoff with jitter
// - Timeout errors: 5s, 10s, 20s backoff
// - Rate limit errors (429): 60s, 120s backoff
// - Network errors: 5s, 10s, 20s backoff
//
// RELIABILITY: Prevents retry storms and respects rate limits

// ErrorType represents the category of error for retry logic
type ErrorType string

const (
	ErrorTypeTimeout   ErrorType = "timeout"
	ErrorTypeRateLimit ErrorType = "rate_limit"
	ErrorTypeNetwork   ErrorType = "network"
	ErrorTypeTemporary ErrorType = "temporary"
	ErrorTypePermanent ErrorType = "permanent"
	ErrorTypeUnknown   ErrorType = "unknown"
)

// RetryConfig defines retry behavior for different error types
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts (0 = no retries)
	MaxAttempts int

	// BaseDelay is the initial delay before first retry
	BaseDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// ErrorTypeDelays maps error types to their specific delay sequences
	// FR-SOAR-004: Different delays for different error types
	ErrorTypeDelays map[ErrorType][]time.Duration

	// Jitter adds randomness to prevent thundering herd
	// Value between 0.0 (no jitter) and 1.0 (100% jitter)
	Jitter float64

	// Logger for retry operations
	Logger *zap.SugaredLogger

	// OnRetry is called before each retry attempt
	OnRetry func(attempt int, err error, delay time.Duration)
}

// DefaultRetryConfig returns a retry configuration matching FR-SOAR-004 requirements
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    120 * time.Second,
		Jitter:      0.1, // 10% jitter
		ErrorTypeDelays: map[ErrorType][]time.Duration{
			// FR-SOAR-004: Timeout errors - progressive backoff
			ErrorTypeTimeout: {
				5 * time.Second,
				10 * time.Second,
				20 * time.Second,
			},
			// FR-SOAR-004: Rate limit errors - longer delays to respect limits
			ErrorTypeRateLimit: {
				60 * time.Second,
				120 * time.Second,
			},
			// FR-SOAR-004: Network errors - similar to timeout
			ErrorTypeNetwork: {
				5 * time.Second,
				10 * time.Second,
				20 * time.Second,
			},
			// Temporary errors - exponential backoff
			ErrorTypeTemporary: {
				1 * time.Second,
				2 * time.Second,
				4 * time.Second,
			},
		},
	}
}

// ClassifyError determines the error type for retry logic
// IMPORTANT: Accurate classification ensures appropriate retry behavior
func ClassifyError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	// Check for context deadline exceeded (timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTypeTimeout
	}

	// Check for HTTP status codes
	var httpErr interface{ StatusCode() int }
	if errors.As(err, &httpErr) {
		statusCode := httpErr.StatusCode()
		switch statusCode {
		case http.StatusTooManyRequests: // 429
			return ErrorTypeRateLimit
		case http.StatusServiceUnavailable, // 503
			http.StatusGatewayTimeout, // 504
			http.StatusRequestTimeout: // 408
			return ErrorTypeTimeout
		case http.StatusInternalServerError: // 500
			return ErrorTypeTemporary
		case http.StatusBadRequest, // 400
			http.StatusUnauthorized, // 401
			http.StatusForbidden,    // 403
			http.StatusNotFound:     // 404
			return ErrorTypePermanent
		}
	}

	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrorTypeTimeout
		}
		if netErr.Temporary() {
			return ErrorTypeNetwork
		}
	}

	// Check for syscall errors (connection refused, etc.)
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) ||
			errors.Is(opErr.Err, syscall.ECONNRESET) ||
			errors.Is(opErr.Err, syscall.EPIPE) {
			return ErrorTypeNetwork
		}
	}

	// Check error message for common patterns
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "timed out") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return ErrorTypeTimeout
	}
	if strings.Contains(errMsg, "rate limit") || strings.Contains(errMsg, "too many requests") {
		return ErrorTypeRateLimit
	}
	if strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "network") ||
		strings.Contains(errMsg, "dns") {
		return ErrorTypeNetwork
	}
	if strings.Contains(errMsg, "temporary") {
		return ErrorTypeTemporary
	}

	return ErrorTypeUnknown
}

// ShouldRetry determines if an error is retryable
func ShouldRetry(err error) bool {
	errorType := ClassifyError(err)

	// Permanent errors should not be retried
	if errorType == ErrorTypePermanent {
		return false
	}

	return true
}

// ExecuteWithRetry executes a function with retry logic based on error type
// FR-SOAR-004: Implements error-type-specific retry logic
//
// Parameters:
//
//	ctx: Context for cancellation
//	fn: Function to execute (should be idempotent)
//	config: Retry configuration
//
// Returns: error if all retries failed, nil if succeeded
func ExecuteWithRetry(ctx context.Context, fn func() error, config RetryConfig) error {
	// Initialize logger if not provided
	if config.Logger == nil {
		logger, _ := zap.NewProduction()
		config.Logger = logger.Sugar()
	}

	var lastErr error
	attempt := 0

	for {
		// Check context before attempting
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled before retry attempt %d: %w", attempt+1, err)
		}

		// Attempt execution
		lastErr = fn()

		// Success!
		if lastErr == nil {
			if attempt > 0 {
				config.Logger.Infof("Operation succeeded after %d retries", attempt)
			}
			return nil
		}

		// Classify error
		errorType := ClassifyError(lastErr)

		// Check if error is retryable
		if !ShouldRetry(lastErr) {
			config.Logger.Warnf("Error is not retryable (type: %s): %v", errorType, lastErr)
			return fmt.Errorf("non-retryable error: %w", lastErr)
		}

		// Check if we've exceeded max attempts
		if attempt >= config.MaxAttempts {
			config.Logger.Errorf("Max retry attempts (%d) exceeded for error type %s: %v",
				config.MaxAttempts, errorType, lastErr)
			return fmt.Errorf("max retries (%d) exceeded: %w", config.MaxAttempts, lastErr)
		}

		// Calculate delay based on error type
		delay := calculateDelay(attempt, errorType, config)

		config.Logger.Infow("Retry scheduled",
			"attempt", attempt+1,
			"max_attempts", config.MaxAttempts,
			"error_type", errorType,
			"delay", delay,
			"error", lastErr)

		// Call OnRetry callback if provided
		if config.OnRetry != nil {
			config.OnRetry(attempt+1, lastErr, delay)
		}

		// Wait for delay (with context support)
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during retry delay: %w", ctx.Err())
		}

		attempt++
	}
}

// calculateDelay calculates the delay before next retry based on error type and attempt
// Implements FR-SOAR-004 error-type-specific delays with exponential backoff and jitter
func calculateDelay(attempt int, errorType ErrorType, config RetryConfig) time.Duration {
	var delay time.Duration

	// Get error-type-specific delays
	if delays, ok := config.ErrorTypeDelays[errorType]; ok && attempt < len(delays) {
		// Use pre-defined delay for this error type and attempt
		delay = delays[attempt]
	} else {
		// Fall back to exponential backoff
		// delay = baseDelay * 2^attempt
		delay = config.BaseDelay * time.Duration(1<<uint(attempt))
	}

	// Cap at max delay
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}

	// Add jitter to prevent thundering herd
	// jitter = delay * (1 ± jitter%)
	if config.Jitter > 0 {
		jitterAmount := float64(delay) * config.Jitter
		// Random value between -jitterAmount and +jitterAmount
		jitterDelta := (rand.Float64()*2 - 1) * jitterAmount
		delay = delay + time.Duration(jitterDelta)

		// Ensure delay is positive
		if delay < 0 {
			delay = config.BaseDelay
		}
	}

	return delay
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryableHTTPFunc is an HTTP function that returns status code and error
type RetryableHTTPFunc func() (statusCode int, err error)

// HTTPStatusError wraps HTTP status code for error classification
type HTTPStatusError struct {
	Code    int
	Message string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message)
}

func (e *HTTPStatusError) StatusCode() int {
	return e.Code
}

// ExecuteHTTPWithRetry is a convenience wrapper for HTTP operations
func ExecuteHTTPWithRetry(ctx context.Context, fn RetryableHTTPFunc, config RetryConfig) error {
	return ExecuteWithRetry(ctx, func() error {
		statusCode, err := fn()
		if err != nil {
			return err
		}
		if statusCode < 200 || statusCode >= 300 {
			return &HTTPStatusError{
				Code:    statusCode,
				Message: http.StatusText(statusCode),
			}
		}
		return nil
	}, config)
}

// BEST PRACTICES for using retry logic:
//
// 1. Idempotency: The function being retried MUST be idempotent
//    - Multiple executions should have the same effect as one execution
//    - Use unique IDs or check-before-create patterns
//
// 2. Circuit Breakers: Combine with circuit breakers for failing services
//    - See detect/actions.go for circuit breaker integration
//
// 3. Observability: Log retry attempts for debugging and monitoring
//    - Use structured logging with attempt number, error type, delay
//
// 4. Context Cancellation: Always pass a context for cancellation
//    - Allows graceful shutdown during retries
//
// 5. Error Classification: Ensure ClassifyError accurately identifies error types
//    - Add custom error types as needed for your application
//
// 6. Rate Limiting: Respect rate limits with appropriate backoff
//    - FR-SOAR-004: 60s, 120s for rate limit errors
//
// 7. Jitter: Always use jitter to prevent thundering herd
//    - Especially important for distributed systems

// Example usage:
/*
func sendWebhook(url string, data []byte) error {
	config := DefaultRetryConfig()
	config.Logger = logger

	return ExecuteWithRetry(ctx, func() error {
		resp, err := http.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			return &HTTPStatusError{StatusCode: resp.StatusCode}
		}
		if resp.StatusCode == 429 {
			return &HTTPStatusError{StatusCode: 429}
		}
		if resp.StatusCode >= 400 {
			// Client error - don't retry
			return fmt.Errorf("client error: %d", resp.StatusCode)
		}

		return nil
	}, config)
}
*/
