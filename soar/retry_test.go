package soar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test error types for classification
type testTimeoutError struct{ error }

func (e *testTimeoutError) Timeout() bool   { return true }
func (e *testTimeoutError) Temporary() bool { return false }

type testTemporaryError struct{ error }

func (e *testTemporaryError) Timeout() bool   { return false }
func (e *testTemporaryError) Temporary() bool { return true }

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	assert.Equal(t, 3, config.MaxAttempts, "Default max attempts should be 3")
	assert.Equal(t, 1*time.Second, config.BaseDelay, "Default base delay should be 1s")
	assert.Equal(t, 120*time.Second, config.MaxDelay, "Default max delay should be 120s")
	assert.Equal(t, 0.1, config.Jitter, "Default jitter should be 10%")

	// FR-SOAR-004: Verify error-type-specific delays
	assert.Equal(t, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second},
		config.ErrorTypeDelays[ErrorTypeTimeout],
		"FR-SOAR-004: Timeout delays should be 5s, 10s, 20s")

	assert.Equal(t, []time.Duration{60 * time.Second, 120 * time.Second},
		config.ErrorTypeDelays[ErrorTypeRateLimit],
		"FR-SOAR-004: Rate limit delays should be 60s, 120s")

	assert.Equal(t, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second},
		config.ErrorTypeDelays[ErrorTypeNetwork],
		"FR-SOAR-004: Network delays should be 5s, 10s, 20s")
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"context_deadline", context.DeadlineExceeded, ErrorTypeTimeout},
		{"timeout_error", &testTimeoutError{errors.New("timeout")}, ErrorTypeTimeout},
		{"temporary_error", &testTemporaryError{errors.New("temporary")}, ErrorTypeNetwork},
		{"http_429", &HTTPStatusError{Code: 429}, ErrorTypeRateLimit},
		{"http_503", &HTTPStatusError{Code: 503}, ErrorTypeTimeout},
		{"http_504", &HTTPStatusError{Code: 504}, ErrorTypeTimeout},
		{"http_500", &HTTPStatusError{Code: 500}, ErrorTypeTemporary},
		{"http_400", &HTTPStatusError{Code: 400}, ErrorTypePermanent},
		{"http_401", &HTTPStatusError{Code: 401}, ErrorTypePermanent},
		{"http_404", &HTTPStatusError{Code: 404}, ErrorTypePermanent},
		{"connection_refused", &net.OpError{Err: syscall.ECONNREFUSED}, ErrorTypeNetwork},
		{"connection_reset", &net.OpError{Err: syscall.ECONNRESET}, ErrorTypeNetwork},
		{"timeout_message", errors.New("operation timed out"), ErrorTypeTimeout},
		{"timeout_message_uppercase", errors.New("Operation Timed Out"), ErrorTypeTimeout},
		{"deadline_exceeded_message", errors.New("deadline exceeded"), ErrorTypeTimeout},
		{"rate_limit_message", errors.New("rate limit exceeded"), ErrorTypeRateLimit},
		{"network_message", errors.New("network unreachable"), ErrorTypeNetwork},
		{"dns_message", errors.New("dns lookup failed"), ErrorTypeNetwork},
		{"temporary_message", errors.New("temporary failure"), ErrorTypeTemporary},
		{"unknown", errors.New("unknown error"), ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			assert.Equal(t, tt.expected, result,
				"Error %v should be classified as %s", tt.err, tt.expected)
			t.Logf("✓ Classified %s as %s", tt.name, result)
		})
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"timeout", &testTimeoutError{errors.New("timeout")}, true},
		{"network", &net.OpError{Err: syscall.ECONNREFUSED}, true},
		{"rate_limit", &HTTPStatusError{Code: 429}, true},
		{"temporary", &testTemporaryError{errors.New("temp")}, true},
		{"permanent_400", &HTTPStatusError{Code: 400}, false},
		{"permanent_404", &HTTPStatusError{Code: 404}, false},
		{"unknown", errors.New("unknown"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldRetry(tt.err)
			assert.Equal(t, tt.expected, result,
				"Error %v should return retryable=%v", tt.err, tt.expected)
		})
	}
}

func TestExecuteWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() error {
		attempts++
		return nil // Success on first attempt
	}

	err := ExecuteWithRetry(ctx, fn, config)
	assert.NoError(t, err)
	assert.Equal(t, 1, attempts, "Should succeed on first attempt")
}

func TestExecuteWithRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.Jitter = 0 // Disable jitter for predictable testing
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 3 {
			return &testTimeoutError{errors.New("timeout")}
		}
		return nil // Success on 3rd attempt
	}

	err := ExecuteWithRetry(ctx, fn, config)
	assert.NoError(t, err)
	assert.Equal(t, 3, attempts, "Should succeed after 2 retries")
}

func TestExecuteWithRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.Jitter = 0
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	testErr := &testTimeoutError{errors.New("persistent timeout")}

	fn := func() error {
		attempts++
		return testErr
	}

	err := ExecuteWithRetry(ctx, fn, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max retries")
	assert.Equal(t, 4, attempts, "Should attempt 4 times (initial + 3 retries)")
}

func TestExecuteWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	permanentErr := &HTTPStatusError{Code: 404, Message: "Not Found"}

	fn := func() error {
		attempts++
		return permanentErr
	}

	err := ExecuteWithRetry(ctx, fn, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-retryable")
	assert.Equal(t, 1, attempts, "Should not retry permanent errors")
}

func TestExecuteWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := DefaultRetryConfig()
	config.Jitter = 0
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() error {
		attempts++
		if attempts == 2 {
			cancel() // Cancel context on 2nd attempt
		}
		return &testTimeoutError{errors.New("timeout")}
	}

	err := ExecuteWithRetry(ctx, fn, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context")
	// Should fail on 2nd or 3rd attempt when context is cancelled
	assert.GreaterOrEqual(t, attempts, 2)
	assert.LessOrEqual(t, attempts, 3)
}

func TestExecuteWithRetry_ErrorTypeDelays(t *testing.T) {
	// Test that different error types get different delays
	tests := []struct {
		name          string
		errorType     ErrorType
		attempt       int
		expectedDelay time.Duration
	}{
		{"timeout_attempt_0", ErrorTypeTimeout, 0, 5 * time.Second},
		{"timeout_attempt_1", ErrorTypeTimeout, 1, 10 * time.Second},
		{"timeout_attempt_2", ErrorTypeTimeout, 2, 20 * time.Second},
		{"rate_limit_attempt_0", ErrorTypeRateLimit, 0, 60 * time.Second},
		{"rate_limit_attempt_1", ErrorTypeRateLimit, 1, 120 * time.Second},
		{"network_attempt_0", ErrorTypeNetwork, 0, 5 * time.Second},
		{"network_attempt_1", ErrorTypeNetwork, 1, 10 * time.Second},
	}

	config := DefaultRetryConfig()
	config.Jitter = 0 // Disable jitter for exact comparison

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := calculateDelay(tt.attempt, tt.errorType, config)
			assert.Equal(t, tt.expectedDelay, delay,
				"FR-SOAR-004: %s attempt %d should have delay %s",
				tt.errorType, tt.attempt, tt.expectedDelay)
		})
	}
}

func TestCalculateDelay_ExponentialBackoff(t *testing.T) {
	config := DefaultRetryConfig()
	config.BaseDelay = 1 * time.Second
	config.Jitter = 0

	// For unknown error type, should use exponential backoff
	delays := []time.Duration{
		calculateDelay(0, ErrorTypeUnknown, config), // 1 * 2^0 = 1s
		calculateDelay(1, ErrorTypeUnknown, config), // 1 * 2^1 = 2s
		calculateDelay(2, ErrorTypeUnknown, config), // 1 * 2^2 = 4s
		calculateDelay(3, ErrorTypeUnknown, config), // 1 * 2^3 = 8s
	}

	assert.Equal(t, 1*time.Second, delays[0])
	assert.Equal(t, 2*time.Second, delays[1])
	assert.Equal(t, 4*time.Second, delays[2])
	assert.Equal(t, 8*time.Second, delays[3])
}

func TestCalculateDelay_MaxDelay(t *testing.T) {
	config := DefaultRetryConfig()
	config.BaseDelay = 1 * time.Second
	config.MaxDelay = 10 * time.Second
	config.Jitter = 0

	// Attempt with large exponent should be capped
	delay := calculateDelay(10, ErrorTypeUnknown, config) // Would be 1024s
	assert.Equal(t, 10*time.Second, delay, "Delay should be capped at MaxDelay")
}

func TestCalculateDelay_Jitter(t *testing.T) {
	config := DefaultRetryConfig()
	config.BaseDelay = 10 * time.Second
	config.Jitter = 0.5 // 50% jitter

	// Run multiple times to test jitter randomness
	delays := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		delays[i] = calculateDelay(0, ErrorTypeUnknown, config)
	}

	// With 50% jitter, delays should be between 5s and 15s
	for i, delay := range delays {
		assert.GreaterOrEqual(t, delay, 5*time.Second,
			"Delay %d should be >= 5s with 50%% jitter", i)
		assert.LessOrEqual(t, delay, 15*time.Second,
			"Delay %d should be <= 15s with 50%% jitter", i)
	}

	// Delays should vary (not all the same)
	allSame := true
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "Jitter should produce varying delays")
}

func TestExecuteWithRetry_OnRetryCallback(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.Jitter = 0
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	callbackCalls := 0
	config.OnRetry = func(attempt int, err error, delay time.Duration) {
		callbackCalls++
		t.Logf("OnRetry called: attempt=%d, error=%v, delay=%s", attempt, err, delay)
	}

	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 3 {
			return &testTimeoutError{errors.New("timeout")}
		}
		return nil
	}

	err := ExecuteWithRetry(ctx, fn, config)
	assert.NoError(t, err)
	assert.Equal(t, 2, callbackCalls, "OnRetry should be called twice (before 2nd and 3rd attempts)")
}

func TestHTTPStatusError(t *testing.T) {
	err := &HTTPStatusError{
		Code:    429,
		Message: "Too Many Requests",
	}

	assert.Equal(t, 429, err.StatusCode())
	assert.Contains(t, err.Error(), "HTTP 429")
	assert.Contains(t, err.Error(), "Too Many Requests")
}

func TestExecuteHTTPWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() (int, error) {
		attempts++
		return 200, nil
	}

	err := ExecuteHTTPWithRetry(ctx, fn, config)
	assert.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func TestExecuteHTTPWithRetry_ErrorResponse(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 2
	config.Jitter = 0
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() (int, error) {
		attempts++
		return 500, nil // Server error
	}

	err := ExecuteHTTPWithRetry(ctx, fn, config)
	require.Error(t, err)
	assert.Equal(t, 3, attempts, "Should retry temporary server errors")
}

func TestExecuteHTTPWithRetry_RateLimit(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 1 // Only 1 retry
	config.Jitter = 0
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() (int, error) {
		attempts++
		if attempts == 1 {
			return 429, nil // Rate limit
		}
		return 200, nil // Success on retry
	}

	startTime := time.Now()
	err := ExecuteHTTPWithRetry(ctx, fn, config)
	duration := time.Since(startTime)

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts)
	// FR-SOAR-004: Rate limit should wait 60s
	assert.GreaterOrEqual(t, duration, 60*time.Second,
		"FR-SOAR-004: Rate limit retry should wait at least 60s")
}

func TestExecuteHTTPWithRetry_PermanentError(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	attempts := 0
	fn := func() (int, error) {
		attempts++
		return 404, nil // Not Found - permanent
	}

	err := ExecuteHTTPWithRetry(ctx, fn, config)
	require.Error(t, err)
	assert.Equal(t, 1, attempts, "Should not retry permanent errors like 404")
}

// BenchmarkExecuteWithRetry_Success benchmarks successful execution
func BenchmarkExecuteWithRetry_Success(b *testing.B) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	logger, _ := zap.NewProduction()
	config.Logger = logger.Sugar()

	fn := func() error {
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExecuteWithRetry(ctx, fn, config)
	}
}

// BenchmarkCalculateDelay benchmarks delay calculation
func BenchmarkCalculateDelay(b *testing.B) {
	config := DefaultRetryConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateDelay(i%5, ErrorTypeTimeout, config)
	}
}

// Example demonstrates basic retry usage
func ExampleExecuteWithRetry() {
	ctx := context.Background()
	config := DefaultRetryConfig()

	attempts := 0
	err := ExecuteWithRetry(ctx, func() error {
		attempts++
		if attempts < 3 {
			return &testTimeoutError{errors.New("timeout")}
		}
		return nil
	}, config)

	if err != nil {
		fmt.Printf("Failed: %v\n", err)
	} else {
		fmt.Printf("Succeeded after %d attempts\n", attempts)
	}
	// Output: Succeeded after 3 attempts
}
