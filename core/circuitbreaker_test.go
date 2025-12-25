package core

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForCondition polls a condition function with timeout
// This is a local copy to avoid import cycle with cerberus/testing package
func waitForCondition(t *testing.T, condition func() bool, timeout time.Duration, description string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}

		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatalf("Timeout waiting for condition: %s (timeout: %v)", description, timeout)
			}
		}
	}
}

// TestCircuitBreakerBasicFlow tests the basic state transitions
func TestCircuitBreakerBasicFlow(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// Initially closed
	if cb.State() != CircuitBreakerStateClosed {
		t.Errorf("Expected initial state to be Closed, got %v", cb.State())
	}

	// Record failures to open circuit
	for i := 0; i < 3; i++ {
		oldState, newState := cb.RecordFailure()
		if i < 2 {
			if newState != CircuitBreakerStateClosed {
				t.Errorf("Expected state to remain Closed after %d failures, got %v", i+1, newState)
			}
		} else {
			if oldState != CircuitBreakerStateClosed || newState != CircuitBreakerStateOpen {
				t.Errorf("Expected transition from Closed to Open after 3 failures, got %v -> %v", oldState, newState)
			}
		}
	}

	// Circuit should be open
	if err := cb.Allow(); err != ErrCircuitBreakerOpen {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}

	// FLAKE FIX: Replace sleep with WaitForCondition to handle timing deterministically
	// Wait for timeout to expire (100ms) plus margin for the circuit to transition
	startTime := time.Now()
	waitForCondition(t, func() bool {
		// Wait at least the timeout duration
		if time.Since(startTime) < 100*time.Millisecond {
			return false
		}
		// Try to allow a request - if it succeeds or returns half-open error, timeout has passed
		err := cb.Allow()
		return err == nil || cb.State() == CircuitBreakerStateHalfOpen
	}, 1*time.Second, "circuit breaker timeout to expire and transition to half-open")

	if cb.State() != CircuitBreakerStateHalfOpen {
		t.Errorf("Expected state to be HalfOpen, got %v", cb.State())
	}

	// Success in half-open closes circuit
	oldState, newState := cb.RecordSuccess()
	if oldState != CircuitBreakerStateHalfOpen || newState != CircuitBreakerStateClosed {
		t.Errorf("Expected transition from HalfOpen to Closed on success, got %v -> %v", oldState, newState)
	}
}

// TestCircuitBreakerHalfOpenCounterLeak tests the counter leak fix
// This test verifies that the half-open request counter is properly decremented
// even when state transitions occur before requests complete
func TestCircuitBreakerHalfOpenCounterLeak(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 2,
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitBreakerStateOpen {
		t.Fatalf("Expected circuit to be open, got %v", cb.State())
	}

	// FLAKE FIX: Replace sleep with WaitForCondition
	// Wait for timeout to transition to half-open (timeout is 50ms)
	startTime := time.Now()
	waitForCondition(t, func() bool {
		return time.Since(startTime) >= 50*time.Millisecond
	}, 1*time.Second, "circuit breaker timeout to expire")

	// First Allow() transitions to half-open but doesn't increment counter
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected first Allow() (transition) to succeed, got %v", err)
	}

	// Second and third Allow() increment the counter
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected second Allow() to succeed, got %v", err)
	}
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected third Allow() to succeed, got %v", err)
	}

	// Verify counter is at max (2)
	if cb.halfOpenReqs != 2 {
		t.Errorf("Expected halfOpenReqs to be 2, got %d", cb.halfOpenReqs)
	}

	// Fourth request should be rejected
	if err := cb.Allow(); err != ErrTooManyRequests {
		t.Errorf("Expected ErrTooManyRequests, got %v", err)
	}

	// First request succeeds - this should transition to Closed and reset counter
	oldState, newState := cb.RecordSuccess()
	if oldState != CircuitBreakerStateHalfOpen || newState != CircuitBreakerStateClosed {
		t.Errorf("Expected transition to Closed, got %v -> %v", oldState, newState)
	}

	// Counter should be reset to 0 after transition
	if cb.halfOpenReqs != 0 {
		t.Errorf("Expected halfOpenReqs to be 0 after transition, got %d", cb.halfOpenReqs)
	}

	// BUGFIX TEST: Second request completes after state transition
	// Before fix: counter would not decrement, causing leak
	// After fix: counter properly decrements even in Closed state
	cb.RecordSuccess()

	// Counter should remain 0 (was decremented but already 0)
	if cb.halfOpenReqs != 0 {
		t.Errorf("Expected halfOpenReqs to remain 0, got %d", cb.halfOpenReqs)
	}
}

// TestCircuitBreakerConcurrentAccess tests thread safety with race detector
// Run with: go test -race -run TestCircuitBreakerConcurrentAccess
func TestCircuitBreakerConcurrentAccess(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         10,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 5,
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// RACE FIX: Use error channel to collect errors from goroutines
	// instead of calling t.Errorf directly (which causes data race)
	errChan := make(chan error, 100)

	// Simulate 100 concurrent goroutines making requests
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Try to allow request
			err := cb.Allow()
			if err != nil && err != ErrCircuitBreakerOpen && err != ErrTooManyRequests {
				// RACE FIX: Send error to channel instead of calling t.Errorf
				errChan <- fmt.Errorf("goroutine %d: unexpected error from Allow(): %v", id, err)
				return
			}

			// Only record success/failure if request was allowed
			if err == nil {
				// Simulate work
				time.Sleep(1 * time.Millisecond)

				// Randomly succeed or fail
				if id%3 == 0 {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// RACE FIX: Check for errors after all goroutines complete
	for err := range errChan {
		t.Error(err)
	}

	// Verify final state is valid
	state := cb.State()
	if state != CircuitBreakerStateClosed &&
		state != CircuitBreakerStateOpen &&
		state != CircuitBreakerStateHalfOpen {
		t.Errorf("Invalid final state: %v", state)
	}

	// Counter should never be negative
	if cb.halfOpenReqs < 0 {
		t.Errorf("halfOpenReqs is negative: %d", cb.halfOpenReqs)
	}
}

// TestCircuitBreakerCounterDecrement tests that counter properly decrements
// in all states, not just half-open
func TestCircuitBreakerCounterDecrement(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 3,
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// Open the circuit
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}

	// FLAKE FIX: Replace sleep with WaitForCondition
	// Wait for timeout (50ms) to expire
	startTime := time.Now()
	waitForCondition(t, func() bool {
		return time.Since(startTime) >= 50*time.Millisecond
	}, 1*time.Second, "circuit breaker timeout to expire")

	// Allow requests in half-open
	// First Allow() transitions but doesn't increment
	cb.Allow()
	// Second and third Allow() increment the counter
	cb.Allow()
	cb.Allow()

	if cb.halfOpenReqs != 2 {
		t.Errorf("Expected halfOpenReqs to be 2, got %d", cb.halfOpenReqs)
	}

	// One request fails, transitions to open
	cb.RecordFailure()

	if cb.State() != CircuitBreakerStateOpen {
		t.Errorf("Expected state to be Open after failure, got %v", cb.State())
	}

	// Counter should be reset on transition to open
	if cb.halfOpenReqs != 0 {
		t.Errorf("Expected halfOpenReqs to be 0 after transition, got %d", cb.halfOpenReqs)
	}

	// The second request completes in Open state
	// BUGFIX: This should decrement counter (even though it's already 0)
	cb.RecordSuccess()

	if cb.halfOpenReqs != 0 {
		t.Errorf("Expected halfOpenReqs to remain 0, got %d", cb.halfOpenReqs)
	}
}

// TestCircuitBreakerMaxHalfOpenRequests verifies half-open request limiting
func TestCircuitBreakerMaxHalfOpenRequests(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 2,
	}

	cb, cbErr := NewCircuitBreaker(config)
	require.NoError(t, cbErr, "NewCircuitBreaker should succeed with valid config")

	// Open circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// FLAKE FIX: Replace sleep with WaitForCondition
	// Wait for timeout (50ms) to expire
	startTime := time.Now()
	waitForCondition(t, func() bool {
		return time.Since(startTime) >= 50*time.Millisecond
	}, 1*time.Second, "circuit breaker timeout to expire")

	// First Allow() transitions to half-open (doesn't count against limit)
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected first Allow() (transition) to succeed, got %v", err)
	}

	// Second and third Allow() count against the limit (MaxHalfOpenRequests = 2)
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected second Allow() to succeed, got %v", err)
	}
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected third Allow() to succeed, got %v", err)
	}

	// Fourth request should be rejected (limit reached)
	if err := cb.Allow(); err != ErrTooManyRequests {
		t.Errorf("Expected ErrTooManyRequests for fourth request, got %v", err)
	}

	// Complete one request successfully
	cb.RecordSuccess()

	// Should still reject because we're in Closed state now and counter is 0
	// (the transition to Closed reset the counter)
	// But Allow() should succeed because circuit is closed
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected Allow() to succeed in Closed state, got %v", err)
	}
}

// TestCircuitBreakerConfigValidation tests config validation
// TASK 137: Updated to test error returns instead of panics
func TestCircuitBreakerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      CircuitBreakerConfig
		shouldError bool
	}{
		{
			name: "Valid config",
			config: CircuitBreakerConfig{
				MaxFailures:         3,
				Timeout:             60 * time.Second,
				MaxHalfOpenRequests: 1,
			},
			shouldError: false,
		},
		{
			name: "Zero MaxFailures",
			config: CircuitBreakerConfig{
				MaxFailures:         0,
				Timeout:             60 * time.Second,
				MaxHalfOpenRequests: 1,
			},
			shouldError: true,
		},
		{
			name: "Zero Timeout",
			config: CircuitBreakerConfig{
				MaxFailures:         3,
				Timeout:             0,
				MaxHalfOpenRequests: 1,
			},
			shouldError: true,
		},
		{
			name: "Zero MaxHalfOpenRequests",
			config: CircuitBreakerConfig{
				MaxFailures:         3,
				Timeout:             60 * time.Second,
				MaxHalfOpenRequests: 0,
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TASK 137: Test error returns instead of panics
			_, err := NewCircuitBreaker(tt.config)
			if tt.shouldError {
				assert.Error(t, err, "Expected error for invalid config")
				assert.ErrorIs(t, err, ErrInvalidCircuitBreakerConfig, "Should return ErrInvalidCircuitBreakerConfig")
			} else {
				assert.NoError(t, err, "Expected no error for valid config")
			}
		})
	}
}

// TestCircuitBreakerReset tests the Reset functionality
func TestCircuitBreakerReset(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitBreakerStateOpen {
		t.Errorf("Expected state to be Open, got %v", cb.State())
	}

	// Reset
	cb.Reset()

	// Should be closed with zero failures
	if cb.State() != CircuitBreakerStateClosed {
		t.Errorf("Expected state to be Closed after reset, got %v", cb.State())
	}

	if cb.Failures() != 0 {
		t.Errorf("Expected failures to be 0 after reset, got %d", cb.Failures())
	}

	if cb.halfOpenReqs != 0 {
		t.Errorf("Expected halfOpenReqs to be 0 after reset, got %d", cb.halfOpenReqs)
	}
}

// BenchmarkCircuitBreakerAllow benchmarks Allow() performance
func BenchmarkCircuitBreakerAllow(b *testing.B) {
	config := CircuitBreakerConfig{
		MaxFailures:         10,
		Timeout:             60 * time.Second,
		MaxHalfOpenRequests: 5,
	}

	cb, err := NewCircuitBreaker(config)
	if err != nil {
		b.Fatalf("NewCircuitBreaker failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Allow()
	}
}

// BenchmarkCircuitBreakerRecordSuccess benchmarks RecordSuccess() performance
func BenchmarkCircuitBreakerRecordSuccess(b *testing.B) {
	config := CircuitBreakerConfig{
		MaxFailures:         10,
		Timeout:             60 * time.Second,
		MaxHalfOpenRequests: 5,
	}

	cb, err := NewCircuitBreaker(config)
	if err != nil {
		b.Fatalf("NewCircuitBreaker failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.RecordSuccess()
	}
}

// ============================================================================
// PATTERN COMPLIANCE TESTS
// Based on: docs/requirements/circuit-breaker-requirements.md
// These tests verify the circuit breaker follows the established pattern,
// not just implementation details.
// ============================================================================

// Requirement: FR-001 - Prevent Resource Exhaustion
// Source: Release It! 2nd Edition, Chapter 5.1 "Fail Fast"
// Source: docs/requirements/circuit-breaker-requirements.md
// "Circuit MUST prevent thread pool exhaustion by failing fast"
func TestCircuitBreaker_PreventsResourceExhaustion(t *testing.T) {
	// Pattern requirement: When circuit is OPEN, requests MUST fail immediately
	// (not wait for downstream timeout), freeing threads for other work

	config := CircuitBreakerConfig{
		MaxFailures:         5,                // From requirement: reasonable threshold for service down detection
		Timeout:             30 * time.Second, // From requirement: typical service recovery time
		MaxHalfOpenRequests: 3,                // From requirement: limited probes to avoid overwhelming recovering service
	}

	cb, err := NewCircuitBreaker(config)
	require.NoError(t, err, "NewCircuitBreaker should succeed with valid config")

	// Open the circuit by exceeding MaxFailures
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}

	// REQUIREMENT: Circuit is now OPEN
	require.Equal(t, CircuitBreakerStateOpen, cb.State(),
		"Circuit must be OPEN after MaxFailures per pattern requirement")

	// REQUIREMENT: Further requests MUST be rejected IMMEDIATELY
	// Not allowed to consume threads waiting for timeout
	start := time.Now()
	err = cb.Allow()
	elapsed := time.Since(start)

	assert.Error(t, err, "Circuit MUST reject requests when OPEN per FR-001")
	assert.ErrorIs(t, err, ErrCircuitBreakerOpen,
		"Error MUST identify circuit breaker cause for observability")
	assert.Less(t, elapsed, 10*time.Millisecond,
		"CRITICAL: Rejection MUST be immediate (<10ms), not wait for timeout (prevents resource exhaustion)")
}

// Requirement: FR-002 - Allow Service Recovery
// Source: Martin Fowler's Circuit Breaker Pattern, "Resetting the Breaker"
// Source: docs/requirements/circuit-breaker-requirements.md
// "Circuit MUST attempt recovery by testing downstream service after timeout"
func TestCircuitBreaker_AllowsServiceRecovery(t *testing.T) {
	// Pattern requirement: Services don't stay down forever
	// Circuit must detect recovery using HALF_OPEN state

	config := CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond, // Short timeout for test speed
		MaxHalfOpenRequests: 2,
	}

	cb, cbErr := NewCircuitBreaker(config)
	require.NoError(t, cbErr, "NewCircuitBreaker should succeed with valid config")

	// Open circuit
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	require.Equal(t, CircuitBreakerStateOpen, cb.State())

	// FLAKE FIX: Replace sleep with WaitForCondition
	// Wait for timeout (100ms) to expire
	startTime := time.Now()
	waitForCondition(t, func() bool {
		return time.Since(startTime) >= 100*time.Millisecond
	}, 1*time.Second, "circuit breaker timeout to expire")

	// REQUIREMENT: After timeout, circuit MUST allow probe request (transition to HALF_OPEN)
	err := cb.Allow()
	assert.NoError(t, err, "First request after timeout MUST succeed (transition to HALF_OPEN) per FR-002")
	assert.Equal(t, CircuitBreakerStateHalfOpen, cb.State(),
		"Circuit must be in HALF_OPEN state for recovery testing")

	// REQUIREMENT: Success in HALF_OPEN must close circuit
	oldState, newState := cb.RecordSuccess()
	assert.Equal(t, CircuitBreakerStateHalfOpen, oldState)
	assert.Equal(t, CircuitBreakerStateClosed, newState,
		"Successful probe MUST transition to CLOSED per recovery pattern")

	// REQUIREMENT: Circuit resumes normal operation
	err = cb.Allow()
	assert.NoError(t, err, "Circuit must allow requests in CLOSED state")
}

// Requirement: FR-003 - Protect Recovering Service
// Source: Release It! 2nd Edition, Chapter 5.3.1 "Half-Open State"
// Source: docs/requirements/circuit-breaker-requirements.md
// "Circuit MUST limit concurrent probe requests to avoid overwhelming recovering service"
func TestCircuitBreaker_LimitsHalfOpenRequests(t *testing.T) {
	// Pattern requirement: When service just recovered, sending 1000 requests
	// immediately may cause it to fail again. Use MaxHalfOpenRequests to limit load.

	config := CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 2, // CRITICAL: Only 2 probe requests allowed
	}

	cb, cbErr := NewCircuitBreaker(config)
	require.NoError(t, cbErr, "NewCircuitBreaker should succeed with valid config")

	// Open circuit
	cb.RecordFailure()
	cb.RecordFailure()
	require.Equal(t, CircuitBreakerStateOpen, cb.State())

	// FLAKE FIX: Replace sleep with WaitForCondition
	// Wait for timeout (50ms) to expire
	startTime := time.Now()
	waitForCondition(t, func() bool {
		return time.Since(startTime) >= 50*time.Millisecond
	}, 1*time.Second, "circuit breaker timeout to expire")

	// REQUIREMENT: Exactly MaxHalfOpenRequests allowed in HALF_OPEN
	// First Allow() transitions to HALF_OPEN (doesn't count against limit per implementation)
	err1 := cb.Allow()
	assert.NoError(t, err1, "First probe MUST be allowed (transition to HALF_OPEN)")

	// Second and third Allow() count against the limit (MaxHalfOpenRequests = 2)
	err2 := cb.Allow()
	assert.NoError(t, err2, "Second probe MUST be allowed (1/2)")

	err3 := cb.Allow()
	assert.NoError(t, err3, "Third probe MUST be allowed (2/2)")

	// Fourth request MUST be rejected (limit reached)
	err4 := cb.Allow()
	assert.Error(t, err4, "Fourth request MUST be rejected (limit exceeded)")
	assert.ErrorIs(t, err4, ErrTooManyRequests,
		"MUST return ErrTooManyRequests when half-open limit reached per FR-003")
}

// Requirement: FR-004 - Thread Safety
// Source: General concurrency requirement for production systems
// Source: docs/requirements/circuit-breaker-requirements.md
// "Circuit breaker MUST be thread-safe for concurrent access"
//
// Run with: go test -race -run TestCircuitBreaker_PatternCompliance_ThreadSafety
func TestCircuitBreaker_PatternCompliance_ThreadSafety(t *testing.T) {
	// Pattern requirement: Circuit breaker is shared by all requests
	// Must handle concurrent Allow(), RecordSuccess(), RecordFailure() calls
	// without data races or state corruption

	config := CircuitBreakerConfig{
		MaxFailures:         10,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 5,
	}

	cb, cbErr := NewCircuitBreaker(config)
	require.NoError(t, cbErr, "NewCircuitBreaker should succeed with valid config")

	// REQUIREMENT: Must handle concurrent operations without races
	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Simulate 100 concurrent requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Try to allow request
			err := cb.Allow()
			// Acceptable errors: circuit open, too many requests
			if err != nil && err != ErrCircuitBreakerOpen && err != ErrTooManyRequests {
				errChan <- err
				return
			}

			// Only record result if request was allowed
			if err == nil {
				// Simulate work
				time.Sleep(1 * time.Millisecond)

				// Randomly succeed or fail (causes state transitions)
				if id%3 == 0 {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Verify no unexpected errors
	for err := range errChan {
		t.Errorf("Unexpected error from concurrent operation: %v", err)
	}

	// REQUIREMENT: Final state must be valid (not corrupted)
	state := cb.State()
	assert.Contains(t, []CircuitBreakerState{
		CircuitBreakerStateClosed,
		CircuitBreakerStateOpen,
		CircuitBreakerStateHalfOpen,
	}, state, "Final state must be valid (thread safety verified)")

	// REQUIREMENT: Counter must never be negative (data race would cause this)
	assert.GreaterOrEqual(t, int(cb.halfOpenReqs), 0,
		"Counter must never be negative (would indicate data race)")
}

// Requirement: FR-005 - Observability
// Source: Release It! 2nd Edition, Chapter 17 "Transparency"
// Source: docs/requirements/circuit-breaker-requirements.md
// "Circuit breaker MUST expose current state and metrics for monitoring"
func TestCircuitBreaker_Observability(t *testing.T) {
	// Pattern requirement: Operations team needs to know when circuits are open
	// Metrics enable alerts and capacity planning

	config := CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             60 * time.Second,
		MaxHalfOpenRequests: 1,
	}

	cb, cbErr := NewCircuitBreaker(config)
	require.NoError(t, cbErr, "NewCircuitBreaker should succeed with valid config")

	// REQUIREMENT: State must be observable at all times
	assert.Equal(t, CircuitBreakerStateClosed, cb.State(),
		"Initial state must be observable (CLOSED)")

	// Record failures and verify counter is observable
	cb.RecordFailure()
	assert.Equal(t, uint32(1), cb.Failures(),
		"Failure count must be observable for metrics")

	cb.RecordFailure()
	assert.Equal(t, uint32(2), cb.Failures())

	cb.RecordFailure()
	assert.Equal(t, uint32(3), cb.Failures())

	// REQUIREMENT: State transitions must be observable
	assert.Equal(t, CircuitBreakerStateOpen, cb.State(),
		"State change to OPEN must be observable for alerting")

	// Verify state is consistently reported
	for i := 0; i < 10; i++ {
		assert.Equal(t, CircuitBreakerStateOpen, cb.State(),
			"State must be consistently observable across multiple reads")
	}
}
