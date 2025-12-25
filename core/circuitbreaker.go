package core

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	// CircuitBreakerStateClosed means requests pass through normally
	CircuitBreakerStateClosed CircuitBreakerState = "closed"
	// CircuitBreakerStateOpen means requests fail immediately
	CircuitBreakerStateOpen CircuitBreakerState = "open"
	// CircuitBreakerStateHalfOpen means testing if service recovered
	CircuitBreakerStateHalfOpen CircuitBreakerState = "half_open"
)

var (
	// ErrCircuitBreakerOpen is returned when circuit breaker is open
	ErrCircuitBreakerOpen = errors.New("circuit breaker is open")
	// ErrTooManyRequests is returned when too many requests in half-open state
	ErrTooManyRequests = errors.New("too many requests")
)

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit
	MaxFailures uint32
	// Timeout is how long to wait before trying again (open -> half-open)
	Timeout time.Duration
	// MaxHalfOpenRequests is max concurrent requests in half-open state
	MaxHalfOpenRequests uint32
}

// Validate checks if the circuit breaker configuration is valid
func (c *CircuitBreakerConfig) Validate() error {
	if c.MaxFailures == 0 {
		return errors.New("MaxFailures must be greater than 0")
	}
	if c.Timeout <= 0 {
		return errors.New("Timeout must be greater than 0")
	}
	if c.MaxHalfOpenRequests == 0 {
		return errors.New("MaxHalfOpenRequests must be greater than 0")
	}
	return nil
}

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             60 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config       CircuitBreakerConfig
	state        CircuitBreakerState
	failures     uint32
	lastFailTime time.Time
	halfOpenReqs uint32
	mu           sync.RWMutex
}

// ErrInvalidCircuitBreakerConfig is returned when circuit breaker config is invalid
var ErrInvalidCircuitBreakerConfig = errors.New("invalid circuit breaker configuration")

// NewCircuitBreaker creates a new circuit breaker
// TASK 137: Returns error instead of panicking for invalid config
func NewCircuitBreaker(config CircuitBreakerConfig) (*CircuitBreaker, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCircuitBreakerConfig, err)
	}

	return &CircuitBreaker{
		config:       config,
		state:        CircuitBreakerStateClosed,
		failures:     0,
		halfOpenReqs: 0,
	}, nil
}

// MustNewCircuitBreaker creates a new circuit breaker or panics if config is invalid
// Use this for initialization in init() functions where startup validation is acceptable
func MustNewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	cb, err := NewCircuitBreaker(config)
	if err != nil {
		panic(err)
	}
	return cb
}

// Allow checks if a request is allowed through the circuit breaker
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitBreakerStateClosed:
		return nil

	case CircuitBreakerStateOpen:
		// Check if timeout has elapsed
		if time.Since(cb.lastFailTime) > cb.config.Timeout {
			cb.state = CircuitBreakerStateHalfOpen
			cb.halfOpenReqs = 0
			return nil
		}
		return ErrCircuitBreakerOpen

	case CircuitBreakerStateHalfOpen:
		if cb.halfOpenReqs >= cb.config.MaxHalfOpenRequests {
			return ErrTooManyRequests
		}
		cb.halfOpenReqs++
		return nil

	default:
		return nil
	}
}

// RecordSuccess records a successful request
// Returns the old and new state atomically to prevent race conditions
func (cb *CircuitBreaker) RecordSuccess() (oldState, newState CircuitBreakerState) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	oldState = cb.state

	switch cb.state {
	case CircuitBreakerStateClosed:
		cb.failures = 0

	case CircuitBreakerStateHalfOpen:
		// Decrement counter for this completed request
		if cb.halfOpenReqs > 0 {
			cb.halfOpenReqs--
		}
		// Success in half-open state closes the circuit
		cb.state = CircuitBreakerStateClosed
		cb.failures = 0
		cb.halfOpenReqs = 0 // Reset all counters when transitioning to closed
	}

	newState = cb.state
	return
}

// RecordFailure records a failed request
// Returns the old and new state atomically to prevent race conditions
func (cb *CircuitBreaker) RecordFailure() (oldState, newState CircuitBreakerState) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	oldState = cb.state
	cb.lastFailTime = time.Now()
	cb.failures++

	switch cb.state {
	case CircuitBreakerStateClosed:
		if cb.failures >= cb.config.MaxFailures {
			cb.state = CircuitBreakerStateOpen
		}

	case CircuitBreakerStateHalfOpen:
		// Decrement counter for this completed request
		if cb.halfOpenReqs > 0 {
			cb.halfOpenReqs--
		}
		// Failure in half-open state reopens the circuit
		cb.state = CircuitBreakerStateOpen
		cb.halfOpenReqs = 0 // Reset counter when transitioning to open
	}

	newState = cb.state
	return
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Failures returns the current failure count
func (cb *CircuitBreaker) Failures() uint32 {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitBreakerStateClosed
	cb.failures = 0
	cb.halfOpenReqs = 0
}
