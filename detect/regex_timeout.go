package detect

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// RegexWithTimeout matches a pattern against input with a timeout using goroutines
// TASK 32.1: Timeout wrapper using context.WithTimeout() and goroutines
// This provides ReDoS protection by enforcing a maximum execution time for regex matching
func RegexWithTimeout(pattern, input string, timeout time.Duration) (bool, error) {
	if pattern == "" {
		return false, fmt.Errorf("regex pattern cannot be empty")
	}

	if timeout <= 0 {
		return false, fmt.Errorf("timeout must be positive, got: %v", timeout)
	}

	// Compile the regex pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Channel to receive match result
	resultCh := make(chan bool, 1)
	// Channel to receive error
	errCh := make(chan error, 1)

	// Execute regex matching in goroutine
	go func() {
		defer func() {
			// Recover from any panic during regex matching
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("regex matching panic: %v", r)
			}
		}()
		match := re.MatchString(input)
		resultCh <- match
	}()

	// Wait for result or timeout
	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return false, err
	case <-ctx.Done():
		// Timeout occurred
		return false, fmt.Errorf("regex timeout after %v", timeout)
	}
}

// MatchWithTimeout is an alias for RegexWithTimeout for backward compatibility
// TASK 32.1: Convenience function with same signature as task specification
func MatchWithTimeout(pattern, input string, timeout time.Duration) (bool, error) {
	return RegexWithTimeout(pattern, input, timeout)
}
