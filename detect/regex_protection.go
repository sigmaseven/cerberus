package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"cerberus/metrics"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
)

// REQUIREMENT: Task #2 - ReDoS Protection
// TASK 2.1: Use regexp2 library with MatchTimeout for proper backtracking limits
const DefaultRegexTimeout = 500 * time.Millisecond

var ErrRegexTimeout = fmt.Errorf("regex evaluation timeout")

// regexp2Cache stores regexp2 compiled patterns with timeout
var (
	regexp2Cache = make(map[string]*regexp2.Regexp)
	regexp2Mutex sync.RWMutex
)

// EvaluateRegexWithTimeout wraps regex matching with timeout using regexp2
// TASK 2.1: Uses regexp2 library with MatchTimeout to prevent ReDoS attacks
// SECURITY: regexp2 provides proper backtracking limits unlike goroutine-based timeouts
func EvaluateRegexWithTimeout(re *regexp.Regexp, input string, timeout time.Duration) (bool, error) {
	if re == nil {
		return false, fmt.Errorf("regex pattern is nil")
	}
	return EvaluateRegexPatternWithTimeout(re.String(), input, timeout, nil)
}

// EvaluateRegexPatternWithTimeout matches a pattern string against input with timeout
// TASK 2.1: Uses regexp2 library for proper ReDoS protection
func EvaluateRegexPatternWithTimeout(pattern, input string, timeout time.Duration, logger *zap.SugaredLogger) (bool, error) {
	if pattern == "" {
		return false, fmt.Errorf("regex pattern cannot be empty")
	}

	// Create cache key that includes pattern and timeout (different timeouts need different cache entries)
	cacheKey := fmt.Sprintf("%s:%d", pattern, timeout.Milliseconds())

	// Get or compile regexp2 pattern
	regexp2Mutex.RLock()
	re2, exists := regexp2Cache[cacheKey]
	regexp2Mutex.RUnlock()

	if !exists {
		// Compile new pattern (need write lock)
		regexp2Mutex.Lock()
		// Double-check after acquiring write lock (another goroutine may have compiled it)
		re2, exists = regexp2Cache[cacheKey]
		if !exists {
			// Compile new pattern
			var err error
			re2, err = regexp2.Compile(pattern, 0)
			if err != nil {
				regexp2Mutex.Unlock()
				return false, fmt.Errorf("failed to compile regex pattern: %w", err)
			}

			// Set match timeout to prevent ReDoS
			re2.MatchTimeout = timeout

			// Cache the compiled pattern with timeout-specific key
			regexp2Cache[cacheKey] = re2
		}
		regexp2Mutex.Unlock()
	}

	// Ensure we have a valid pattern
	if re2 == nil {
		return false, fmt.Errorf("regexp2 pattern is nil (should not happen)")
	}

	// Match with timeout protection (regexp2 handles timeout internally via MatchTimeout)
	start := time.Now()
	match, err := re2.MatchString(input)
	duration := time.Since(start)

	// TASK 2.5: Record execution duration metric
	metrics.RegexExecutionDuration.WithLabelValues("unknown").Observe(duration.Seconds())

	if err != nil {
		// Check if error is timeout-related (regexp2 may return different error types)
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "timeout") {
			// TASK 2.5: Record timeout metric
			patternHash := hashPattern(pattern)
			metrics.RegexTimeouts.WithLabelValues("unknown", patternHash).Inc()

			// Log timeout event
			if logger != nil {
				logger.Warnf("Regex timeout: pattern may be vulnerable to ReDoS (pattern: %s, timeout: %v, input length: %d)",
					pattern, timeout, len(input))
			}
			return false, ErrRegexTimeout
		}
		return false, fmt.Errorf("regex matching error: %w", err)
	}

	return match, nil
}

// ClearRegexp2Cache clears the regexp2 pattern cache (useful for testing)
func ClearRegexp2Cache() {
	regexp2Mutex.Lock()
	defer regexp2Mutex.Unlock()
	regexp2Cache = make(map[string]*regexp2.Regexp)
}

// hashPattern creates a short hash of a pattern for metrics labeling
func hashPattern(pattern string) string {
	hash := sha256.Sum256([]byte(pattern))
	return hex.EncodeToString(hash[:])[:8] // Use first 8 chars as hash
}
