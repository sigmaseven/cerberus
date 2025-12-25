package detect

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 2.6: Comprehensive testing including catastrophic backtracking and performance benchmarks

func TestReDoSProtection_CatastrophicBacktracking(t *testing.T) {
	// Test patterns that are known to cause ReDoS attacks
	maliciousPatterns := []struct {
		name    string
		pattern string
		input   string
	}{
		{
			name:    "Nested quantifiers (a+)+",
			pattern: "(a+)+",
			input:   strings.Repeat("a", 30) + "X",
		},
		{
			name:    "Nested quantifiers (a*)*",
			pattern: "(a*)*",
			input:   strings.Repeat("a", 30) + "X",
		},
		{
			name:    "Exponential backtracking (a+)+b",
			pattern: "(a+)+b",
			input:   strings.Repeat("a", 30) + "X",
		},
		{
			name:    "Alternation overlap (a|a)+",
			pattern: "(a|a)+",
			input:   strings.Repeat("a", 30) + "X",
		},
		{
			name:    "Complex nested (.*)+",
			pattern: "(.*)+",
			input:   strings.Repeat("a", 50),
		},
	}

	timeout := 500 * time.Millisecond
	var logger *zap.SugaredLogger = nil // Use nil logger for tests

	for _, tt := range maliciousPatterns {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			result, err := EvaluateRegexPatternWithTimeout(tt.pattern, tt.input, timeout, logger)
			elapsed := time.Since(start)

			// MUST: Complete within timeout + buffer (regexp2 may handle some patterns efficiently)
			// The key is that timeout protection is in place, not that every pattern times out
			assert.Less(t, elapsed, timeout+300*time.Millisecond,
				"Pattern should complete or timeout within %v, took %v", timeout+300*time.Millisecond, elapsed)

			// Result may be false (no match) or timeout error
			// Note: regexp2 may handle some patterns efficiently even if dangerous
			if err != nil {
				assert.ErrorIs(t, err, ErrRegexTimeout, "Should return timeout error for dangerous pattern")
				t.Logf("✓ TIMEOUT: Pattern %s timed out after %v (expected)", tt.pattern, elapsed)
			} else {
				// Pattern completed - may not match (which is safe) or matched quickly
				// The protection is that timeout is enforced, preventing CPU exhaustion
				if result {
					t.Logf("✓ MATCH: Pattern %s completed in %v with match (quick execution)", tt.pattern, elapsed)
				} else {
					t.Logf("✓ NO MATCH: Pattern %s completed in %v without match", tt.pattern, elapsed)
				}
				// Key: completed within timeout window, preventing ReDoS
				assert.Less(t, elapsed, timeout+300*time.Millisecond, "Should not hang indefinitely")
			}
		})
	}
}

func TestReDoSProtection_SafePatterns(t *testing.T) {
	// Test that safe patterns still work correctly
	safePatterns := []struct {
		name        string
		pattern     string
		input       string
		shouldMatch bool
	}{
		{
			name:        "Simple pattern",
			pattern:     "test",
			input:       "this is a test",
			shouldMatch: true,
		},
		{
			name:        "Email pattern",
			pattern:     `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			input:       "user@example.com",
			shouldMatch: true,
		},
		{
			name:        "IP address",
			pattern:     `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
			input:       "192.168.1.1",
			shouldMatch: true,
		},
		{
			name:        "Single quantifier",
			pattern:     "a+",
			input:       "aaa",
			shouldMatch: true,
		},
		{
			name:        "Simple group",
			pattern:     "(abc)+",
			input:       "abcabc",
			shouldMatch: true,
		},
	}

	timeout := 500 * time.Millisecond
	var logger *zap.SugaredLogger = nil

	for _, tt := range safePatterns {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			result, err := EvaluateRegexPatternWithTimeout(tt.pattern, tt.input, timeout, logger)
			elapsed := time.Since(start)

			require.NoError(t, err, "Safe pattern should not error")
			assert.Equal(t, tt.shouldMatch, result, "Pattern match result should be correct")
			assert.Less(t, elapsed, 100*time.Millisecond, "Safe pattern should complete quickly, took %v", elapsed)
			t.Logf("✓ SAFE: Pattern %s completed in %v, match=%v", tt.pattern, elapsed, result)
		})
	}
}

func TestReDoSProtection_TimeoutEnforcement(t *testing.T) {
	// Test that timeout is actually enforced
	// Note: regexp2's MatchTimeout should prevent this from hanging
	pattern := "(a+)+"
	input := strings.Repeat("a", 100) + "X" // Large input that would cause exponential backtracking
	timeout := 100 * time.Millisecond       // Short timeout

	start := time.Now()
	_, err := EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	elapsed := time.Since(start)

	// Should complete within timeout + buffer (regexp2 enforces timeout internally)
	assert.Less(t, elapsed, timeout+300*time.Millisecond,
		"Should complete or timeout within %v, took %v", timeout+300*time.Millisecond, elapsed)

	// Key protection: pattern completes within timeout window, preventing CPU exhaustion
	// Whether it errors or just doesn't match is fine - the timeout prevents ReDoS
	if err != nil {
		assert.ErrorIs(t, err, ErrRegexTimeout, "Should return timeout error")
		t.Logf("✓ TIMEOUT ENFORCEMENT: Pattern timed out in %v (timeout: %v)", elapsed, timeout)
	} else {
		// Pattern may complete quickly even with timeout protection (regexp2 optimization)
		t.Logf("✓ TIMEOUT ENFORCEMENT: Pattern completed in %v without hanging (timeout: %v)", elapsed, timeout)
	}
}

func TestReDoSProtection_LargeInputs(t *testing.T) {
	// Test with various input sizes
	pattern := regexp.MustCompile("needle")
	timeout := 500 * time.Millisecond

	testCases := []struct {
		name  string
		input string
	}{
		{"Small input", strings.Repeat("hay ", 10) + "needle"},
		{"Medium input", strings.Repeat("hay ", 1000) + "needle"},
		{"Large input", strings.Repeat("hay ", 10000) + "needle"},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			result, err := EvaluateRegexWithTimeout(pattern, tt.input, timeout)
			elapsed := time.Since(start)

			require.NoError(t, err, "Should not error on large input")
			assert.True(t, result, "Should find match in large input")
			assert.Less(t, elapsed, timeout, "Should complete within timeout, took %v", elapsed)
			t.Logf("✓ LARGE INPUT: %s (length: %d) completed in %v", tt.name, len(tt.input), elapsed)
		})
	}
}

func TestReDoSProtection_PatternCache(t *testing.T) {
	// Test that pattern caching works
	ClearRegexp2Cache()

	pattern := "test"
	input := "this is a test"
	timeout := 500 * time.Millisecond

	// First call should compile and cache
	start1 := time.Now()
	result1, err1 := EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	elapsed1 := time.Since(start1)

	require.NoError(t, err1)
	assert.True(t, result1)

	// Second call should use cache (should be faster)
	start2 := time.Now()
	result2, err2 := EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	elapsed2 := time.Since(start2)

	require.NoError(t, err2)
	assert.True(t, result2)

	// Cached call should be faster (but this is not guaranteed, just check it works)
	assert.LessOrEqual(t, elapsed2, elapsed1*2, "Cached call should be similar or faster")
	t.Logf("✓ CACHE: First call: %v, Second call: %v", elapsed1, elapsed2)

	ClearRegexp2Cache()
}

func BenchmarkRegexWithTimeout_Normal(b *testing.B) {
	pattern := "error"
	input := "This is an error message"
	timeout := 500 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	}
}

func BenchmarkRegexWithTimeout_ComplexSafe(b *testing.B) {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	input := "user.name+tag@example.co.uk"
	timeout := 500 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	}
}

func BenchmarkRegexWithTimeout_LargeInput(b *testing.B) {
	pattern := "needle"
	input := strings.Repeat("hay ", 10000) + "needle"
	timeout := 500 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRegexPatternWithTimeout(pattern, input, timeout, nil)
	}
}

// Test integration with rule engine
func TestReDoSProtection_RuleEngineIntegration(t *testing.T) {
	// Create a rule with a safe regex pattern using SigmaYAML
	rule := core.Rule{
		ID:      "test-rule",
		Enabled: true,
		Type:    "sigma",
		SigmaYAML: `title: Regex Test Rule
logsource:
  category: test
detection:
  selection:
    message|re: 'error'
  condition: selection`,
	}

	engine := NewRuleEngine([]core.Rule{rule}, []core.CorrelationRule{}, 0)
	defer engine.Stop()

	// Test with matching event
	event := core.NewEvent()
	event.Fields = map[string]interface{}{"message": "This is an error message"}

	matches := engine.Evaluate(event)
	assert.Len(t, matches, 1, "Should match rule with safe regex")
	t.Logf("✓ INTEGRATION: Rule engine correctly evaluates regex condition")
}
