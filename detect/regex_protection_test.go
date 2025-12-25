package detect

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// REQUIREMENT: Task #2 - ReDoS Protection Tests

func TestEvaluateRegexWithTimeout_NormalPattern(t *testing.T) {
	pattern := regexp.MustCompile("test")
	input := "this is a test string"
	timeout := 500 * time.Millisecond

	start := time.Now()
	result, err := EvaluateRegexWithTimeout(pattern, input, timeout)
	elapsed := time.Since(start)

	require.NoError(t, err, "Normal pattern should not timeout")
	assert.True(t, result, "Should find match")
	assert.Less(t, elapsed, 100*time.Millisecond, "Should complete quickly")

	t.Logf("✓ PERFORMANCE: Pattern executed in %v", elapsed)
}

func TestEvaluateRegexWithTimeout_ComplexPattern(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	input := "user@example.com"
	timeout := 500 * time.Millisecond

	start := time.Now()
	result, err := EvaluateRegexWithTimeout(pattern, input, timeout)
	elapsed := time.Since(start)

	require.NoError(t, err, "Complex safe pattern should work")
	assert.True(t, result, "Should match email")
	assert.Less(t, elapsed, 100*time.Millisecond, "Should complete quickly")

	t.Logf("✓ PERFORMANCE: Complex pattern executed in %v", elapsed)
}

func TestEvaluateRegexWithTimeout_LargeInput(t *testing.T) {
	pattern := regexp.MustCompile("needle")
	input := strings.Repeat("hay ", 10000) + "needle"
	timeout := 500 * time.Millisecond

	start := time.Now()
	result, err := EvaluateRegexWithTimeout(pattern, input, timeout)
	elapsed := time.Since(start)

	// Should complete (RE2 is efficient) or timeout gracefully
	if err != nil {
		assert.ErrorIs(t, err, ErrRegexTimeout, "Should timeout gracefully if too slow")
		t.Logf("✓ RESOURCE LIMIT: Large input timed out after %v", elapsed)
	} else {
		require.NoError(t, err, "Should complete or timeout gracefully")
		assert.True(t, result, "Should find needle if completed")
		t.Logf("✓ PERFORMANCE: Large input (%d bytes) processed in %v", len(input), elapsed)
	}
}

func TestEvaluateRegexWithTimeout_NilPattern(t *testing.T) {
	result, err := EvaluateRegexWithTimeout(nil, "test", 100*time.Millisecond)

	require.Error(t, err, "Nil regex pattern should return error")
	assert.False(t, result, "Nil pattern should return false")
	assert.Contains(t, err.Error(), "nil", "Error should mention nil pattern")

	t.Log("✓ DEFENSIVE: Nil pattern handled gracefully")
}

func TestEvaluateRegexWithTimeout_EmptyInput(t *testing.T) {
	pattern := regexp.MustCompile("^$")
	emptyInput := ""

	start := time.Now()
	result, err := EvaluateRegexWithTimeout(pattern, emptyInput, 100*time.Millisecond)
	elapsed := time.Since(start)

	require.NoError(t, err, "Empty input should not cause timeout")
	assert.True(t, result, "Pattern ^$ should match empty string")
	assert.Less(t, elapsed, 10*time.Millisecond, "Empty input should complete instantly")

	t.Logf("✓ EDGE CASE: Empty input handled correctly in %v", elapsed)
}

func TestDefaultRegexTimeout(t *testing.T) {
	assert.Equal(t, 500*time.Millisecond, DefaultRegexTimeout, "Default timeout should be 500ms")
	t.Log("✓ CONFIG: Default timeout is 500ms as per requirement")
}

func TestErrRegexTimeout(t *testing.T) {
	assert.NotNil(t, ErrRegexTimeout, "Timeout error should be defined")
	assert.Contains(t, ErrRegexTimeout.Error(), "timeout", "Error should mention timeout")
	t.Log("✓ ERROR HANDLING: Timeout error properly defined")
}

func BenchmarkEvaluateRegexWithTimeout_Normal(b *testing.B) {
	pattern := regexp.MustCompile("error")
	input := "This is an error message"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRegexWithTimeout(pattern, input, 500*time.Millisecond)
	}
}

func BenchmarkEvaluateRegexWithTimeout_Complex(b *testing.B) {
	pattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	input := "user.name+tag@example.co.uk"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRegexWithTimeout(pattern, input, 500*time.Millisecond)
	}
}
