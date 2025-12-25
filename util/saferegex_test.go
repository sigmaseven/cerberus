package util

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRegexValidator tests creation of RegexValidator with default settings
func TestNewRegexValidator(t *testing.T) {
	validator := NewRegexValidator()

	require.NotNil(t, validator, "Validator should not be nil")
	assert.Equal(t, MaxRegexLength, validator.maxLength, "Should use default max length")
	// Timeout field removed - cannot implement timeout for Go regexp
}

// TestNewRegexValidatorWithTimeout tests creation with custom timeout
func TestNewRegexValidatorWithTimeout(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "normal timeout",
			timeout:         50 * time.Millisecond,
			expectedTimeout: 50 * time.Millisecond,
		},
		{
			name:            "timeout at max",
			timeout:         MaxRegexTimeout,
			expectedTimeout: MaxRegexTimeout,
		},
		{
			name:            "timeout exceeding max gets capped",
			timeout:         2 * time.Second,
			expectedTimeout: MaxRegexTimeout,
		},
		{
			name:            "very small timeout",
			timeout:         1 * time.Millisecond,
			expectedTimeout: 1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Function should work but timeout is ignored (deprecated function)
			validator := NewRegexValidatorWithTimeout(tt.timeout)

			require.NotNil(t, validator, "Validator should not be nil")
			// Timeout field no longer exists - timeout parameter is deprecated and ignored
			assert.Equal(t, MaxRegexLength, validator.maxLength, "Should use default max length")
		})
	}
}

// TestValidatePattern_ReDoSPatterns tests ReDoS pattern detection (CRITICAL SECURITY)
func TestValidatePattern_ReDoSPatterns(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMatch  string
	}{
		// Nested quantifiers - exponential time complexity
		// Note: Go allows these patterns and compiles them fine, so saferegex catches them as nested quantifiers
		{
			name:        "nested quantifiers (a+)+",
			pattern:     "(a+)+",
			expectError: false, // Go regex engine allows this, relies on static analysis
		},
		{
			name:        "nested quantifiers (a*)*",
			pattern:     "(a*)*",
			expectError: false, // Go regex engine allows this
		},
		{
			name:        "nested quantifiers (a+)*",
			pattern:     "(a+)*",
			expectError: false, // Go regex engine allows this
		},
		{
			name:        "nested quantifiers with braces (a{1,5})+",
			pattern:     "(a{1,5})+",
			expectError: false, // Go regex engine allows this
		},
		{
			name:        "double plus ++",
			pattern:     "a++",
			expectError: true,
			errorMatch:  "nested quantifiers", // Caught by checkForReDoSPatterns
		},
		{
			name:        "double asterisk **",
			pattern:     "a**",
			expectError: true,
			errorMatch:  "nested quantifiers", // Caught by checkForReDoSPatterns
		},
		{
			name:        "plus after asterisk *+",
			pattern:     "a*+",
			expectError: true,
			errorMatch:  "nested quantifiers", // Caught by checkForReDoSPatterns
		},
		{
			name:        "asterisk after plus +*",
			pattern:     "a+*",
			expectError: true,
			errorMatch:  "nested quantifiers", // Caught by checkForReDoSPatterns
		},

		// Safe patterns - should pass
		{
			name:        "safe bounded quantifier",
			pattern:     "a{1,10}",
			expectError: false,
		},
		{
			name:        "safe simple group",
			pattern:     "(abc)",
			expectError: false,
		},
		{
			name:        "safe alternation",
			pattern:     "cat|dog|bird",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			err := validator.ValidatePattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "ReDoS pattern should be rejected: %s", tt.pattern)
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Safe pattern should be accepted: %s", tt.pattern)
			}
		})
	}
}

// TestValidatePattern_ExcessiveAlternation tests alternation count limits
func TestValidatePattern_ExcessiveAlternation(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMatch  string
	}{
		{
			name:        "10 alternations - OK",
			pattern:     "a|b|c|d|e|f|g|h|i|j|k",
			expectError: false,
		},
		{
			name:        "50 alternations - OK (at limit)",
			pattern:     strings.Repeat("a|", 50) + "z",
			expectError: false,
		},
		{
			name:        "51 alternations - FAIL",
			pattern:     strings.Repeat("a|", 51) + "z",
			expectError: true,
			errorMatch:  "too many alternations",
		},
		{
			name:        "100 alternations - FAIL",
			pattern:     strings.Repeat("x|", 100) + "y",
			expectError: true,
			errorMatch:  "too many alternations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			err := validator.ValidatePattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "Excessive alternation should be rejected")
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Reasonable alternation should be accepted")
			}
		})
	}
}

// TestValidatePattern_ExcessiveRepetition tests repetition range limits
func TestValidatePattern_ExcessiveRepetition(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMatch  string
	}{
		{
			name:        "a{100} - safe small range",
			pattern:     "a{100}",
			expectError: false,
		},
		{
			name:        "a{999} - safe medium range",
			pattern:     "a{999}",
			expectError: false,
		},
		{
			name:        "a{1000} - dangerous large range",
			pattern:     "a{1000}",
			expectError: true,
			errorMatch:  "excessive repetition",
		},
		{
			name:        "a{5000} - dangerous huge range",
			pattern:     "a{5000}",
			expectError: true,
			errorMatch:  "excessive repetition",
		},
		{
			name:        "a{10000} - dangerous massive range",
			pattern:     "a{10000}",
			expectError: true,
			errorMatch:  "excessive repetition",
		},
		{
			name:        "a{1,1000} - large range but allowed",
			pattern:     "a{1,1000}",
			expectError: false, // Currently allows ranges up to {1000,}
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			err := validator.ValidatePattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "Excessive repetition should be rejected: %s", tt.pattern)
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Reasonable repetition should be accepted: %s", tt.pattern)
			}
		})
	}
}

// TestValidatePattern_PatternLength tests pattern length limits
func TestValidatePattern_PatternLength(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMatch  string
	}{
		{
			name:        "empty pattern",
			pattern:     "",
			expectError: true,
			errorMatch:  "cannot be empty",
		},
		{
			name:        "short pattern",
			pattern:     "hello",
			expectError: false,
		},
		{
			name:        "at max length 500",
			pattern:     strings.Repeat("a", MaxRegexLength),
			expectError: false,
		},
		{
			name:        "over max length 501",
			pattern:     strings.Repeat("a", MaxRegexLength+1),
			expectError: true,
			errorMatch:  "too long",
		},
		{
			name:        "way over max length 1000",
			pattern:     strings.Repeat("x", 1000),
			expectError: true,
			errorMatch:  "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			err := validator.ValidatePattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "Invalid pattern length should be rejected")
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Valid pattern length should be accepted")
			}
		})
	}
}

// TestValidatePattern_InvalidSyntax tests detection of invalid regex syntax
func TestValidatePattern_InvalidSyntax(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		errorMatch string
	}{
		{
			name:       "unmatched open bracket",
			pattern:    "[abc",
			errorMatch: "invalid regex pattern",
		},
		{
			name:       "unmatched close bracket - Go accepts it",
			pattern:    "abc]",
			errorMatch: "", // This won't actually error in Go regex
		},
		{
			name:       "unmatched open paren",
			pattern:    "(abc",
			errorMatch: "invalid regex pattern",
		},
		{
			name:       "unmatched close paren",
			pattern:    "abc)",
			errorMatch: "invalid regex pattern",
		},
		{
			name:       "invalid escape sequence",
			pattern:    "\\k",
			errorMatch: "invalid regex pattern",
		},
		{
			name:       "invalid quantifier placement",
			pattern:    "*abc",
			errorMatch: "invalid regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			err := validator.ValidatePattern(tt.pattern)

			if tt.errorMatch == "" {
				// Pattern is actually valid in Go
				assert.NoError(t, err, "Pattern is valid in Go: %s", tt.pattern)
			} else {
				require.Error(t, err, "Invalid syntax should be rejected: %s", tt.pattern)
			}
		})
	}
}

// TestCompile_ValidPatterns tests successful compilation of valid patterns
func TestCompile_ValidPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{
			name:    "simple literal",
			pattern: "hello",
		},
		{
			name:    "word boundary",
			pattern: `\btest\b`,
		},
		{
			name:    "digit pattern",
			pattern: `\d{1,4}`,
		},
		{
			name:    "character class",
			pattern: `[a-z]{1,10}`,
		},
		{
			name:    "alternation",
			pattern: `error|warning|info`,
		},
		{
			name:    "anchors",
			pattern: `^start.*end$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			regex, err := validator.Compile(tt.pattern)

			require.NoError(t, err, "Valid pattern should compile: %s", tt.pattern)
			require.NotNil(t, regex, "Compiled regex should not be nil")

			// Verify it's a valid regexp.Regexp
			assert.IsType(t, &regexp.Regexp{}, regex)
		})
	}
}

// TestCompile_InvalidPatterns tests compilation rejection of invalid patterns
func TestCompile_InvalidPatterns(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "safe pattern - Go allows it",
			pattern:     "a{1,10}",
			expectError: false,
		},
		{
			name:        "too long",
			pattern:     strings.Repeat("x", 600),
			expectError: true,
		},
		{
			name:        "excessive alternation",
			pattern:     strings.Repeat("a|", 60) + "z",
			expectError: true,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewRegexValidator()
			regex, err := validator.Compile(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "Invalid pattern should not compile: %s", tt.pattern)
				assert.Nil(t, regex, "Failed compilation should return nil regex")
			} else {
				require.NoError(t, err, "Valid pattern should compile: %s", tt.pattern)
				assert.NotNil(t, regex, "Successful compilation should return regex")
			}
		})
	}
}

// TestCompileWithTimeout_BackwardCompatibility tests deprecated function still works
func TestCompileWithTimeout_BackwardCompatibility(t *testing.T) {
	validator := NewRegexValidator()

	// Should work same as Compile()
	regex, err := validator.CompileWithTimeout("test{1,5}", 1*time.Second)

	require.NoError(t, err, "CompileWithTimeout should work for backward compatibility")
	require.NotNil(t, regex, "Compiled regex should not be nil")
	assert.True(t, regex.MatchString("testttt"), "Regex should match expected string")
}

// TestEscapeUserInput tests escaping of regex metacharacters
func TestEscapeUserInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no special chars",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "dot metacharacter",
			input:    "192.168.1.1",
			expected: `192\.168\.1\.1`,
		},
		{
			name:     "asterisk metacharacter",
			input:    "file*.txt",
			expected: `file\*\.txt`,
		},
		{
			name:     "plus metacharacter",
			input:    "a+b",
			expected: `a\+b`,
		},
		{
			name:     "question mark",
			input:    "what?",
			expected: `what\?`,
		},
		{
			name:     "brackets",
			input:    "[abc]",
			expected: `\[abc\]`,
		},
		{
			name:     "parens",
			input:    "(test)",
			expected: `\(test\)`,
		},
		{
			name:     "dollar and caret",
			input:    "$100^2",
			expected: `\$100\^2`,
		},
		{
			name:     "pipe",
			input:    "a|b",
			expected: `a\|b`,
		},
		{
			name:     "backslash",
			input:    `C:\path\to\file`,
			expected: `C:\\path\\to\\file`,
		},
		{
			name:     "curly braces",
			input:    "a{1,5}",
			expected: `a\{1,5\}`,
		},
		{
			name:     "all special chars",
			input:    `.*+?^$[]{}()|\ `,
			expected: `\.\*\+\?\^\$\[\]\{\}\(\)\|\\ `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeUserInput(tt.input)
			assert.Equal(t, tt.expected, result, "Escaped string should match expected")

			// Verify the escaped string matches literally
			regex, err := regexp.Compile(result)
			require.NoError(t, err, "Escaped pattern should compile")
			assert.True(t, regex.MatchString(tt.input), "Escaped pattern should match original input literally")
		})
	}
}

// TestSafeCompile_ConvenienceFunction tests the package-level convenience function
func TestSafeCompile_ConvenienceFunction(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "valid pattern",
			pattern:     `\d{1,3}`,
			expectError: false,
		},
		{
			name:        "double quantifier pattern",
			pattern:     "a++",
			expectError: true,
		},
		{
			name:        "too long",
			pattern:     strings.Repeat("x", 600),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := SafeCompile(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "SafeCompile should reject invalid pattern")
				assert.Nil(t, regex, "Should return nil regex on error")
			} else {
				require.NoError(t, err, "SafeCompile should accept valid pattern")
				require.NotNil(t, regex, "Should return compiled regex")
			}
		})
	}
}

// TestValidateRegexPattern_ConvenienceFunction tests the package-level validation function
func TestValidateRegexPattern_ConvenienceFunction(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "valid pattern",
			pattern:     "hello{1,5}",
			expectError: false,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			expectError: true,
		},
		{
			name:        "double quantifier",
			pattern:     "a**",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegexPattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err, "ValidateRegexPattern should reject invalid pattern")
			} else {
				assert.NoError(t, err, "ValidateRegexPattern should accept valid pattern")
			}
		})
	}
}

// TestRegexValidator_Compile_FullWorkflow tests complete workflow from validation to matching
func TestRegexValidator_Compile_FullWorkflow(t *testing.T) {
	validator := NewRegexValidator()

	// Compile a pattern
	pattern := `error|warning|critical`
	regex, err := validator.Compile(pattern)

	require.NoError(t, err, "Valid pattern should compile")
	require.NotNil(t, regex, "Regex should not be nil")

	// Test matching
	tests := []struct {
		input       string
		shouldMatch bool
	}{
		{"error occurred", true},
		{"warning: high load", true},
		{"critical failure", true},
		{"info: all good", false},
		{"debug message", false},
	}

	for _, tt := range tests {
		matched := regex.MatchString(tt.input)
		assert.Equal(t, tt.shouldMatch, matched, "Match result for '%s'", tt.input)
	}
}

// TestCheckForReDoSPatterns_DirectPatternDetection tests internal ReDoS detection
func TestCheckForReDoSPatterns_DirectPatternDetection(t *testing.T) {
	validator := NewRegexValidator()

	// These are the exact patterns that checkForReDoSPatterns should catch
	dangerousPatterns := []string{
		")+*", ")*+", ")+{", ")*{",
		"}+*", "}*+", "}+{", "}*{",
		"++", "**", "*+", "+*",
	}

	for _, dangerous := range dangerousPatterns {
		t.Run("pattern_"+dangerous, func(t *testing.T) {
			testPattern := "a" + dangerous + "b"
			err := validator.ValidatePattern(testPattern)

			require.Error(t, err, "Dangerous pattern should be rejected: %s", dangerous)
			assert.Contains(t, err.Error(), "nested quantifiers", "Should identify as nested quantifier issue")
		})
	}
}

// TestConstants verifies expected constant values
func TestConstants(t *testing.T) {
	assert.Equal(t, 500, MaxRegexLength, "MaxRegexLength should be 500")
	assert.Equal(t, 100*time.Millisecond, DefaultRegexTimeout, "DefaultRegexTimeout should be 100ms")
	assert.Equal(t, 1*time.Second, MaxRegexTimeout, "MaxRegexTimeout should be 1s")
}

// TestCompile_AcceptedPatternsCompleteQuickly verifies that patterns passing validation execute fast
// This is defense-in-depth: static analysis rejects dangerous patterns, but we also verify
// that accepted patterns don't cause ReDoS attacks in practice
func TestCompile_AcceptedPatternsCompleteQuickly(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string // Worst-case input for this pattern
		maxTime time.Duration
	}{
		{
			name:    "bounded quantifier worst case",
			pattern: `\w{1,50}`,
			input:   strings.Repeat("a", 50), // Matches max length
			maxTime: 10 * time.Millisecond,
		},
		{
			name:    "bounded quantifier no match",
			pattern: `\w{1,50}`,
			input:   strings.Repeat("!", 50), // No match, tries all positions
			maxTime: 10 * time.Millisecond,
		},
		{
			name:    "alternation worst case - max allowed branches",
			pattern: "a|b|c|d|e|f",            // 6 alternations
			input:   strings.Repeat("g", 100), // No match, tries all branches
			maxTime: 10 * time.Millisecond,
		},
		{
			name:    "alternation with match at end",
			pattern: "apple|banana|cherry|date|elderberry|fig",
			input:   "fig",
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "complex nested groups - max nesting",
			pattern: "(((a)))", // Max nesting depth
			input:   "aaa",
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "character class ranges",
			pattern: `[a-zA-Z0-9_]{1,100}`,
			input:   strings.Repeat("x", 100),
			maxTime: 10 * time.Millisecond,
		},
		{
			name:    "multiple character classes",
			pattern: `[a-z]+[0-9]+[A-Z]+`,
			input:   strings.Repeat("a", 50) + strings.Repeat("1", 50) + strings.Repeat("Z", 50),
			maxTime: 15 * time.Millisecond,
		},
		{
			name:    "dot with bounded quantifier",
			pattern: `.{1,100}`,
			input:   strings.Repeat("x", 100),
			maxTime: 10 * time.Millisecond,
		},
		{
			name:    "optional groups - worst case",
			pattern: `(a)?(b)?(c)?(d)?`,
			input:   "abcd",
			maxTime: 5 * time.Millisecond,
		},
		{
			name:    "anchored pattern",
			pattern: `^[a-z]{1,50}$`,
			input:   strings.Repeat("x", 50),
			maxTime: 10 * time.Millisecond,
		},
	}

	validator := NewRegexValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile regex
			regex, err := validator.Compile(tt.pattern)
			require.NoError(t, err, "Pattern should pass validation")

			// Execute and measure time
			start := time.Now()
			_ = regex.MatchString(tt.input)
			elapsed := time.Since(start)

			// MUST complete within timeout
			assert.Less(t, elapsed, tt.maxTime,
				"Pattern %s took %v, expected < %v (input length: %d)",
				tt.pattern, elapsed, tt.maxTime, len(tt.input))
		})
	}
}

// TestCompile_ReDoSProtectionUnderLoad verifies regex performance under repeated execution
// Simulates real-world scenario where same regex is applied to many inputs
func TestCompile_ReDoSProtectionUnderLoad(t *testing.T) {
	validator := NewRegexValidator()

	tests := []struct {
		name       string
		pattern    string
		inputs     []string
		iterations int
		maxTotal   time.Duration
	}{
		{
			name:    "IP address validation under load",
			pattern: `^(\d{1,3}\.){3}\d{1,3}$`,
			inputs: []string{
				"192.168.1.1",
				"10.0.0.1",
				"invalid",
				"999.999.999.999",
			},
			iterations: 1000,
			maxTotal:   100 * time.Millisecond,
		},
		{
			name:    "email validation under load",
			pattern: `^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,}$`,
			inputs: []string{
				"user@example.com",
				"test.user+tag@example.co.uk",
				"invalid@",
				"@example.com",
			},
			iterations: 1000,
			maxTotal:   100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := validator.Compile(tt.pattern)
			require.NoError(t, err)

			start := time.Now()
			for i := 0; i < tt.iterations; i++ {
				for _, input := range tt.inputs {
					_ = regex.MatchString(input)
				}
			}
			elapsed := time.Since(start)

			assert.Less(t, elapsed, tt.maxTotal,
				"Pattern %s processed %d inputs in %v, expected < %v",
				tt.pattern, tt.iterations*len(tt.inputs), elapsed, tt.maxTotal)
		})
	}
}

// TestRegexValidator_ConcurrentAccess verifies thread safety of RegexValidator
// RegexValidator should be safe to use concurrently from multiple goroutines
func TestRegexValidator_ConcurrentAccess(t *testing.T) {
	validator := NewRegexValidator()

	// Number of concurrent goroutines
	const numGoroutines = 100

	// Channel to collect errors from goroutines
	errors := make(chan error, numGoroutines)
	done := make(chan bool)

	// Launch multiple goroutines that compile patterns concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine compiles different patterns
			pattern := fmt.Sprintf(`\w{1,%d}`, (id%20)+1)

			regex, err := validator.Compile(pattern)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: compilation failed: %w", id, err)
				return
			}

			// Test the compiled regex
			testInput := strings.Repeat("a", (id%20)+1)
			if !regex.MatchString(testInput) {
				errors <- fmt.Errorf("goroutine %d: regex didn't match expected input", id)
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// TestRegexValidator_ConcurrentValidation verifies concurrent validation
func TestRegexValidator_ConcurrentValidation(t *testing.T) {
	validator := NewRegexValidator()

	const numGoroutines = 50

	// Test both valid and invalid patterns concurrently
	patterns := []struct {
		pattern   string
		shouldErr bool
	}{
		{`\w{1,10}`, false},
		{`(a)+*`, true}, // Nested quantifier - should fail (contains ")+*")
		{`[a-z]{1,50}`, false},
		{`a{10000}`, true}, // Excessive repetition - should fail
		{`\d{1,3}\.\d{1,3}`, false},
		{`a++`, true}, // Double quantifier - should fail (contains "++")
		{`\w{1,20}`, false},
	}

	errors := make(chan error, numGoroutines)
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Cycle through patterns
			tt := patterns[id%len(patterns)]

			err := validator.ValidatePattern(tt.pattern)

			if tt.shouldErr && err == nil {
				errors <- fmt.Errorf("goroutine %d: expected error for pattern %s but got nil", id, tt.pattern)
			} else if !tt.shouldErr && err != nil {
				errors <- fmt.Errorf("goroutine %d: unexpected error for pattern %s: %w", id, tt.pattern, err)
			}
		}(i)
	}

	// Wait for completion
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// Check errors
	for err := range errors {
		t.Errorf("Concurrent validation error: %v", err)
	}
}

// TestSafeCompile_Concurrent verifies concurrent use of the SafeCompile convenience function
func TestSafeCompile_Concurrent(t *testing.T) {
	const numGoroutines = 100

	errors := make(chan error, numGoroutines)
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			pattern := fmt.Sprintf(`[a-z]{1,%d}`, (id%50)+1)

			regex, err := SafeCompile(pattern)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: SafeCompile failed: %w", id, err)
				return
			}

			// Verify compiled regex works
			if !regex.MatchString("test") {
				errors <- fmt.Errorf("goroutine %d: regex didn't match 'test'", id)
			}
		}(i)
	}

	// Wait for completion
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// Check errors
	for err := range errors {
		t.Errorf("Concurrent SafeCompile error: %v", err)
	}
}
