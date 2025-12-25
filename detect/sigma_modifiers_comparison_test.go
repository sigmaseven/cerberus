package detect

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCompareValues_Equals tests the default "equals" operator for exact matching.
func TestCompareValues_Equals(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "exact string match",
			actual:   "test",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "string mismatch",
			actual:   "test",
			pattern:  "testing",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "empty strings match",
			actual:   "",
			pattern:  "",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "case sensitive - different case",
			actual:   "Test",
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "int to string conversion - match",
			actual:   42,
			pattern:  "42",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "int to string conversion - mismatch",
			actual:   42,
			pattern:  "43",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "float to string conversion",
			actual:   3.14,
			pattern:  "3.14",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "bool to string conversion - true",
			actual:   true,
			pattern:  "true",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "bool to string conversion - false",
			actual:   false,
			pattern:  "false",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "both nil",
			actual:   nil,
			pattern:  nil,
			expected: true,
			wantErr:  false,
		},
		{
			name:     "actual nil",
			actual:   nil,
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "pattern nil",
			actual:   "test",
			pattern:  nil,
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, DefaultOperator, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_Contains tests the "contains" operator for substring matching.
func TestCompareValues_Contains(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "substring present in middle",
			actual:   "testing",
			pattern:  "esti",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "substring present at start",
			actual:   "testing",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "substring present at end",
			actual:   "testing",
			pattern:  "ing",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "substring not present",
			actual:   "testing",
			pattern:  "xyz",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "empty pattern matches all",
			actual:   "testing",
			pattern:  "",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "empty actual with non-empty pattern",
			actual:   "",
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "exact match",
			actual:   "test",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "case sensitive - different case",
			actual:   "Testing",
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "contains with numbers",
			actual:   "test123",
			pattern:  "123",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "contains with type conversion",
			actual:   12345,
			pattern:  "234",
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, ModifierContains, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_StartsWith tests the "startswith" operator for prefix matching.
func TestCompareValues_StartsWith(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "prefix match",
			actual:   "testing",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "no prefix match",
			actual:   "testing",
			pattern:  "ing",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "full string match",
			actual:   "test",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "empty pattern matches all",
			actual:   "testing",
			pattern:  "",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "pattern longer than actual",
			actual:   "test",
			pattern:  "testing",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "case sensitive",
			actual:   "Testing",
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "single character prefix",
			actual:   "testing",
			pattern:  "t",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "startswith with numbers",
			actual:   "123test",
			pattern:  "123",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "startswith with type conversion",
			actual:   12345,
			pattern:  "123",
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, ModifierStartsWith, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_EndsWith tests the "endswith" operator for suffix matching.
func TestCompareValues_EndsWith(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		expected bool
		wantErr  bool
	}{
		{
			name:     "suffix match",
			actual:   "testing",
			pattern:  "ing",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "no suffix match",
			actual:   "testing",
			pattern:  "test",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "full string match",
			actual:   "test",
			pattern:  "test",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "empty pattern matches all",
			actual:   "testing",
			pattern:  "",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "pattern longer than actual",
			actual:   "test",
			pattern:  "testing",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "case sensitive",
			actual:   "testiNG",
			pattern:  "ing",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "single character suffix",
			actual:   "testing",
			pattern:  "g",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "endswith with numbers",
			actual:   "test123",
			pattern:  "123",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "endswith with type conversion",
			actual:   12345,
			pattern:  "45",
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, ModifierEndsWith, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_Regex tests the "re" operator for regex matching with ReDoS protection.
func TestCompareValues_Regex(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		expected bool
		wantErr  bool
		errCheck func(error) bool // Optional: check error message content
	}{
		{
			name:     "simple regex match",
			actual:   "test123",
			pattern:  "test\\d+",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "simple regex no match",
			actual:   "testing",
			pattern:  "\\d+",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "regex with anchors - match",
			actual:   "test",
			pattern:  "^test$",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "regex with anchors - no match",
			actual:   "testing",
			pattern:  "^test$",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "regex character class",
			actual:   "hello",
			pattern:  "[a-z]+",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "regex alternation",
			actual:   "cat",
			pattern:  "(cat|dog)",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "invalid regex pattern - unclosed bracket",
			actual:   "test",
			pattern:  "[invalid",
			expected: false,
			wantErr:  true,
			errCheck: func(err error) bool {
				return strings.Contains(err.Error(), "regex error")
			},
		},
		{
			name:     "invalid regex pattern - unclosed paren",
			actual:   "test",
			pattern:  "(unclosed",
			expected: false,
			wantErr:  true,
			errCheck: func(err error) bool {
				return strings.Contains(err.Error(), "regex error")
			},
		},
		{
			name:     "regex with escape sequences",
			actual:   "test\nline",
			pattern:  "test\\nline",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "regex with word boundary",
			actual:   "test word",
			pattern:  "\\bword\\b",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "complex regex - email-like",
			actual:   "user@example.com",
			pattern:  "[a-z]+@[a-z]+\\.[a-z]+",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "regex with type conversion",
			actual:   12345,
			pattern:  "\\d{5}",
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, ModifierRegex, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errCheck != nil {
				if !tt.errCheck(err) {
					t.Errorf("compareValues() error = %v, does not match expected error pattern", err)
				}
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_Regex_InputSizeProtection tests protection against large inputs.
// Note: Go's RE2 engine guarantees O(n) matching time, so we use input size limits
// instead of goroutine-based timeouts (which can leak) for DoS protection.
func TestCompareValues_Regex_InputSizeProtection(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	// Test input within limit (should succeed)
	t.Run("within limit", func(t *testing.T) {
		input := strings.Repeat("a", 100000) // 100KB - well under 1MB limit
		pattern := "a+"

		result, err := evaluator.compareValues(input, pattern, ModifierRegex, evaluator.regexTimeout)
		if err != nil {
			t.Errorf("Expected no error for input within limit, got: %v", err)
		}
		if !result {
			t.Error("Expected match for input within limit")
		}
	})

	// Test input exceeding limit (should fail with error)
	t.Run("exceeds limit", func(t *testing.T) {
		input := strings.Repeat("a", 2*1024*1024) // 2MB - over 1MB limit
		pattern := "a+"

		result, err := evaluator.compareValues(input, pattern, ModifierRegex, evaluator.regexTimeout)
		if err == nil {
			t.Error("Expected error for input exceeding limit, got nil")
		}
		if !strings.Contains(err.Error(), "regex input too large") {
			t.Errorf("Expected 'regex input too large' error, got: %v", err)
		}
		if result {
			t.Error("Expected false result for oversized input, got true")
		}
	})
}

// TestCompareValues_CIDR tests the "cidr" operator implementation.
func TestCompareValues_CIDR(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name      string
		ip        string
		cidr      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Valid match - IP in CIDR",
			ip:        "192.168.1.100",
			cidr:      "192.168.1.0/24",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Valid no match - IP not in CIDR",
			ip:        "192.168.2.100",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Invalid IP",
			ip:        "not-an-ip",
			cidr:      "192.168.1.0/24",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR",
			ip:        "192.168.1.1",
			cidr:      "invalid-cidr",
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:      "IPv6 match",
			ip:        "2001:db8::1",
			cidr:      "2001:db8::/32",
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.ip, tt.cidr, ModifierCIDR, evaluator.regexTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.wantMatch {
				t.Errorf("compareValues() = %v, want %v", result, tt.wantMatch)
			}
		})
	}
}

// TestCompareValues_UnknownOperator tests error handling for unknown operators.
func TestCompareValues_UnknownOperator(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	result, err := evaluator.compareValues("test", "test", "unknown_operator", evaluator.regexTimeout)

	if err == nil {
		t.Error("Expected error for unknown operator, got nil")
		return
	}

	if !strings.Contains(err.Error(), "unknown comparison operator") {
		t.Errorf("Expected 'unknown comparison operator' error, got: %v", err)
	}

	if result {
		t.Error("Expected false result for unknown operator, got true")
	}
}

// TestToString tests the type conversion helper function.
func TestToString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "string",
			input:    "test",
			expected: "test",
		},
		{
			name:     "int",
			input:    42,
			expected: "42",
		},
		{
			name:     "int64",
			input:    int64(42),
			expected: "42",
		},
		{
			name:     "int32",
			input:    int32(42),
			expected: "42",
		},
		{
			name:     "float64",
			input:    3.14,
			expected: "3.14",
		},
		{
			name:     "float32",
			input:    float32(3.14),
			expected: "3.14",
		},
		{
			name:     "bool true",
			input:    true,
			expected: "true",
		},
		{
			name:     "bool false",
			input:    false,
			expected: "false",
		},
		{
			name:     "negative int",
			input:    -42,
			expected: "-42",
		},
		{
			name:     "zero",
			input:    0,
			expected: "0",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toString(tt.input)
			if result != tt.expected {
				t.Errorf("toString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestMatchRegexWithTimeout tests the regex matching helper function directly.
func TestMatchRegexWithTimeout(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		timeout  time.Duration
		expected bool
		wantErr  bool
	}{
		{
			name:     "valid pattern match",
			pattern:  "test\\d+",
			value:    "test123",
			timeout:  100 * time.Millisecond,
			expected: true,
			wantErr:  false,
		},
		{
			name:     "valid pattern no match",
			pattern:  "\\d+",
			value:    "abc",
			timeout:  100 * time.Millisecond,
			expected: false,
			wantErr:  false,
		},
		{
			name:     "invalid pattern",
			pattern:  "[invalid",
			value:    "test",
			timeout:  100 * time.Millisecond,
			expected: false,
			wantErr:  true,
		},
		{
			name:     "empty pattern matches empty",
			pattern:  "",
			value:    "",
			timeout:  100 * time.Millisecond,
			expected: true,
			wantErr:  false,
		},
		{
			name:     "empty pattern matches all",
			pattern:  "",
			value:    "anything",
			timeout:  100 * time.Millisecond,
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := matchRegexWithTimeout(tt.pattern, tt.value, tt.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchRegexWithTimeout() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("matchRegexWithTimeout() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_TypeConversion tests type conversion across different types.
func TestCompareValues_TypeConversion(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name     string
		actual   interface{}
		pattern  interface{}
		operator string
		expected bool
	}{
		{
			name:     "int equals string",
			actual:   42,
			pattern:  "42",
			operator: DefaultOperator,
			expected: true,
		},
		{
			name:     "float equals string",
			actual:   3.14,
			pattern:  "3.14",
			operator: DefaultOperator,
			expected: true,
		},
		{
			name:     "bool equals string",
			actual:   true,
			pattern:  "true",
			operator: DefaultOperator,
			expected: true,
		},
		{
			name:     "int contains digit",
			actual:   12345,
			pattern:  "234",
			operator: ModifierContains,
			expected: true,
		},
		{
			name:     "int startswith digit",
			actual:   12345,
			pattern:  "123",
			operator: ModifierStartsWith,
			expected: true,
		},
		{
			name:     "int endswith digit",
			actual:   12345,
			pattern:  "45",
			operator: ModifierEndsWith,
			expected: true,
		},
		{
			name:     "float regex match",
			actual:   3.14159,
			pattern:  "3\\.14\\d+",
			operator: ModifierRegex,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.compareValues(tt.actual, tt.pattern, tt.operator, evaluator.regexTimeout)
			if err != nil {
				t.Errorf("compareValues() unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("compareValues() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestCompareValues_Integration tests comparison operators with the full EvaluateWithModifiers flow.
func TestCompareValues_Integration(t *testing.T) {
	evaluator := NewModifierEvaluator(100 * time.Millisecond)

	tests := []struct {
		name      string
		value     interface{}
		pattern   interface{}
		modifiers []string
		expected  bool
		wantErr   bool
	}{
		{
			name:      "contains modifier",
			value:     "testing",
			pattern:   "test",
			modifiers: []string{"contains"},
			expected:  true,
			wantErr:   false,
		},
		{
			name:      "startswith modifier",
			value:     "testing",
			pattern:   "test",
			modifiers: []string{"startswith"},
			expected:  true,
			wantErr:   false,
		},
		{
			name:      "endswith modifier",
			value:     "testing",
			pattern:   "ing",
			modifiers: []string{"endswith"},
			expected:  true,
			wantErr:   false,
		},
		{
			name:      "regex modifier",
			value:     "test123",
			pattern:   "test\\d+",
			modifiers: []string{"re"},
			expected:  true,
			wantErr:   false,
		},
		{
			name:      "base64 with contains",
			value:     "dGVzdGluZw==", // "testing" in base64
			pattern:   "test",
			modifiers: []string{"base64", "contains"},
			expected:  true,
			wantErr:   false,
		},
		{
			name:      "windash with equals",
			value:     "test\u2013value", // test with EN DASH
			pattern:   "test-value",      // test with ASCII hyphen
			modifiers: []string{"windash"},
			expected:  true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateWithModifiers(tt.value, tt.pattern, tt.modifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateWithModifiers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("EvaluateWithModifiers() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestValidateRegexPattern tests pattern validation for DoS protection.
func TestValidateRegexPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple pattern",
			pattern: "test\\d+",
			wantErr: false,
		},
		{
			name:    "valid pattern with small quantifier",
			pattern: "a{1,100}",
			wantErr: false,
		},
		{
			name:    "pattern too long",
			pattern: strings.Repeat("a", 15000), // 15KB > 10KB limit
			wantErr: true,
			errMsg:  "regex pattern too long",
		},
		{
			name:    "quantifier too large - single value",
			pattern: "a{5000}",
			wantErr: true,
			errMsg:  "regex quantifier too large",
		},
		{
			name:    "quantifier too large - range max",
			pattern: "a{1,5000}",
			wantErr: true,
			errMsg:  "regex quantifier too large",
		},
		{
			name:    "valid pattern at edge of quantifier limit",
			pattern: "a{1000}", // Exactly at limit
			wantErr: false,
		},
		{
			name:    "valid complex pattern",
			pattern: "(foo|bar|baz){1,10}[a-z]+\\d*",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegexPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRegexPattern() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateRegexPattern() error = %v, expected to contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestRegexCache_ConcurrentAccess tests thread-safety of regex cache.
func TestRegexCache_ConcurrentAccess(t *testing.T) {
	// Create patterns that will cause cache evictions
	patterns := make([]string, 200) // More than default cache size
	for i := range patterns {
		patterns[i] = "pattern_" + strings.Repeat("x", i%50) + "_\\d+"
	}

	// Run concurrent cache accesses
	const numGoroutines = 50
	const accessesPerGoroutine = 100

	errCh := make(chan error, numGoroutines)
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < accessesPerGoroutine; j++ {
				pattern := patterns[(id*accessesPerGoroutine+j)%len(patterns)]
				_, err := defaultRegexCache.get(pattern)
				if err != nil {
					errCh <- err
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent cache access error: %v", err)
	}
}

// TestMatchRegexWithTimeout_PatternValidation tests that pattern validation is enforced.
func TestMatchRegexWithTimeout_PatternValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid pattern",
			pattern: "test\\d+",
			value:   "test123",
			wantErr: false,
		},
		{
			name:    "pattern with excessive quantifier",
			pattern: "a{10000}",
			value:   "aaa",
			wantErr: true,
			errMsg:  "invalid regex pattern",
		},
		{
			name:    "pattern too long",
			pattern: strings.Repeat("a", 15000),
			value:   "test",
			wantErr: true,
			errMsg:  "invalid regex pattern",
		},
		{
			name:    "input exceeds size limit",
			pattern: "test",
			value:   strings.Repeat("a", 2*1024*1024), // 2MB
			wantErr: true,
			errMsg:  "regex input too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := matchRegexWithTimeout(tt.pattern, tt.value, 100*time.Millisecond)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchRegexWithTimeout() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("matchRegexWithTimeout() error = %v, expected to contain %q", err, tt.errMsg)
				}
			}
		})
	}
}
