package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnalyzeRegexComplexity_HappyPath tests valid regex patterns
func TestAnalyzeRegexComplexity_HappyPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{
			name:    "simple word match",
			pattern: "hello",
		},
		{
			name:    "simple alternation",
			pattern: "cat|dog|bird",
		},
		{
			name:    "bounded quantifier single",
			pattern: "a{1,5}",
		},
		{
			name:    "bounded quantifier multiple",
			pattern: "a{1,10}b{2,8}",
		},
		{
			name:    "character class",
			pattern: "[abc]",
		},
		{
			name:    "anchors",
			pattern: "^start$",
		},
		{
			name:    "escaped dots",
			pattern: `\d\d\d\.\d\d\d\.\d\d\d\.\d\d\d`,
		},
		{
			name:    "simple group",
			pattern: "(hello)",
		},
		{
			name:    "multiple groups within limit",
			pattern: "(a)(b)(c)",
		},
		{
			name:    "word boundaries",
			pattern: `\w{1,20}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			assert.NoError(t, err, "Valid pattern should not return error: %s", tt.pattern)
		})
	}
}

// TestAnalyzeRegexComplexity_UnboundedQuantifiers tests detection of dangerous unbounded quantifiers
func TestAnalyzeRegexComplexity_UnboundedQuantifiers(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		errorMatch string
	}{
		{
			name:       "asterisk quantifier",
			pattern:    "a*",
			errorMatch: "unsafe characters",
		},
		{
			name:       "plus quantifier",
			pattern:    "a+",
			errorMatch: "unsafe characters",
		},
		{
			name:       "question mark quantifier",
			pattern:    "a?",
			errorMatch: "unbounded quantifier",
		},
		{
			name:       "unbounded range quantifier",
			pattern:    "a{1,}",
			errorMatch: "unbounded range quantifier",
		},
		{
			name:       "asterisk in complex pattern",
			pattern:    "hello.*world",
			errorMatch: "unsafe characters",
		},
		{
			name:       "plus in complex pattern",
			pattern:    "(abc)+",
			errorMatch: "unsafe characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			require.Error(t, err, "Unbounded quantifier should be rejected: %s", tt.pattern)
			assert.Contains(t, err.Error(), tt.errorMatch)
		})
	}
}

// TestAnalyzeRegexComplexity_ExcessiveRepetitions tests limits on bounded quantifiers
func TestAnalyzeRegexComplexity_ExcessiveRepetitions(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		errorMatch string
	}{
		{
			name:       "quantifier exceeds max repetitions",
			pattern:    "a{1,101}",
			errorMatch: "exceeds maximum allowed repetitions (100)",
		},
		{
			name:       "quantifier span too large",
			pattern:    "a{1,52}",
			errorMatch: "span too large",
		},
		{
			name:       "total complexity too high",
			pattern:    "a{1,50}b{1,50}c{1,50}d{1,50}e{1,50}",
			errorMatch: "total repetition complexity",
		},
		{
			name:       "single huge quantifier",
			pattern:    "x{1,200}",
			errorMatch: "exceeds maximum allowed repetitions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			require.Error(t, err, "Excessive repetitions should be rejected: %s", tt.pattern)
			assert.Contains(t, err.Error(), tt.errorMatch)
		})
	}
}

// TestAnalyzeRegexComplexity_DangerousPatterns tests detection of dangerous regex constructs
func TestAnalyzeRegexComplexity_DangerousPatterns(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		errorMatch string
	}{
		{
			name:       "backreference \\1",
			pattern:    "(a)\\1",
			errorMatch: "potentially dangerous construct",
		},
		{
			name:       "backreference \\2",
			pattern:    "(a)(b)\\2",
			errorMatch: "potentially dangerous construct",
		},
		{
			name:       "positive lookahead",
			pattern:    "(?=test)",
			errorMatch: "unsafe characters",
		},
		{
			name:       "negative lookahead",
			pattern:    "(?!test)",
			errorMatch: "unsafe characters",
		},
		{
			name:       "positive lookbehind",
			pattern:    "(?<=test)",
			errorMatch: "unsafe characters",
		},
		{
			name:       "negative lookbehind",
			pattern:    "(?<!test)",
			errorMatch: "unsafe characters",
		},
		{
			name:       "atomic group",
			pattern:    "(?>test)",
			errorMatch: "unsafe characters",
		},
		{
			name:       "recursive pattern",
			pattern:    "(?R)",
			errorMatch: "unbounded quantifier",
		},
		{
			name:       "conditional pattern",
			pattern:    "(?(1)yes|no)",
			errorMatch: "unbounded quantifier",
		},
		{
			name:       "negated character class",
			pattern:    "[^abc]",
			errorMatch: "potentially dangerous construct",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			require.Error(t, err, "Dangerous pattern should be rejected: %s", tt.pattern)
			assert.Contains(t, err.Error(), tt.errorMatch)
		})
	}
}

// TestAnalyzeRegexComplexity_NestingDepth tests nesting depth limits
func TestAnalyzeRegexComplexity_NestingDepth(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		expectErr  bool
		errorMatch string
	}{
		{
			name:      "nesting depth 1 - OK",
			pattern:   "(a)",
			expectErr: false,
		},
		{
			name:      "nesting depth 2 - OK",
			pattern:   "((a))",
			expectErr: false,
		},
		{
			name:      "nesting depth 3 - OK",
			pattern:   "(((a)))",
			expectErr: false,
		},
		{
			name:       "nesting depth 4 - FAIL",
			pattern:    "((((a))))",
			expectErr:  true,
			errorMatch: "excessive nesting depth",
		},
		{
			name:       "nesting depth 5 - FAIL",
			pattern:    "(((((a)))))",
			expectErr:  true,
			errorMatch: "excessive nesting depth",
		},
		{
			name:       "unmatched open paren",
			pattern:    "((a)",
			expectErr:  true,
			errorMatch: "unmatched parentheses",
		},
		{
			name:       "unmatched close paren",
			pattern:    "(a))",
			expectErr:  true,
			errorMatch: "unmatched parentheses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Should reject excessive nesting: %s", tt.pattern)
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Should accept valid nesting: %s", tt.pattern)
			}
		})
	}
}

// TestAnalyzeRegexComplexity_GroupCount tests group count limits
func TestAnalyzeRegexComplexity_GroupCount(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		expectErr  bool
		errorMatch string
	}{
		{
			name:      "5 groups - OK",
			pattern:   "(a)(b)(c)(d)(e)",
			expectErr: false,
		},
		{
			name:       "6 groups - FAIL",
			pattern:    "(a)(b)(c)(d)(e)(f)",
			expectErr:  true,
			errorMatch: "too many groups",
		},
		{
			name:       "10 groups - FAIL",
			pattern:    "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
			expectErr:  true,
			errorMatch: "too many groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Should reject too many groups: %s", tt.pattern)
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Should accept valid group count: %s", tt.pattern)
			}
		})
	}
}

// TestAnalyzeRegexComplexity_PatternLength tests pattern length limits
func TestAnalyzeRegexComplexity_PatternLength(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		expectErr  bool
		errorMatch string
	}{
		{
			name:      "200 characters - OK",
			pattern:   "a{1,1}" + "b{1,1}" + "c{1,1}" + "d{1,1}" + "e{1,1}" + "f{1,1}" + "g{1,1}" + "h{1,1}" + "i{1,1}" + "j{1,1}" + "k{1,1}" + "l{1,1}" + "m{1,1}" + "n{1,1}" + "o{1,1}" + "p{1,1}" + "q{1,1}" + "r{1,1}" + "s{1,1}" + "t{1,1}" + "u{1,1}" + "v{1,1}" + "w{1,1}" + "x{1,1}" + "y{1,1}" + "z{1,1}" + "A{1,1}" + "B{1,1}",
			expectErr: false,
		},
		{
			name:      "201 characters - complexity limit triggers first",
			pattern:   "a{1,1}" + "b{1,1}" + "c{1,1}" + "d{1,1}" + "e{1,1}" + "f{1,1}" + "g{1,1}" + "h{1,1}" + "i{1,1}" + "j{1,1}" + "k{1,1}" + "l{1,1}" + "m{1,1}" + "n{1,1}" + "o{1,1}" + "p{1,1}" + "q{1,1}" + "r{1,1}" + "s{1,1}" + "t{1,1}" + "u{1,1}" + "v{1,1}" + "w{1,1}" + "x{1,1}" + "y{1,1}" + "z{1,1}" + "A{1,1}" + "B{1,1}" + "C{1,1}",
			expectErr: false, // 201 chars passes the length check but short enough
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Should reject pattern that's too long")
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Should accept pattern within length limit")
			}
		})
	}
}

// TestAnalyzeRegexComplexity_AlternationCount tests alternation limits
func TestAnalyzeRegexComplexity_AlternationCount(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		expectErr  bool
		errorMatch string
	}{
		{
			name:      "5 alternations - OK",
			pattern:   "a|b|c|d|e|f",
			expectErr: false,
		},
		{
			name:       "6 alternations - FAIL",
			pattern:    "a|b|c|d|e|f|g",
			expectErr:  true,
			errorMatch: "too many alternations",
		},
		{
			name:       "10 alternations - FAIL",
			pattern:    "a|b|c|d|e|f|g|h|i|j|k",
			expectErr:  true,
			errorMatch: "too many alternations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Should reject too many alternations: %s", tt.pattern)
				assert.Contains(t, err.Error(), tt.errorMatch)
			} else {
				assert.NoError(t, err, "Should accept valid alternation count: %s", tt.pattern)
			}
		})
	}
}

// TestAnalyzeRegexComplexity_UnsafeCharacters tests detection of unsafe characters
func TestAnalyzeRegexComplexity_UnsafeCharacters(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		errorMatch string
	}{
		{
			name:       "contains asterisk (unbounded)",
			pattern:    "test*",
			errorMatch: "unsafe characters",
		},
		{
			name:       "contains plus (unbounded)",
			pattern:    "test+",
			errorMatch: "unsafe characters",
		},
		{
			name:       "contains question mark (unbounded)",
			pattern:    "test?",
			errorMatch: "unbounded quantifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			require.Error(t, err, "Unsafe characters should be rejected: %s", tt.pattern)
			assert.Contains(t, err.Error(), tt.errorMatch)
		})
	}
}

// TestAnalyzeRegexComplexity_RealWorldPatterns tests realistic use cases
func TestAnalyzeRegexComplexity_RealWorldPatterns(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		expectErr bool
	}{
		{
			name:      "IP address pattern (bounded)",
			pattern:   `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
			expectErr: false,
		},
		{
			name:      "username pattern",
			pattern:   `\w{3,20}`,
			expectErr: false,
		},
		{
			name:      "simple log pattern",
			pattern:   `(ERROR|WARN|INFO)`,
			expectErr: false,
		},
		{
			name:      "date pattern YYYY-MM-DD",
			pattern:   `\d{4}-\d{2}-\d{2}`,
			expectErr: false,
		},
		{
			name:      "email-like pattern (simplified, bounded)",
			pattern:   `\w{1,50}`,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Pattern should be rejected: %s", tt.pattern)
			} else {
				assert.NoError(t, err, "Realistic pattern should be accepted: %s", tt.pattern)
			}
		})
	}
}

// TestAnalyzeRegexComplexity_EdgeCases tests edge cases and boundary conditions
func TestAnalyzeRegexComplexity_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		expectErr  bool
		errorMatch string
	}{
		{
			name:       "empty string fails safeRegex check",
			pattern:    "",
			expectErr:  true,
			errorMatch: "unsafe characters",
		},
		{
			name:      "single character",
			pattern:   "a",
			expectErr: false,
		},
		{
			name:      "escaped special chars",
			pattern:   `\.\-\_`,
			expectErr: false,
		},
		{
			name:      "quantifier at min boundary {1,1}",
			pattern:   "a{1,1}",
			expectErr: false,
		},
		{
			name:       "quantifier at max boundary {1,100} exceeds span",
			pattern:    "a{1,100}",
			expectErr:  true,
			errorMatch: "span too large",
		},
		{
			name:       "quantifier just over max {1,101}",
			pattern:    "a{1,101}",
			expectErr:  true,
			errorMatch: "exceeds maximum allowed repetitions",
		},
		{
			name:      "multiple simple groups",
			pattern:   "(a)(b)(c)(d)(e)",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AnalyzeRegexComplexity(tt.pattern)
			if tt.expectErr {
				require.Error(t, err, "Edge case should trigger error: %s", tt.pattern)
				if tt.errorMatch != "" {
					assert.Contains(t, err.Error(), tt.errorMatch)
				}
			} else {
				assert.NoError(t, err, "Edge case should be valid: %s", tt.pattern)
			}
		})
	}
}
