package detect

import (
	"strings"
	"testing"
)

// TestTokenize_SimpleExpressions tests basic tokenization of simple SIGMA condition expressions.
func TestTokenize_SimpleExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "single identifier",
			input:    "selection1",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "simple OR",
			input:    "selection1 or selection2",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "simple AND",
			input:    "selection1 and selection2",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "simple NOT",
			input:    "not selection1",
			expected: []TokenType{TokenNOT, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "three identifiers OR",
			input:    "a or b or c",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "three identifiers AND",
			input:    "a and b and c",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed AND OR",
			input:    "a and b or c",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}
		})
	}
}

// TestTokenize_ComplexNestedExpressions tests tokenization of complex nested expressions.
func TestTokenize_ComplexNestedExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "simple parentheses",
			input:    "(selection1)",
			expected: []TokenType{TokenLPAREN, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
		{
			name:     "parentheses with OR",
			input:    "(a or b)",
			expected: []TokenType{TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
		{
			name:     "nested parentheses",
			input:    "((a))",
			expected: []TokenType{TokenLPAREN, TokenLPAREN, TokenIDENTIFIER, TokenRPAREN, TokenRPAREN, TokenEOF},
		},
		{
			name:     "complex nested expression",
			input:    "(a or b) and not (c or d)",
			expected: []TokenType{TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenRPAREN, TokenAND, TokenNOT, TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
		{
			name:     "deeply nested",
			input:    "(a and (b or (c and d)))",
			expected: []TokenType{TokenLPAREN, TokenIDENTIFIER, TokenAND, TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenLPAREN, TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenRPAREN, TokenRPAREN, TokenRPAREN, TokenEOF},
		},
		{
			name:     "multiple NOT",
			input:    "not (not a)",
			expected: []TokenType{TokenNOT, TokenLPAREN, TokenNOT, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
		{
			name:     "complex with NOT",
			input:    "not (a and b) or not (c and d)",
			expected: []TokenType{TokenNOT, TokenLPAREN, TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenRPAREN, TokenOR, TokenNOT, TokenLPAREN, TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}
		})
	}
}

// TestTokenize_WhitespaceHandling tests various whitespace scenarios.
func TestTokenize_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "no whitespace",
			input:    "a or b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "multiple spaces",
			input:    "a    or    b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "leading whitespace",
			input:    "   a or b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "trailing whitespace",
			input:    "a or b   ",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "tabs",
			input:    "a\tor\tb",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "newlines",
			input:    "a\nor\nb",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed whitespace",
			input:    "  \t\na \t\n or \t\n b  \t\n",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "whitespace only",
			input:    "   \t\n   ",
			expected: []TokenType{TokenEOF},
		},
		{
			name:     "no space around parentheses",
			input:    "(a or b)and(c or d)",
			expected: []TokenType{TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenRPAREN, TokenAND, TokenLPAREN, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenRPAREN, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}
		})
	}
}

// TestTokenize_CaseInsensitivity tests case-insensitive keyword matching.
func TestTokenize_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "lowercase and",
			input:    "a and b",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "uppercase AND",
			input:    "a AND b",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed case And",
			input:    "a And b",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "lowercase or",
			input:    "a or b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "uppercase OR",
			input:    "a OR b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed case Or",
			input:    "a Or b",
			expected: []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "lowercase not",
			input:    "not a",
			expected: []TokenType{TokenNOT, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "uppercase NOT",
			input:    "NOT a",
			expected: []TokenType{TokenNOT, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed case Not",
			input:    "Not a",
			expected: []TokenType{TokenNOT, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "all keywords mixed case",
			input:    "All Of Them",
			expected: []TokenType{TokenALL, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "any of mixed case",
			input:    "AnY oF selection*",
			expected: []TokenType{TokenANY, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "lowercase one",
			input:    "one of them",
			expected: []TokenType{TokenONE, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "uppercase ONE",
			input:    "ONE of them",
			expected: []TokenType{TokenONE, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "mixed case One",
			input:    "OnE Of Them",
			expected: []TokenType{TokenONE, TokenOF, TokenTHEM, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}
		})
	}
}

// TestTokenize_KeywordBoundaries tests that keywords are distinguished from identifiers with similar prefixes.
func TestTokenize_KeywordBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "not is keyword",
			input:    "not a",
			expected: []TokenType{TokenNOT, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "notable is identifier",
			input:    "notable",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "notation is identifier",
			input:    "notation",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "and is keyword",
			input:    "and",
			expected: []TokenType{TokenAND, TokenEOF},
		},
		{
			name:     "android is identifier",
			input:    "android",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "or is keyword",
			input:    "or",
			expected: []TokenType{TokenOR, TokenEOF},
		},
		{
			name:     "oracle is identifier",
			input:    "oracle",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "all is keyword",
			input:    "all",
			expected: []TokenType{TokenALL, TokenEOF},
		},
		{
			name:     "allow is identifier",
			input:    "allow",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "any is keyword",
			input:    "any",
			expected: []TokenType{TokenANY, TokenEOF},
		},
		{
			name:     "anyone is identifier",
			input:    "anyone",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "of is keyword",
			input:    "of",
			expected: []TokenType{TokenOF, TokenEOF},
		},
		{
			name:     "office is identifier",
			input:    "office",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "them is keyword",
			input:    "them",
			expected: []TokenType{TokenTHEM, TokenEOF},
		},
		{
			name:     "theme is identifier",
			input:    "theme",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "one is keyword",
			input:    "one",
			expected: []TokenType{TokenONE, TokenEOF},
		},
		{
			name:     "onerous is identifier",
			input:    "onerous",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "mixed keywords and identifiers",
			input:    "notable and android or oracle",
			expected: []TokenType{TokenIDENTIFIER, TokenAND, TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s (value: %q)", i, tokens[i].Type, expectedType, tokens[i].Value)
				}
			}
		})
	}
}

// TestTokenize_WildcardPatterns tests wildcard pattern tokenization.
func TestTokenize_WildcardPatterns(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      []TokenType
		expectedValue string
		valueIndex    int // which token to check for expectedValue
	}{
		{
			name:          "wildcard suffix",
			input:         "selection*",
			expected:      []TokenType{TokenIDENTIFIER, TokenEOF},
			expectedValue: "selection*",
			valueIndex:    0,
		},
		{
			name:          "wildcard in aggregation",
			input:         "all of selection*",
			expected:      []TokenType{TokenALL, TokenOF, TokenIDENTIFIER, TokenEOF},
			expectedValue: "selection*",
			valueIndex:    2, // third token is the identifier
		},
		{
			name:          "multiple wildcards",
			input:         "selection* or filter*",
			expected:      []TokenType{TokenIDENTIFIER, TokenOR, TokenIDENTIFIER, TokenEOF},
			expectedValue: "", // multiple tokens, value not checked
			valueIndex:    -1,
		},
		{
			name:          "underscore with wildcard",
			input:         "selection_windows*",
			expected:      []TokenType{TokenIDENTIFIER, TokenEOF},
			expectedValue: "selection_windows*",
			valueIndex:    0,
		},
		{
			name:          "number in identifier with wildcard",
			input:         "selection1*",
			expected:      []TokenType{TokenIDENTIFIER, TokenEOF},
			expectedValue: "selection1*",
			valueIndex:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}

			// Check specific token value if specified
			if tt.expectedValue != "" && tt.valueIndex >= 0 && tt.valueIndex < len(tokens) {
				if tokens[tt.valueIndex].Value != tt.expectedValue {
					t.Errorf("token %d value: got %q, expected %q", tt.valueIndex, tokens[tt.valueIndex].Value, tt.expectedValue)
				}
			}
		})
	}
}

// TestTokenize_AggregationExpressions tests tokenization of aggregation expressions.
func TestTokenize_AggregationExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "all of them",
			input:    "all of them",
			expected: []TokenType{TokenALL, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "any of them",
			input:    "any of them",
			expected: []TokenType{TokenANY, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "1 of them",
			input:    "1 of them",
			expected: []TokenType{TokenNUMBER, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "all of selection*",
			input:    "all of selection*",
			expected: []TokenType{TokenALL, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "any of selection*",
			input:    "any of selection*",
			expected: []TokenType{TokenANY, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "1 of selection*",
			input:    "1 of selection*",
			expected: []TokenType{TokenNUMBER, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "2 of them",
			input:    "2 of them",
			expected: []TokenType{TokenNUMBER, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "10 of selection*",
			input:    "10 of selection*",
			expected: []TokenType{TokenNUMBER, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "aggregation in complex expression",
			input:    "(all of them) and selection",
			expected: []TokenType{TokenLPAREN, TokenALL, TokenOF, TokenTHEM, TokenRPAREN, TokenAND, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "multiple aggregations",
			input:    "1 of them or all of selection*",
			expected: []TokenType{TokenNUMBER, TokenOF, TokenTHEM, TokenOR, TokenALL, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
		{
			name:     "one of them",
			input:    "one of them",
			expected: []TokenType{TokenONE, TokenOF, TokenTHEM, TokenEOF},
		},
		{
			name:     "one of selection*",
			input:    "one of selection*",
			expected: []TokenType{TokenONE, TokenOF, TokenIDENTIFIER, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
			}

			for i, expectedType := range tt.expected {
				if tokens[i].Type != expectedType {
					t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
				}
			}
		})
	}
}

// TestTokenize_InvalidCharacters tests error handling for invalid characters.
func TestTokenize_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldError bool
	}{
		{
			name:        "at sign",
			input:       "selection @",
			shouldError: true,
		},
		{
			name:        "hash",
			input:       "selection#",
			shouldError: true,
		},
		{
			name:        "dollar sign",
			input:       "selection$",
			shouldError: true,
		},
		{
			name:        "percent",
			input:       "selection%",
			shouldError: true,
		},
		{
			name:        "ampersand",
			input:       "selection & filter",
			shouldError: true,
		},
		{
			name:        "plus",
			input:       "selection + filter",
			shouldError: true,
		},
		{
			name:        "equals",
			input:       "selection = filter",
			shouldError: true,
		},
		{
			name:        "square bracket",
			input:       "selection[0]",
			shouldError: true,
		},
		{
			name:        "curly brace",
			input:       "selection{test}",
			shouldError: true,
		},
		{
			name:        "semicolon",
			input:       "selection; filter",
			shouldError: true,
		},
		{
			name:        "colon",
			input:       "selection: filter",
			shouldError: true,
		},
		{
			name:        "comma",
			input:       "selection, filter",
			shouldError: true,
		},
		{
			name:        "quote",
			input:       "selection'",
			shouldError: true,
		},
		{
			name:        "double quote",
			input:       "\"selection\"",
			shouldError: true,
		},
		{
			name:        "backslash",
			input:       "selection\\filter",
			shouldError: true,
		},
		{
			name:        "pipe",
			input:       "selection | filter",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.input)
			if tt.shouldError && err == nil {
				t.Errorf("Tokenize(%q) expected error, got nil", tt.input)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Tokenize(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

// TestTokenize_EmptyAndEdgeCases tests edge cases like empty strings and special scenarios.
func TestTokenize_EmptyAndEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []TokenType{TokenEOF},
			wantErr:  false,
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: []TokenType{TokenEOF},
			wantErr:  false,
		},
		{
			name:     "only tabs",
			input:    "\t\t\t",
			expected: []TokenType{TokenEOF},
			wantErr:  false,
		},
		{
			name:     "only newlines",
			input:    "\n\n\n",
			expected: []TokenType{TokenEOF},
			wantErr:  false,
		},
		{
			name:     "single character identifier",
			input:    "a",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
			wantErr:  false,
		},
		{
			name:     "underscore prefix",
			input:    "_selection",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
			wantErr:  false,
		},
		{
			name:     "many underscores",
			input:    "___selection___test___",
			expected: []TokenType{TokenIDENTIFIER, TokenEOF},
			wantErr:  false,
		},
		{
			name:     "number only",
			input:    "123",
			expected: []TokenType{TokenNUMBER, TokenEOF},
			wantErr:  false,
		},
		{
			name:     "large number",
			input:    "99999",
			expected: []TokenType{TokenNUMBER, TokenEOF},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Tokenize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}

			if !tt.wantErr {
				if len(tokens) != len(tt.expected) {
					t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.expected))
				}

				for i, expectedType := range tt.expected {
					if tokens[i].Type != expectedType {
						t.Errorf("token %d: got type %s, expected %s", i, tokens[i].Type, expectedType)
					}
				}
			}
		})
	}
}

// TestTokenize_PositionTracking tests that position information is correctly tracked.
func TestTokenize_PositionTracking(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		positions []int
	}{
		{
			name:      "simple expression",
			input:     "a or b",
			positions: []int{0, 2, 5, 6}, // a, or, b, EOF
		},
		{
			name:      "with spaces",
			input:     "  a  or  b  ",
			positions: []int{2, 5, 9, 12}, // a, or, b, EOF
		},
		{
			name:      "parentheses",
			input:     "(a)",
			positions: []int{0, 1, 2, 3}, // (, a, ), EOF
		},
		{
			name:      "complex",
			input:     "not (a and b)",
			positions: []int{0, 4, 5, 7, 11, 12, 13}, // not, (, a, and, b, ), EOF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if len(tokens) != len(tt.positions) {
				t.Fatalf("Tokenize(%q) got %d tokens, expected %d", tt.input, len(tokens), len(tt.positions))
			}

			for i, expectedPos := range tt.positions {
				if tokens[i].Position != expectedPos {
					t.Errorf("token %d: got position %d, expected %d", i, tokens[i].Position, expectedPos)
				}
			}
		})
	}
}

// TestTokenize_ErrorPositions tests that error messages include correct position information.
func TestTokenize_ErrorPositions(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPos  string
		expectedChar string
	}{
		{
			name:         "invalid char at start",
			input:        "@invalid",
			expectedPos:  "position 0",
			expectedChar: "@",
		},
		{
			name:         "invalid char in middle",
			input:        "selection @ filter",
			expectedPos:  "position 10",
			expectedChar: "@",
		},
		{
			name:         "invalid char at end",
			input:        "selection#",
			expectedPos:  "position 9",
			expectedChar: "#",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.input)
			if err == nil {
				t.Fatalf("Tokenize(%q) expected error, got nil", tt.input)
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.expectedPos) {
				t.Errorf("error message %q does not contain expected position %q", errMsg, tt.expectedPos)
			}
			if !strings.Contains(errMsg, tt.expectedChar) {
				t.Errorf("error message %q does not contain expected character %q", errMsg, tt.expectedChar)
			}
		})
	}
}

// TestTokenize_ValuePreservation tests that token values preserve original case.
func TestTokenize_ValuePreservation(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		tokenIndex    int
		expectedValue string
	}{
		{
			name:          "lowercase identifier",
			input:         "selection",
			tokenIndex:    0,
			expectedValue: "selection",
		},
		{
			name:          "uppercase identifier",
			input:         "SELECTION",
			tokenIndex:    0,
			expectedValue: "SELECTION",
		},
		{
			name:          "mixed case identifier",
			input:         "MySelection",
			tokenIndex:    0,
			expectedValue: "MySelection",
		},
		{
			name:          "lowercase keyword",
			input:         "and",
			tokenIndex:    0,
			expectedValue: "and",
		},
		{
			name:          "uppercase keyword",
			input:         "AND",
			tokenIndex:    0,
			expectedValue: "AND",
		},
		{
			name:          "mixed case keyword",
			input:         "And",
			tokenIndex:    0,
			expectedValue: "And",
		},
		{
			name:          "identifier with number",
			input:         "Selection123",
			tokenIndex:    0,
			expectedValue: "Selection123",
		},
		{
			name:          "identifier with underscore",
			input:         "My_Selection_Name",
			tokenIndex:    0,
			expectedValue: "My_Selection_Name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			if tt.tokenIndex >= len(tokens) {
				t.Fatalf("token index %d out of range (got %d tokens)", tt.tokenIndex, len(tokens))
			}

			if tokens[tt.tokenIndex].Value != tt.expectedValue {
				t.Errorf("token %d value: got %q, expected %q", tt.tokenIndex, tokens[tt.tokenIndex].Value, tt.expectedValue)
			}
		})
	}
}

// TestTokenize_AllTokenTypes tests that all token types are recognized correctly.
func TestTokenize_AllTokenTypes(t *testing.T) {
	input := "selection1 AND selection2 OR NOT ( 1 OF all any one them filter* ) )"
	expectedTypes := []TokenType{
		TokenIDENTIFIER, // selection1
		TokenAND,        // AND
		TokenIDENTIFIER, // selection2
		TokenOR,         // OR
		TokenNOT,        // NOT
		TokenLPAREN,     // (
		TokenNUMBER,     // 1
		TokenOF,         // OF
		TokenALL,        // all
		TokenANY,        // any
		TokenONE,        // one
		TokenTHEM,       // them
		TokenIDENTIFIER, // filter*
		TokenRPAREN,     // )
		TokenRPAREN,     // )
		TokenEOF,        // EOF
	}

	tokens, err := Tokenize(input)
	if err != nil {
		t.Fatalf("Tokenize(%q) error = %v", input, err)
	}

	if len(tokens) != len(expectedTypes) {
		t.Fatalf("Tokenize(%q) got %d tokens, expected %d", input, len(tokens), len(expectedTypes))
	}

	for i, expectedType := range expectedTypes {
		if tokens[i].Type != expectedType {
			t.Errorf("token %d: got type %s (%q), expected %s", i, tokens[i].Type, tokens[i].Value, expectedType)
		}
	}
}

// TestTokenize_RealWorldExamples tests realistic SIGMA condition expressions.
func TestTokenize_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple detection",
			input: "selection",
		},
		{
			name:  "two selections",
			input: "selection1 and selection2",
		},
		{
			name:  "exclusion",
			input: "selection and not filter",
		},
		{
			name:  "complex boolean",
			input: "(selection1 or selection2) and not (filter1 or filter2)",
		},
		{
			name:  "all of pattern",
			input: "all of selection_*",
		},
		{
			name:  "1 of pattern",
			input: "1 of selection_*",
		},
		{
			name:  "any of them",
			input: "any of them",
		},
		{
			name:  "combined aggregation and boolean",
			input: "1 of selection_* and not filter",
		},
		{
			name:  "nested aggregation",
			input: "(all of selection_*) or (any of filter_*)",
		},
		{
			name:  "complex with numbers",
			input: "2 of selection_*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v", tt.input, err)
			}

			// Verify tokens end with EOF
			if len(tokens) == 0 {
				t.Fatal("expected at least EOF token")
			}
			if tokens[len(tokens)-1].Type != TokenEOF {
				t.Errorf("expected last token to be EOF, got %s", tokens[len(tokens)-1].Type)
			}

			// Verify no unknown types
			for i, token := range tokens {
				if token.Type.String() == "UNKNOWN" {
					t.Errorf("token %d has unknown type: %v", i, token)
				}
			}
		})
	}
}

// TestParseNumber tests the ParseNumber utility function.
func TestParseNumber(t *testing.T) {
	tests := []struct {
		name      string
		token     Token
		expected  int
		wantError bool
	}{
		{
			name:      "valid number 1",
			token:     Token{Type: TokenNUMBER, Value: "1", Position: 0},
			expected:  1,
			wantError: false,
		},
		{
			name:      "valid number 10",
			token:     Token{Type: TokenNUMBER, Value: "10", Position: 0},
			expected:  10,
			wantError: false,
		},
		{
			name:      "valid number 999",
			token:     Token{Type: TokenNUMBER, Value: "999", Position: 0},
			expected:  999,
			wantError: false,
		},
		{
			name:      "not a number token",
			token:     Token{Type: TokenIDENTIFIER, Value: "abc", Position: 0},
			expected:  0,
			wantError: true,
		},
		{
			name:      "invalid number format",
			token:     Token{Type: TokenNUMBER, Value: "not-a-number", Position: 0},
			expected:  0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseNumber(tt.token)
			if (err != nil) != tt.wantError {
				t.Fatalf("ParseNumber(%v) error = %v, wantError %v", tt.token, err, tt.wantError)
			}

			if !tt.wantError && result != tt.expected {
				t.Errorf("ParseNumber(%v) = %d, expected %d", tt.token, result, tt.expected)
			}
		})
	}
}

// TestToken_String tests the String method of Token.
func TestToken_String(t *testing.T) {
	tests := []struct {
		name     string
		token    Token
		expected string
	}{
		{
			name:     "identifier token",
			token:    Token{Type: TokenIDENTIFIER, Value: "selection", Position: 0},
			expected: `IDENTIFIER("selection") at pos 0`,
		},
		{
			name:     "keyword token",
			token:    Token{Type: TokenAND, Value: "and", Position: 5},
			expected: `AND("and") at pos 5`,
		},
		{
			name:     "EOF token",
			token:    Token{Type: TokenEOF, Value: "", Position: 20},
			expected: `EOF("") at pos 20`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.String()
			if result != tt.expected {
				t.Errorf("Token.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestTokenType_String tests the String method of TokenType.
func TestTokenType_String(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		expected  string
	}{
		{TokenEOF, "EOF"},
		{TokenAND, "AND"},
		{TokenOR, "OR"},
		{TokenNOT, "NOT"},
		{TokenLPAREN, "LPAREN"},
		{TokenRPAREN, "RPAREN"},
		{TokenOF, "OF"},
		{TokenALL, "ALL"},
		{TokenANY, "ANY"},
		{TokenONE, "ONE"},
		{TokenTHEM, "THEM"},
		{TokenNUMBER, "NUMBER"},
		{TokenIDENTIFIER, "IDENTIFIER"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.tokenType.String()
			if result != tt.expected {
				t.Errorf("TokenType.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
