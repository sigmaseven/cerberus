package detect

import (
	"errors"
	"strings"
	"testing"
)

// TestUndefinedIdentifierError tests the UndefinedIdentifierError custom error type
func TestUndefinedIdentifierError(t *testing.T) {
	tests := []struct {
		name     string
		err      *UndefinedIdentifierError
		wantMsg  string
		contains []string
	}{
		{
			name: "undefined identifier with no available identifiers",
			err: &UndefinedIdentifierError{
				Identifier:           "unknown",
				Position:             10,
				AvailableIdentifiers: []string{},
			},
			wantMsg: "undefined identifier 'unknown' at position 10 (no identifiers available)",
		},
		{
			name: "undefined identifier with available identifiers",
			err: &UndefinedIdentifierError{
				Identifier:           "selection",
				Position:             5,
				AvailableIdentifiers: []string{"sel1", "sel2", "filter"},
			},
			contains: []string{"undefined identifier", "selection", "position 5", "available"},
		},
		{
			name: "undefined identifier with similar suggestions",
			err: &UndefinedIdentifierError{
				Identifier:           "selction",
				Position:             0,
				AvailableIdentifiers: []string{"selection", "selection_windows", "filter"},
			},
			contains: []string{"undefined identifier", "selction", "did you mean"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if tt.wantMsg != "" && msg != tt.wantMsg {
				t.Errorf("UndefinedIdentifierError.Error() = %q, want %q", msg, tt.wantMsg)
			}
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("UndefinedIdentifierError.Error() = %q, want to contain %q", msg, want)
				}
			}
		})
	}
}

// TestUndefinedIdentifierError_Is tests the Is() method for error matching
func TestUndefinedIdentifierError_Is(t *testing.T) {
	err1 := &UndefinedIdentifierError{
		Identifier:           "test",
		Position:             10,
		AvailableIdentifiers: []string{"a", "b"},
	}
	err2 := &UndefinedIdentifierError{
		Identifier:           "test",
		Position:             20, // Different position
		AvailableIdentifiers: []string{"c", "d"},
	}
	err3 := &UndefinedIdentifierError{
		Identifier:           "other",
		Position:             10,
		AvailableIdentifiers: []string{"a", "b"},
	}

	if !err1.Is(err2) {
		t.Error("UndefinedIdentifierError.Is() should match errors with same identifier")
	}

	if err1.Is(err3) {
		t.Error("UndefinedIdentifierError.Is() should not match errors with different identifier")
	}

	if err1.Is(errors.New("different error")) {
		t.Error("UndefinedIdentifierError.Is() should not match non-UndefinedIdentifierError")
	}
}

// TestParseError tests the ParseError custom error type
func TestParseError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParseError
		contains []string
	}{
		{
			name: "parse error with context",
			err: &ParseError{
				Position:   15,
				Token:      TokenRPAREN,
				TokenValue: ")",
				Expected:   "identifier",
				Context:    "unmatched closing parenthesis",
			},
			contains: []string{"parse error", "position 15", "expected identifier", "got RPAREN", "unmatched"},
		},
		{
			name: "parse error without context",
			err: &ParseError{
				Position:   0,
				Token:      TokenEOF,
				TokenValue: "",
				Expected:   "expression",
				Context:    "",
			},
			contains: []string{"parse error", "position 0", "expected expression", "got EOF"},
		},
		{
			name: "missing operand error",
			err: &ParseError{
				Position:   10,
				Token:      TokenAND,
				TokenValue: "and",
				Expected:   "expression after AND operator",
				Context:    "AND operator missing right operand",
			},
			contains: []string{"parse error", "position 10", "AND", "missing right operand"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("ParseError.Error() = %q, want to contain %q", msg, want)
				}
			}
		})
	}
}

// TestParseError_Is tests the Is() method for error matching
func TestParseError_Is(t *testing.T) {
	err1 := &ParseError{Position: 10, Token: TokenAND, TokenValue: "and", Expected: "expr", Context: ""}
	err2 := &ParseError{Position: 10, Token: TokenOR, TokenValue: "or", Expected: "expr", Context: ""}
	err3 := &ParseError{Position: 20, Token: TokenAND, TokenValue: "and", Expected: "expr", Context: ""}

	if !err1.Is(err2) {
		t.Error("ParseError.Is() should match errors at same position")
	}

	if err1.Is(err3) {
		t.Error("ParseError.Is() should not match errors at different positions")
	}

	if err1.Is(errors.New("different error")) {
		t.Error("ParseError.Is() should not match non-ParseError")
	}
}

// TestTokenizationError tests the TokenizationError custom error type
func TestTokenizationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *TokenizationError
		contains []string
	}{
		{
			name: "invalid character @",
			err: &TokenizationError{
				Position:    5,
				InvalidChar: '@',
				Context:     "test @ invalid",
			},
			contains: []string{"tokenization error", "position 5", "'@'", "context", "test @ invalid"},
		},
		{
			name: "invalid character #",
			err: &TokenizationError{
				Position:    0,
				InvalidChar: '#',
				Context:     "# start",
			},
			contains: []string{"tokenization error", "position 0", "'#'", "context"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("TokenizationError.Error() = %q, want to contain %q", msg, want)
				}
			}
		})
	}
}

// TestTokenizationError_Is tests the Is() method for error matching
func TestTokenizationError_Is(t *testing.T) {
	err1 := &TokenizationError{Position: 5, InvalidChar: '@', Context: "test"}
	err2 := &TokenizationError{Position: 5, InvalidChar: '#', Context: "different"}
	err3 := &TokenizationError{Position: 10, InvalidChar: '@', Context: "test"}

	if !err1.Is(err2) {
		t.Error("TokenizationError.Is() should match errors at same position")
	}

	if err1.Is(err3) {
		t.Error("TokenizationError.Is() should not match errors at different positions")
	}

	if err1.Is(errors.New("different error")) {
		t.Error("TokenizationError.Is() should not match non-TokenizationError")
	}
}

// TestAggregationError tests the AggregationError custom error type
func TestAggregationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *AggregationError
		contains []string
	}{
		{
			name: "pattern matched no identifiers",
			err: &AggregationError{
				Pattern:              "unknown_*",
				Position:             10,
				Reason:               "matched no identifiers",
				RequiredCount:        1,
				ActualCount:          0,
				AvailableIdentifiers: []string{"sel1", "sel2"},
			},
			contains: []string{"aggregation error", "position 10", "unknown_*", "matched no identifiers", "required: 1", "found: 0"},
		},
		{
			name: "insufficient matches",
			err: &AggregationError{
				Pattern:              "sel*",
				Position:             5,
				Reason:               "insufficient matches",
				RequiredCount:        5,
				ActualCount:          2,
				AvailableIdentifiers: []string{"sel1", "sel2"},
			},
			contains: []string{"aggregation error", "position 5", "sel*", "insufficient matches", "required: 5", "found: 2"},
		},
		{
			name: "no count info",
			err: &AggregationError{
				Pattern:              "them",
				Position:             0,
				Reason:               "evaluation failed",
				RequiredCount:        -1,
				ActualCount:          -1,
				AvailableIdentifiers: []string{"a", "b"},
			},
			contains: []string{"aggregation error", "position 0", "them", "evaluation failed", "available"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("AggregationError.Error() = %q, want to contain %q", msg, want)
				}
			}
		})
	}
}

// TestAggregationError_Is tests the Is() method for error matching
func TestAggregationError_Is(t *testing.T) {
	err1 := &AggregationError{Pattern: "sel*", Position: 10, Reason: "test", RequiredCount: 1, ActualCount: 0, AvailableIdentifiers: []string{}}
	err2 := &AggregationError{Pattern: "sel*", Position: 10, Reason: "other", RequiredCount: 2, ActualCount: 1, AvailableIdentifiers: []string{}}
	err3 := &AggregationError{Pattern: "other*", Position: 10, Reason: "test", RequiredCount: 1, ActualCount: 0, AvailableIdentifiers: []string{}}
	err4 := &AggregationError{Pattern: "sel*", Position: 20, Reason: "test", RequiredCount: 1, ActualCount: 0, AvailableIdentifiers: []string{}}

	if !err1.Is(err2) {
		t.Error("AggregationError.Is() should match errors with same pattern and position")
	}

	if err1.Is(err3) {
		t.Error("AggregationError.Is() should not match errors with different pattern")
	}

	if err1.Is(err4) {
		t.Error("AggregationError.Is() should not match errors with different position")
	}

	if err1.Is(errors.New("different error")) {
		t.Error("AggregationError.Is() should not match non-AggregationError")
	}
}

// TestValidationError tests the ValidationError custom error type
func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		contains []string
	}{
		{
			name: "single error",
			err: &ValidationError{
				Expression: "test expr",
				Errors:     []error{errors.New("syntax error")},
			},
			contains: []string{"validation failed", "test expr", "syntax error"},
		},
		{
			name: "multiple errors",
			err: &ValidationError{
				Expression: "complex expr",
				Errors: []error{
					errors.New("error 1"),
					errors.New("error 2"),
					errors.New("error 3"),
				},
			},
			contains: []string{"validation failed", "complex expr", "3 errors", "1. error 1", "2. error 2", "3. error 3"},
		},
		{
			name: "no errors",
			err: &ValidationError{
				Expression: "empty",
				Errors:     []error{},
			},
			contains: []string{"validation error", "no specific errors"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(msg, want) {
					t.Errorf("ValidationError.Error() = %q, want to contain %q", msg, want)
				}
			}
		})
	}
}

// TestValidationError_Unwrap tests the Unwrap() method
func TestValidationError_Unwrap(t *testing.T) {
	err1 := errors.New("first error")
	err2 := errors.New("second error")

	ve := &ValidationError{
		Expression: "test",
		Errors:     []error{err1, err2},
	}

	unwrapped := ve.Unwrap()
	if unwrapped != err1 {
		t.Errorf("ValidationError.Unwrap() = %v, want %v", unwrapped, err1)
	}

	veEmpty := &ValidationError{
		Expression: "test",
		Errors:     []error{},
	}

	if veEmpty.Unwrap() != nil {
		t.Errorf("ValidationError.Unwrap() on empty errors should return nil")
	}
}

// TestValidationError_Is tests the Is() method
func TestValidationError_Is(t *testing.T) {
	target := errors.New("target error")
	other := errors.New("other error")

	ve := &ValidationError{
		Expression: "test",
		Errors:     []error{errors.New("first"), target, errors.New("third")},
	}

	if !ve.Is(target) {
		t.Error("ValidationError.Is() should find matching error in list")
	}

	if ve.Is(other) {
		t.Error("ValidationError.Is() should not match error not in list")
	}
}

// TestTokenizeInvalidCharacter tests that Tokenize returns TokenizationError for invalid characters
func TestTokenizeInvalidCharacter(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantPos    int
		wantChar   rune
	}{
		{
			name:       "invalid @ character",
			expression: "selection @",
			wantPos:    10,
			wantChar:   '@',
		},
		{
			name:       "invalid # character",
			expression: "# comment",
			wantPos:    0,
			wantChar:   '#',
		},
		{
			name:       "invalid $ character",
			expression: "selection and $filter",
			wantPos:    14,
			wantChar:   '$',
		},
		{
			name:       "invalid % character",
			expression: "test % invalid",
			wantPos:    5,
			wantChar:   '%',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.expression)
			if err == nil {
				t.Fatal("Tokenize() should return error for invalid character")
			}

			var tokErr *TokenizationError
			if !errors.As(err, &tokErr) {
				t.Fatalf("Tokenize() error should be TokenizationError, got %T", err)
			}

			if tokErr.Position != tt.wantPos {
				t.Errorf("TokenizationError.Position = %d, want %d", tokErr.Position, tt.wantPos)
			}

			if tokErr.InvalidChar != tt.wantChar {
				t.Errorf("TokenizationError.InvalidChar = %q, want %q", tokErr.InvalidChar, tt.wantChar)
			}
		})
	}
}

// TestParseUnmatchedParentheses tests that parser returns ParseError for unmatched parentheses
func TestParseUnmatchedParentheses(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		wantErrType interface{}
		contains    string
	}{
		{
			name:        "unmatched left paren",
			expression:  "(selection",
			wantErrType: &ParseError{},
			contains:    "closing parenthesis",
		},
		{
			name:        "unmatched right paren",
			expression:  "selection)",
			wantErrType: &ParseError{},
			contains:    "RPAREN",
		},
		{
			name:        "multiple unmatched left parens",
			expression:  "((selection",
			wantErrType: &ParseError{},
			contains:    "closing parenthesis",
		},
		{
			name:        "nested with unmatched",
			expression:  "(selection and (filter)",
			wantErrType: &ParseError{},
			contains:    "closing parenthesis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(tt.expression)
			if err == nil {
				t.Fatal("Parse() should return error for unmatched parentheses")
			}

			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse() error should be ParseError, got %T: %v", err, err)
			}

			if !strings.Contains(parseErr.Error(), tt.contains) {
				t.Errorf("ParseError message = %q, want to contain %q", parseErr.Error(), tt.contains)
			}
		})
	}
}

// TestParseMissingOperands tests that parser returns ParseError for missing operands
func TestParseMissingOperands(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		contains   string
	}{
		{
			name:       "AND missing right operand",
			expression: "selection and",
			contains:   "AND operator missing right operand",
		},
		{
			name:       "OR missing right operand",
			expression: "selection or",
			contains:   "OR operator missing right operand",
		},
		{
			name:       "NOT missing operand",
			expression: "not",
			contains:   "NOT operator missing operand",
		},
		{
			name:       "AND missing left operand",
			expression: "and selection",
			contains:   "AND operator missing left operand",
		},
		{
			name:       "OR missing left operand",
			expression: "or selection",
			contains:   "OR operator missing left operand",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(tt.expression)
			if err == nil {
				t.Fatal("Parse() should return error for missing operand")
			}

			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse() error should be ParseError, got %T: %v", err, err)
			}

			if !strings.Contains(parseErr.Error(), tt.contains) {
				t.Errorf("ParseError message = %q, want to contain %q", parseErr.Error(), tt.contains)
			}
		})
	}
}

// TestParseUnexpectedEOF tests that parser returns ParseError for unexpected end of expression
func TestParseUnexpectedEOF(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{
			name:       "empty after NOT",
			expression: "selection and not",
		},
		{
			name:       "empty after AND",
			expression: "selection and",
		},
		{
			name:       "empty after OR",
			expression: "selection or",
		},
		{
			name:       "incomplete parentheses",
			expression: "selection and (",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(tt.expression)
			if err == nil {
				t.Fatal("Parse() should return error for unexpected EOF")
			}

			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse() error should be ParseError, got %T: %v", err, err)
			}
		})
	}
}

// TestParseAggregationErrors tests aggregation-specific error cases
func TestParseAggregationErrors(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		identifiers []string
		wantErrType interface{}
		contains    string
	}{
		{
			name:        "pattern matches no identifiers",
			expression:  "all of unknown_*",
			identifiers: []string{"selection1", "selection2"},
			wantErrType: &AggregationError{},
			contains:    "matched no identifiers",
		},
		{
			name:        "count exceeds matches",
			expression:  "5 of sel*",
			identifiers: []string{"sel1", "sel2"},
			wantErrType: &AggregationError{},
			contains:    "insufficient matches",
		},
		{
			name:        "pattern matches nothing with 'them'",
			expression:  "all of unknown",
			identifiers: []string{"selection1", "selection2"},
			wantErrType: &AggregationError{},
			contains:    "matched no identifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.ParseWithContext(tt.expression, tt.identifiers)
			if err == nil {
				t.Fatal("ParseWithContext() should return error for invalid aggregation")
			}

			var aggErr *AggregationError
			if !errors.As(err, &aggErr) {
				t.Fatalf("ParseWithContext() error should be AggregationError, got %T: %v", err, err)
			}

			if !strings.Contains(aggErr.Error(), tt.contains) {
				t.Errorf("AggregationError message = %q, want to contain %q", aggErr.Error(), tt.contains)
			}
		})
	}
}

// TestEvaluateUndefinedIdentifier tests that Evaluate returns UndefinedIdentifierError
func TestEvaluateUndefinedIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		context    map[string]bool
		wantIdent  string
	}{
		{
			name:       "single undefined identifier",
			expression: "unknown",
			context:    map[string]bool{"selection": true},
			wantIdent:  "unknown",
		},
		{
			name:       "undefined in AND expression",
			expression: "selection and unknown",
			context:    map[string]bool{"selection": true},
			wantIdent:  "unknown",
		},
		{
			name:       "undefined in OR expression",
			expression: "unknown or selection",
			context:    map[string]bool{"selection": false},
			wantIdent:  "unknown",
		},
		{
			name:       "undefined in NOT expression",
			expression: "not unknown",
			context:    map[string]bool{"selection": true},
			wantIdent:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.Parse(tt.expression)
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}

			_, evalErr := ast.Evaluate(tt.context)
			if evalErr == nil {
				t.Fatal("Evaluate() should return error for undefined identifier")
			}

			var undefinedErr *UndefinedIdentifierError
			if !errors.As(evalErr, &undefinedErr) {
				t.Fatalf("Evaluate() error should be UndefinedIdentifierError, got %T: %v", evalErr, evalErr)
			}

			if undefinedErr.Identifier != tt.wantIdent {
				t.Errorf("UndefinedIdentifierError.Identifier = %q, want %q", undefinedErr.Identifier, tt.wantIdent)
			}
		})
	}
}

// TestEvaluateAggregationUndefinedIdentifier tests aggregation evaluation with undefined identifiers
func TestEvaluateAggregationUndefinedIdentifier(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"selection1", "selection2", "filter"}

	// Parse aggregation that includes all identifiers
	ast, err := parser.ParseWithContext("all of them", identifiers)
	if err != nil {
		t.Fatalf("ParseWithContext() failed: %v", err)
	}

	// Try to evaluate with context missing one identifier
	context := map[string]bool{
		"selection1": true,
		"selection2": true,
		// "filter" is missing
	}

	_, evalErr := ast.Evaluate(context)
	if evalErr == nil {
		t.Fatal("Evaluate() should return error for undefined identifier in aggregation")
	}

	var undefinedErr *UndefinedIdentifierError
	if !errors.As(evalErr, &undefinedErr) {
		t.Fatalf("Evaluate() error should be UndefinedIdentifierError, got %T: %v", evalErr, evalErr)
	}

	if undefinedErr.Identifier != "filter" {
		t.Errorf("UndefinedIdentifierError.Identifier = %q, want %q", undefinedErr.Identifier, "filter")
	}
}

// TestValidateCondition tests the ValidateCondition function
func TestValidateCondition(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		identifiers []string
		wantErr     bool
		errType     interface{}
	}{
		{
			name:        "valid expression",
			expression:  "selection1 and selection2",
			identifiers: []string{"selection1", "selection2"},
			wantErr:     false,
		},
		{
			name:        "empty expression",
			expression:  "",
			identifiers: []string{"selection"},
			wantErr:     true,
			errType:     &ValidationError{},
		},
		{
			name:        "undefined identifier",
			expression:  "unknown",
			identifiers: []string{"selection"},
			wantErr:     true,
			errType:     &ValidationError{},
		},
		{
			name:        "syntax error - unmatched paren",
			expression:  "(selection",
			identifiers: []string{"selection"},
			wantErr:     true,
			errType:     &ValidationError{},
		},
		{
			name:        "tokenization error",
			expression:  "selection @",
			identifiers: []string{"selection"},
			wantErr:     true,
			errType:     &ValidationError{},
		},
		{
			name:        "multiple undefined identifiers",
			expression:  "unknown1 and unknown2",
			identifiers: []string{"selection"},
			wantErr:     true,
			errType:     &ValidationError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCondition(tt.expression, tt.identifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCondition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				var valErr *ValidationError
				if !errors.As(err, &valErr) {
					t.Errorf("ValidateCondition() error should be ValidationError, got %T", err)
				}
			}
		})
	}
}

// TestValidateConditionWithAggregation tests ValidateCondition with aggregation expressions
func TestValidateConditionWithAggregation(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		identifiers []string
		wantErr     bool
	}{
		{
			name:        "valid aggregation",
			expression:  "all of them",
			identifiers: []string{"selection1", "selection2"},
			wantErr:     false,
		},
		{
			name:        "valid pattern aggregation",
			expression:  "1 of sel*",
			identifiers: []string{"sel1", "sel2", "filter"},
			wantErr:     false,
		},
		{
			name:        "aggregation pattern matches nothing",
			expression:  "all of unknown_*",
			identifiers: []string{"selection1", "selection2"},
			wantErr:     true,
		},
		{
			name:        "aggregation count exceeds matches",
			expression:  "10 of sel*",
			identifiers: []string{"sel1", "sel2"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCondition(tt.expression, tt.identifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCondition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestErrorInterfaceCompliance verifies all custom errors implement error interface
func TestErrorInterfaceCompliance(t *testing.T) {
	var _ error = &UndefinedIdentifierError{}
	var _ error = &ParseError{}
	var _ error = &TokenizationError{}
	var _ error = &AggregationError{}
	var _ error = &ValidationError{}
}

// TestErrorUnwrapMethods verifies Unwrap() methods exist
func TestErrorUnwrapMethods(t *testing.T) {
	t.Run("UndefinedIdentifierError.Unwrap", func(t *testing.T) {
		err := &UndefinedIdentifierError{}
		if err.Unwrap() != nil {
			t.Error("UndefinedIdentifierError.Unwrap() should return nil")
		}
	})

	t.Run("ParseError.Unwrap", func(t *testing.T) {
		err := &ParseError{}
		if err.Unwrap() != nil {
			t.Error("ParseError.Unwrap() should return nil")
		}
	})

	t.Run("TokenizationError.Unwrap", func(t *testing.T) {
		err := &TokenizationError{}
		if err.Unwrap() != nil {
			t.Error("TokenizationError.Unwrap() should return nil")
		}
	})

	t.Run("AggregationError.Unwrap", func(t *testing.T) {
		err := &AggregationError{}
		if err.Unwrap() != nil {
			t.Error("AggregationError.Unwrap() should return nil")
		}
	})

	t.Run("ValidationError.Unwrap", func(t *testing.T) {
		wrapped := errors.New("wrapped")
		err := &ValidationError{Errors: []error{wrapped}}
		if err.Unwrap() != wrapped {
			t.Error("ValidationError.Unwrap() should return first error")
		}
	})
}

// TestFindSimilarIdentifiers tests the findSimilarIdentifiers helper function
func TestFindSimilarIdentifiers(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		available  []string
		maxResults int
		wantLen    int
		wantAny    []string
	}{
		{
			name:       "empty target",
			target:     "",
			available:  []string{"sel1", "sel2"},
			maxResults: 3,
			wantLen:    0,
		},
		{
			name:       "empty available",
			target:     "test",
			available:  []string{},
			maxResults: 3,
			wantLen:    0,
		},
		{
			name:       "prefix match",
			target:     "sel",
			available:  []string{"selection", "selector", "filter"},
			maxResults: 3,
			wantAny:    []string{"selection", "selector"},
		},
		{
			name:       "substring match",
			target:     "lect",
			available:  []string{"selection", "filter", "detect"},
			maxResults: 3,
			wantAny:    []string{"selection"},
		},
		{
			name:       "respects max results",
			target:     "sel",
			available:  []string{"sel1", "sel2", "sel3", "sel4"},
			maxResults: 2,
			wantLen:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findSimilarIdentifiers(tt.target, tt.available, tt.maxResults)

			if tt.wantLen > 0 && len(result) != tt.wantLen {
				t.Errorf("findSimilarIdentifiers() returned %d results, want %d", len(result), tt.wantLen)
			}

			if tt.wantAny != nil {
				found := false
				for _, want := range tt.wantAny {
					for _, got := range result {
						if got == want {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("findSimilarIdentifiers() should include %q, got %v", want, result)
					}
				}
			}
		})
	}
}

// TestExtractIdentifiers tests the extractIdentifiers helper function
func TestExtractIdentifiers(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantIdents []string
	}{
		{
			name:       "single identifier",
			expression: "selection",
			wantIdents: []string{"selection"},
		},
		{
			name:       "AND expression",
			expression: "sel1 and sel2",
			wantIdents: []string{"sel1", "sel2"},
		},
		{
			name:       "OR expression",
			expression: "sel1 or sel2",
			wantIdents: []string{"sel1", "sel2"},
		},
		{
			name:       "NOT expression",
			expression: "not filter",
			wantIdents: []string{"filter"},
		},
		{
			name:       "complex nested expression",
			expression: "(sel1 and sel2) or (not filter)",
			wantIdents: []string{"sel1", "sel2", "filter"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.Parse(tt.expression)
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}

			identifiers := extractIdentifiers(ast)

			for _, want := range tt.wantIdents {
				if _, found := identifiers[want]; !found {
					t.Errorf("extractIdentifiers() missing %q, got %v", want, identifiers)
				}
			}

			if len(identifiers) != len(tt.wantIdents) {
				t.Errorf("extractIdentifiers() returned %d identifiers, want %d", len(identifiers), len(tt.wantIdents))
			}
		})
	}
}

// TestExtractIdentifiersWithAggregation tests extractIdentifiers with aggregation nodes
func TestExtractIdentifiersWithAggregation(t *testing.T) {
	parser := NewConditionParser()
	identifiers := []string{"sel1", "sel2", "sel3"}

	ast, err := parser.ParseWithContext("all of sel*", identifiers)
	if err != nil {
		t.Fatalf("ParseWithContext() failed: %v", err)
	}

	extracted := extractIdentifiers(ast)

	for _, want := range []string{"sel1", "sel2", "sel3"} {
		if _, found := extracted[want]; !found {
			t.Errorf("extractIdentifiers() missing %q from aggregation, got %v", want, extracted)
		}
	}
}

// TestParseErrorPositionTracking tests that all errors include accurate position information
func TestParseErrorPositionTracking(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantPos    int
	}{
		{
			name:       "error at start",
			expression: "@ invalid",
			wantPos:    0,
		},
		{
			name:       "error in middle",
			expression: "selection @ invalid",
			wantPos:    10,
		},
		{
			name:       "error at end",
			expression: "selection and @",
			wantPos:    14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.expression)
			if err == nil {
				t.Fatal("Tokenize() should return error")
			}

			var tokErr *TokenizationError
			if !errors.As(err, &tokErr) {
				t.Fatalf("error should be TokenizationError, got %T", err)
			}

			if tokErr.Position != tt.wantPos {
				t.Errorf("error.Position = %d, want %d", tokErr.Position, tt.wantPos)
			}
		})
	}
}
