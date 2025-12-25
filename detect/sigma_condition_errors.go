package detect

import (
	"fmt"
	"strings"
)

// UndefinedIdentifierError represents an error when a condition references an undefined detection block identifier.
// This error provides detailed context about which identifier was not found and where it was referenced.
type UndefinedIdentifierError struct {
	// Identifier is the name of the undefined detection block
	Identifier string
	// Position is the byte offset in the expression where the identifier appears
	Position int
	// AvailableIdentifiers lists all valid identifiers that were available
	AvailableIdentifiers []string
}

// Error implements the error interface for UndefinedIdentifierError.
// Returns a descriptive message with suggestions for valid identifiers.
func (e *UndefinedIdentifierError) Error() string {
	if len(e.AvailableIdentifiers) == 0 {
		return fmt.Sprintf("undefined identifier '%s' at position %d (no identifiers available)",
			e.Identifier, e.Position)
	}

	// Provide helpful suggestions
	suggestions := findSimilarIdentifiers(e.Identifier, e.AvailableIdentifiers, 3)
	if len(suggestions) > 0 {
		return fmt.Sprintf("undefined identifier '%s' at position %d (did you mean: %s? available: %v)",
			e.Identifier, e.Position, strings.Join(suggestions, ", "), e.AvailableIdentifiers)
	}

	return fmt.Sprintf("undefined identifier '%s' at position %d (available: %v)",
		e.Identifier, e.Position, e.AvailableIdentifiers)
}

// Unwrap returns nil as this error doesn't wrap another error.
// Provided for compatibility with errors.Unwrap().
func (e *UndefinedIdentifierError) Unwrap() error {
	return nil
}

// Is implements error matching for errors.Is().
// Returns true if the target error is an UndefinedIdentifierError with the same identifier.
func (e *UndefinedIdentifierError) Is(target error) bool {
	t, ok := target.(*UndefinedIdentifierError)
	if !ok {
		return false
	}
	return e.Identifier == t.Identifier
}

// ParseError represents a syntax error during parsing of a SIGMA condition expression.
// It provides detailed context about what was expected versus what was found.
type ParseError struct {
	// Position is the byte offset in the expression where the error occurred
	Position int
	// Token is the actual token that was encountered
	Token TokenType
	// TokenValue is the string value of the token
	TokenValue string
	// Expected describes what token(s) were expected at this position
	Expected string
	// Context provides additional context about the error
	Context string
}

// Error implements the error interface for ParseError.
// Returns a descriptive message with position, expected vs actual, and context.
func (e *ParseError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("parse error at position %d: expected %s but got %s (%q) - %s",
			e.Position, e.Expected, e.Token, e.TokenValue, e.Context)
	}
	return fmt.Sprintf("parse error at position %d: expected %s but got %s (%q)",
		e.Position, e.Expected, e.Token, e.TokenValue)
}

// Unwrap returns nil as this error doesn't wrap another error.
// Provided for compatibility with errors.Unwrap().
func (e *ParseError) Unwrap() error {
	return nil
}

// Is implements error matching for errors.Is().
// Returns true if the target error is a ParseError at the same position.
func (e *ParseError) Is(target error) bool {
	t, ok := target.(*ParseError)
	if !ok {
		return false
	}
	return e.Position == t.Position
}

// TokenizationError represents an error during tokenization (lexical analysis) of a SIGMA condition expression.
// This occurs when the input contains invalid characters or malformed tokens.
type TokenizationError struct {
	// Position is the byte offset where the invalid character/sequence appears
	Position int
	// InvalidChar is the invalid character that was encountered
	InvalidChar rune
	// Context provides surrounding text for debugging
	Context string
}

// Error implements the error interface for TokenizationError.
// Returns a descriptive message with position and context.
func (e *TokenizationError) Error() string {
	return fmt.Sprintf("tokenization error at position %d: invalid character %q (context: %q)",
		e.Position, e.InvalidChar, e.Context)
}

// Unwrap returns nil as this error doesn't wrap another error.
// Provided for compatibility with errors.Unwrap().
func (e *TokenizationError) Unwrap() error {
	return nil
}

// Is implements error matching for errors.Is().
// Returns true if the target error is a TokenizationError at the same position.
func (e *TokenizationError) Is(target error) bool {
	t, ok := target.(*TokenizationError)
	if !ok {
		return false
	}
	return e.Position == t.Position
}

// AggregationError represents an error during aggregation expression parsing or evaluation.
// This includes errors like patterns matching zero identifiers or insufficient matches.
type AggregationError struct {
	// Pattern is the aggregation pattern that caused the error (e.g., "selection_*", "them")
	Pattern string
	// Position is the byte offset where the aggregation expression starts
	Position int
	// Reason describes why the aggregation failed
	Reason string
	// RequiredCount is the number of matches required (for count-based aggregations)
	RequiredCount int
	// ActualCount is the number of matches found
	ActualCount int
	// AvailableIdentifiers lists all identifiers that were available for matching
	AvailableIdentifiers []string
}

// Error implements the error interface for AggregationError.
// Returns a descriptive message explaining the aggregation failure.
func (e *AggregationError) Error() string {
	if e.RequiredCount > 0 && e.ActualCount >= 0 {
		return fmt.Sprintf("aggregation error at position %d: pattern %q %s (required: %d, found: %d, available: %v)",
			e.Position, e.Pattern, e.Reason, e.RequiredCount, e.ActualCount, e.AvailableIdentifiers)
	}
	if len(e.AvailableIdentifiers) > 0 {
		return fmt.Sprintf("aggregation error at position %d: pattern %q %s (available: %v)",
			e.Position, e.Pattern, e.Reason, e.AvailableIdentifiers)
	}
	return fmt.Sprintf("aggregation error at position %d: pattern %q %s",
		e.Position, e.Pattern, e.Reason)
}

// Unwrap returns nil as this error doesn't wrap another error.
// Provided for compatibility with errors.Unwrap().
func (e *AggregationError) Unwrap() error {
	return nil
}

// Is implements error matching for errors.Is().
// Returns true if the target error is an AggregationError with the same pattern and position.
func (e *AggregationError) Is(target error) bool {
	t, ok := target.(*AggregationError)
	if !ok {
		return false
	}
	return e.Pattern == t.Pattern && e.Position == t.Position
}

// ValidationError represents a collection of errors found during expression validation.
// This allows ValidateCondition to return all errors found, not just the first one.
type ValidationError struct {
	// Errors is the list of all validation errors found
	Errors []error
	// Expression is the original expression that was being validated
	Expression string
}

// Error implements the error interface for ValidationError.
// Returns a message listing all validation errors.
func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "validation error: no specific errors recorded"
	}

	if len(e.Errors) == 1 {
		return fmt.Sprintf("validation failed for expression %q: %v", e.Expression, e.Errors[0])
	}

	var errMsgs []string
	for i, err := range e.Errors {
		errMsgs = append(errMsgs, fmt.Sprintf("%d. %v", i+1, err))
	}

	return fmt.Sprintf("validation failed for expression %q with %d errors:\n%s",
		e.Expression, len(e.Errors), strings.Join(errMsgs, "\n"))
}

// Unwrap returns the first error in the list, or nil if the list is empty.
// This provides compatibility with errors.Unwrap().
func (e *ValidationError) Unwrap() error {
	if len(e.Errors) == 0 {
		return nil
	}
	return e.Errors[0]
}

// Is implements error matching for errors.Is().
// Returns true if any of the wrapped errors match the target.
func (e *ValidationError) Is(target error) bool {
	for _, err := range e.Errors {
		if err == target {
			return true
		}
	}
	return false
}

// findSimilarIdentifiers finds identifiers that are similar to the target using simple heuristics.
// This provides helpful suggestions in error messages for typos or similar names.
//
// Heuristics used:
// 1. Starts with the same prefix (first 3 characters)
// 2. Contains the target as a substring
// 3. Target is a substring of the identifier
//
// Parameters:
//   - target: the identifier that was not found
//   - available: list of valid identifiers to search
//   - maxResults: maximum number of suggestions to return
//
// Returns:
//   - []string: list of similar identifiers (up to maxResults)
func findSimilarIdentifiers(target string, available []string, maxResults int) []string {
	if len(available) == 0 || target == "" {
		return nil
	}

	var suggestions []string
	targetLower := strings.ToLower(target)

	// First pass: exact prefix matches (most likely typos)
	prefixLen := 3
	if len(targetLower) < prefixLen {
		prefixLen = len(targetLower)
	}
	targetPrefix := targetLower[:prefixLen]

	for _, identifier := range available {
		identLower := strings.ToLower(identifier)
		if len(identLower) >= prefixLen && identLower[:prefixLen] == targetPrefix {
			suggestions = append(suggestions, identifier)
			if len(suggestions) >= maxResults {
				return suggestions
			}
		}
	}

	// Second pass: substring matches
	if len(suggestions) < maxResults {
		for _, identifier := range available {
			identLower := strings.ToLower(identifier)
			// Skip if already suggested
			alreadySuggested := false
			for _, s := range suggestions {
				if s == identifier {
					alreadySuggested = true
					break
				}
			}
			if alreadySuggested {
				continue
			}

			// Check if target is substring of identifier or vice versa
			if strings.Contains(identLower, targetLower) || strings.Contains(targetLower, identLower) {
				suggestions = append(suggestions, identifier)
				if len(suggestions) >= maxResults {
					return suggestions
				}
			}
		}
	}

	return suggestions
}

// ValidateCondition validates a SIGMA condition expression without evaluating it.
// This is a dry-run that checks for syntax errors and undefined identifiers early.
//
// The function performs the following validations:
//  1. Tokenization succeeds (no invalid characters)
//  2. Parsing succeeds (valid syntax)
//  3. All referenced identifiers exist in availableIdentifiers
//  4. All aggregation patterns match at least one identifier
//  5. Aggregation counts don't exceed available matches
//
// Parameters:
//   - expression: the SIGMA condition expression to validate
//   - availableIdentifiers: list of detection block names that exist in the rule
//
// Returns:
//   - error: nil if validation succeeds, otherwise a ValidationError with all errors found
//
// Example usage:
//
//	err := ValidateCondition("selection1 and not selection2", []string{"selection1", "selection2"})
//	if err != nil {
//	    log.Fatalf("Invalid condition: %v", err)
//	}
func ValidateCondition(expression string, availableIdentifiers []string) error {
	if expression == "" {
		return &ValidationError{
			Expression: expression,
			Errors:     []error{fmt.Errorf("condition expression cannot be empty")},
		}
	}

	var validationErrors []error

	// Step 1: Tokenize the expression
	_, err := Tokenize(expression)
	if err != nil {
		validationErrors = append(validationErrors, err)
		// Cannot continue without valid tokens
		return &ValidationError{
			Expression: expression,
			Errors:     validationErrors,
		}
	}

	// Step 2: Parse the expression
	parser := NewConditionParser()
	var ast ConditionNode

	if len(availableIdentifiers) > 0 {
		ast, err = parser.ParseWithContext(expression, availableIdentifiers)
	} else {
		ast, err = parser.Parse(expression)
	}

	if err != nil {
		validationErrors = append(validationErrors, err)
		// Cannot continue without valid AST
		return &ValidationError{
			Expression: expression,
			Errors:     validationErrors,
		}
	}

	// Step 3: Validate all identifiers exist
	// Extract all identifiers from the AST
	referencedIdentifiers := extractIdentifiers(ast)

	// Create a map for fast lookup
	availableMap := make(map[string]bool)
	for _, id := range availableIdentifiers {
		availableMap[id] = true
	}

	// Check each referenced identifier
	for identifier, position := range referencedIdentifiers {
		if !availableMap[identifier] {
			validationErrors = append(validationErrors, &UndefinedIdentifierError{
				Identifier:           identifier,
				Position:             position,
				AvailableIdentifiers: availableIdentifiers,
			})
		}
	}

	// If there were any validation errors, return them all
	if len(validationErrors) > 0 {
		return &ValidationError{
			Expression: expression,
			Errors:     validationErrors,
		}
	}

	return nil
}

// extractIdentifiers recursively extracts all identifier names and their positions from an AST.
// Returns a map of identifier -> position for validation purposes.
func extractIdentifiers(node ConditionNode) map[string]int {
	result := make(map[string]int)

	if node == nil {
		return result
	}

	switch n := node.(type) {
	case *IdentifierNode:
		// For IdentifierNode, we don't have position info stored in the node.
		// We use 0 as a placeholder since we validate during parsing anyway.
		result[n.Name] = 0

	case *BinaryOpNode:
		// Recursively extract from left and right
		leftIds := extractIdentifiers(n.Left)
		rightIds := extractIdentifiers(n.Right)
		for id, pos := range leftIds {
			result[id] = pos
		}
		for id, pos := range rightIds {
			result[id] = pos
		}

	case *NotNode:
		// Recursively extract from child
		childIds := extractIdentifiers(n.Child)
		for id, pos := range childIds {
			result[id] = pos
		}

	case *AggregationNode:
		// Aggregation nodes have their identifiers already resolved
		for _, id := range n.Identifiers {
			result[id] = 0 // Position not stored in aggregation node
		}
	}

	return result
}
