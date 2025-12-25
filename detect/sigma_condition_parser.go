package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TokenType represents the type of a token in a SIGMA condition expression.
type TokenType int

const (
	// TokenEOF represents end of input
	TokenEOF TokenType = iota
	// TokenAND represents the AND logical operator
	TokenAND
	// TokenOR represents the OR logical operator
	TokenOR
	// TokenNOT represents the NOT logical operator
	TokenNOT
	// TokenLPAREN represents a left parenthesis
	TokenLPAREN
	// TokenRPAREN represents a right parenthesis
	TokenRPAREN
	// TokenOF represents the OF keyword in aggregation expressions
	TokenOF
	// TokenALL represents the ALL keyword in aggregation expressions
	TokenALL
	// TokenANY represents the ANY keyword in aggregation expressions
	TokenANY
	// TokenONE represents the ONE keyword in aggregation expressions (for "one of them")
	TokenONE
	// TokenTHEM represents the THEM keyword in aggregation expressions
	TokenTHEM
	// TokenNUMBER represents a numeric literal (for "N of" expressions)
	TokenNUMBER
	// TokenIDENTIFIER represents a detection block name (may include wildcards)
	TokenIDENTIFIER
)

// String returns the string representation of a token type.
func (tt TokenType) String() string {
	switch tt {
	case TokenEOF:
		return "EOF"
	case TokenAND:
		return "AND"
	case TokenOR:
		return "OR"
	case TokenNOT:
		return "NOT"
	case TokenLPAREN:
		return "LPAREN"
	case TokenRPAREN:
		return "RPAREN"
	case TokenOF:
		return "OF"
	case TokenALL:
		return "ALL"
	case TokenANY:
		return "ANY"
	case TokenONE:
		return "ONE"
	case TokenTHEM:
		return "THEM"
	case TokenNUMBER:
		return "NUMBER"
	case TokenIDENTIFIER:
		return "IDENTIFIER"
	default:
		return "UNKNOWN"
	}
}

// Token represents a single token in a SIGMA condition expression.
// It includes the token type, the original value, and position information for error reporting.
type Token struct {
	// Type is the token type
	Type TokenType
	// Value is the original string value of the token
	Value string
	// Position is the byte offset in the original expression where this token starts
	Position int
}

// String returns a string representation of the token for debugging.
func (t Token) String() string {
	return fmt.Sprintf("%s(%q) at pos %d", t.Type, t.Value, t.Position)
}

// tokenPattern represents a regex pattern for matching a specific token type.
type tokenPattern struct {
	Type    TokenType
	Pattern *regexp.Regexp
}

var (
	// tokenPatterns defines the regex patterns for each token type, in priority order.
	// Keywords must come before identifiers to prevent matching keywords as identifiers.
	tokenPatterns = []tokenPattern{
		// Keywords (must be matched as whole words)
		{TokenAND, regexp.MustCompile(`^(?i)\band\b`)},
		{TokenOR, regexp.MustCompile(`^(?i)\bor\b`)},
		{TokenNOT, regexp.MustCompile(`^(?i)\bnot\b`)},
		{TokenOF, regexp.MustCompile(`^(?i)\bof\b`)},
		{TokenALL, regexp.MustCompile(`^(?i)\ball\b`)},
		{TokenANY, regexp.MustCompile(`^(?i)\bany\b`)},
		{TokenONE, regexp.MustCompile(`^(?i)\bone\b`)},
		{TokenTHEM, regexp.MustCompile(`^(?i)\bthem\b`)},

		// Numbers (for "N of" expressions)
		{TokenNUMBER, regexp.MustCompile(`^\d+`)},

		// Parentheses
		{TokenLPAREN, regexp.MustCompile(`^\(`)},
		{TokenRPAREN, regexp.MustCompile(`^\)`)},

		// Identifiers (alphanumeric, underscore, asterisk for wildcards)
		// Must come after keywords to avoid matching keywords as identifiers
		// Supports wildcards at any position: selection*, *_process, *windows*, sel*win*
		{TokenIDENTIFIER, regexp.MustCompile(`^[a-zA-Z0-9_*]+`)},
	}

	// whitespacePattern matches whitespace characters (spaces, tabs, newlines)
	whitespacePattern = regexp.MustCompile(`^\s+`)
)

// Tokenize converts a SIGMA condition expression string into a slice of tokens.
// It performs lexical analysis with the following properties:
//   - Case-insensitive keyword matching (AND, Or, not all work)
//   - Keyword boundary detection (prevents "notation" from matching "not")
//   - Wildcard support in identifiers (selection*, *_windows, etc.)
//   - Position tracking for precise error reporting
//   - Comprehensive validation and error handling
//
// Returns a slice of tokens and an error if the expression contains invalid characters
// or malformed syntax. The returned tokens include an EOF token at the end.
func Tokenize(expression string) ([]Token, error) {
	if expression == "" {
		return []Token{{Type: TokenEOF, Value: "", Position: 0}}, nil
	}

	var tokens []Token
	position := 0

	for position < len(expression) {
		// Skip whitespace
		if match := whitespacePattern.FindString(expression[position:]); match != "" {
			position += len(match)
			continue
		}

		// Try to match a token pattern
		matched := false
		for _, pattern := range tokenPatterns {
			if match := pattern.Pattern.FindString(expression[position:]); match != "" {
				tokens = append(tokens, Token{
					Type:     pattern.Type,
					Value:    match,
					Position: position,
				})
				position += len(match)
				matched = true
				break
			}
		}

		if !matched {
			// Extract context around the error position for better error messages
			start := position
			if start > 20 {
				start = position - 20
			}
			end := position + 20
			if end > len(expression) {
				end = len(expression)
			}
			context := expression[start:end]

			return nil, &TokenizationError{
				Position:    position,
				InvalidChar: rune(expression[position]),
				Context:     context,
			}
		}
	}

	// Add EOF token
	tokens = append(tokens, Token{Type: TokenEOF, Value: "", Position: position})

	return tokens, nil
}

// ParseNumber extracts the integer value from a TokenNUMBER token.
// Returns an error if the token is not a number or if the number is invalid.
// Note: The tokenizer regex (^\d+) only matches non-negative integers,
// so negative numbers are not possible at the tokenization stage.
func ParseNumber(token Token) (int, error) {
	if token.Type != TokenNUMBER {
		return 0, fmt.Errorf("expected NUMBER token, got %s at position %d", token.Type, token.Position)
	}

	value, err := strconv.Atoi(token.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q at position %d: %w", token.Value, token.Position, err)
	}

	return value, nil
}

// ConditionNode represents a node in the SIGMA condition expression AST.
// All condition nodes must implement the Evaluate method to compute their
// boolean result given a context mapping detection block names to their results.
type ConditionNode interface {
	// Evaluate computes the boolean result of this condition node.
	// The context maps detection block identifiers (e.g., "selection1") to their match results.
	// Returns an error if evaluation fails (e.g., unknown identifier, invalid state).
	Evaluate(context map[string]bool) (bool, error)
}

// IdentifierNode represents a reference to a detection block (e.g., "selection", "filter").
// It evaluates to the boolean value stored in the context for that identifier.
type IdentifierNode struct {
	// Name is the identifier of the detection block
	Name string
}

// Evaluate looks up the identifier in the context and returns its boolean value.
// Returns an error if the identifier is not found in the context.
func (n *IdentifierNode) Evaluate(context map[string]bool) (bool, error) {
	if n == nil {
		return false, fmt.Errorf("identifier node is nil")
	}

	if context == nil {
		return false, fmt.Errorf("evaluation context is nil")
	}

	value, exists := context[n.Name]
	if !exists {
		// Build list of available identifiers for error message
		available := make([]string, 0, len(context))
		for k := range context {
			available = append(available, k)
		}
		return false, &UndefinedIdentifierError{
			Identifier:           n.Name,
			Position:             0, // Position not tracked in node
			AvailableIdentifiers: available,
		}
	}

	return value, nil
}

// BinaryOperator represents the type of binary operation (AND, OR).
type BinaryOperator int

const (
	// OpAND represents a logical AND operation
	OpAND BinaryOperator = iota
	// OpOR represents a logical OR operation
	OpOR
)

// String returns the string representation of the binary operator.
func (op BinaryOperator) String() string {
	switch op {
	case OpAND:
		return "AND"
	case OpOR:
		return "OR"
	default:
		return "UNKNOWN"
	}
}

// BinaryOpNode represents a binary logical operation (AND/OR) between two condition nodes.
// It implements short-circuit evaluation:
// - AND: if left is false, right is not evaluated
// - OR: if left is true, right is not evaluated
type BinaryOpNode struct {
	// Operator is the binary operation type (AND or OR)
	Operator BinaryOperator
	// Left is the left operand
	Left ConditionNode
	// Right is the right operand
	Right ConditionNode
}

// Evaluate computes the binary operation result with short-circuit logic.
// For AND: returns false immediately if left is false, otherwise evaluates right.
// For OR: returns true immediately if left is true, otherwise evaluates right.
// Returns an error if either operand evaluation fails or if the node is invalid.
func (n *BinaryOpNode) Evaluate(context map[string]bool) (bool, error) {
	if n == nil {
		return false, fmt.Errorf("binary operation node is nil")
	}

	if n.Left == nil {
		return false, fmt.Errorf("binary operation left operand is nil")
	}

	if n.Right == nil {
		return false, fmt.Errorf("binary operation right operand is nil")
	}

	leftResult, err := n.Left.Evaluate(context)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate left operand of %s: %w", n.Operator, err)
	}

	// Short-circuit evaluation
	switch n.Operator {
	case OpAND:
		// AND: if left is false, don't evaluate right
		if !leftResult {
			return false, nil
		}
		// Left is true, evaluate right
		rightResult, err := n.Right.Evaluate(context)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate right operand of AND: %w", err)
		}
		return rightResult, nil

	case OpOR:
		// OR: if left is true, don't evaluate right
		if leftResult {
			return true, nil
		}
		// Left is false, evaluate right
		rightResult, err := n.Right.Evaluate(context)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate right operand of OR: %w", err)
		}
		return rightResult, nil

	default:
		return false, fmt.Errorf("unknown binary operator: %v", n.Operator)
	}
}

// NotNode represents a logical NOT operation that negates a child condition node.
type NotNode struct {
	// Child is the condition node to negate
	Child ConditionNode
}

// Evaluate computes the logical negation of the child node's result.
// Returns an error if the child evaluation fails or if the node is invalid.
func (n *NotNode) Evaluate(context map[string]bool) (bool, error) {
	if n == nil {
		return false, fmt.Errorf("not node is nil")
	}

	if n.Child == nil {
		return false, fmt.Errorf("not node child is nil")
	}

	childResult, err := n.Child.Evaluate(context)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate NOT child: %w", err)
	}

	return !childResult, nil
}

// AggregationType represents the type of aggregation operation.
type AggregationType int

const (
	// AggAll represents "all of" aggregation (all identifiers must be true)
	AggAll AggregationType = iota
	// AggAny represents "any of" aggregation (at least one identifier must be true)
	AggAny
	// AggCount represents "N of" aggregation (exactly N identifiers must be true)
	AggCount
)

// String returns the string representation of the aggregation type.
func (agg AggregationType) String() string {
	switch agg {
	case AggAll:
		return "all of"
	case AggAny:
		return "any of"
	case AggCount:
		return "count of"
	default:
		return "unknown"
	}
}

// AggregationNode represents an aggregation expression like "all of", "any of", or "1 of".
// It evaluates a set of identifiers according to the aggregation type.
type AggregationNode struct {
	// Type is the aggregation type (ALL/ANY/COUNT)
	Type AggregationType
	// Pattern is the original pattern string (e.g., "selection*", "filter*")
	Pattern string
	// Identifiers is the list of detection block identifiers to aggregate
	Identifiers []string
	// Count is the required count for AggCount type (e.g., 1 for "1 of")
	Count int
}

// Evaluate computes the aggregation result based on the aggregation type.
// - ALL: returns true if all identifiers evaluate to true
// - ANY: returns true if at least one identifier evaluates to true
// - COUNT: returns true if at least Count identifiers evaluate to true
// Returns an error if any identifier evaluation fails or if the node is invalid.
func (n *AggregationNode) Evaluate(context map[string]bool) (bool, error) {
	if n == nil {
		return false, fmt.Errorf("aggregation node is nil")
	}

	if context == nil {
		return false, fmt.Errorf("evaluation context is nil")
	}

	if len(n.Identifiers) == 0 {
		// Build list of available identifiers for error message
		available := make([]string, 0, len(context))
		for k := range context {
			available = append(available, k)
		}
		return false, &AggregationError{
			Pattern:              n.Pattern,
			Position:             0, // Position not tracked in node
			Reason:               "matched no identifiers",
			RequiredCount:        n.Count,
			ActualCount:          0,
			AvailableIdentifiers: available,
		}
	}

	// Evaluate all identifiers and collect results
	trueCount := 0
	for _, identifier := range n.Identifiers {
		value, exists := context[identifier]
		if !exists {
			// Build list of available identifiers for error message
			available := make([]string, 0, len(context))
			for k := range context {
				available = append(available, k)
			}
			return false, &UndefinedIdentifierError{
				Identifier:           identifier,
				Position:             0, // Position not tracked in node
				AvailableIdentifiers: available,
			}
		}

		if value {
			trueCount++
		}
	}

	// Apply aggregation logic
	switch n.Type {
	case AggAll:
		// All identifiers must be true
		return trueCount == len(n.Identifiers), nil

	case AggAny:
		// At least one identifier must be true
		return trueCount > 0, nil

	case AggCount:
		// At least Count identifiers must be true
		return trueCount >= n.Count, nil

	default:
		return false, fmt.Errorf("unknown aggregation type: %v", n.Type)
	}
}

// ParsePatternIdentifiers expands a pattern (e.g., "selection*") into a list of matching identifiers
// from the available detection blocks. This is a utility function for building AggregationNodes.
func ParsePatternIdentifiers(pattern string, availableBlocks []string) []string {
	var matches []string

	// Handle wildcard patterns
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		for _, block := range availableBlocks {
			if strings.HasPrefix(block, prefix) {
				matches = append(matches, block)
			}
		}
	} else {
		// Exact match
		for _, block := range availableBlocks {
			if block == pattern {
				matches = append(matches, block)
				break
			}
		}
	}

	return matches
}

// ConditionParser is a recursive descent parser for SIGMA condition expressions.
// It parses a token stream into an abstract syntax tree (AST) of ConditionNode objects.
//
// The parser implements the following operator precedence (highest to lowest):
//  1. NOT (unary prefix operator)
//  2. AND (binary infix operator)
//  3. OR (binary infix operator)
//
// All binary operators are left-associative, meaning "a op b op c" parses as "(a op b) op c".
// Parentheses can override precedence to force different grouping.
//
// Example usage:
//
//	parser := NewConditionParser()
//	ast, err := parser.Parse("selection1 and not (selection2 or selection3)")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := ast.Evaluate(context)
type ConditionParser struct {
	// tokens is the slice of tokens to parse
	tokens []Token
	// position is the current position in the token stream (0-based index)
	position int
	// availableIdentifiers is the list of detection block names available for aggregation matching
	// This is required for parsing aggregation expressions like "all of them" or "1 of selection_*"
	availableIdentifiers []string
}

// NewConditionParser creates a new parser instance.
func NewConditionParser() *ConditionParser {
	return &ConditionParser{
		tokens:   nil,
		position: 0,
	}
}

// Parse is the main entry point for parsing a SIGMA condition expression.
// It tokenizes the expression, builds an AST, and validates that all tokens are consumed.
//
// Note: This method does not support aggregation expressions. Use ParseWithContext()
// if the expression contains aggregations like "all of them" or "1 of selection_*".
//
// Returns an error if:
//   - The expression is empty
//   - Tokenization fails
//   - Parsing encounters a syntax error
//   - There are unconsumed tokens after parsing completes
func (p *ConditionParser) Parse(expression string) (ConditionNode, error) {
	if expression == "" {
		return nil, fmt.Errorf("cannot parse empty condition expression")
	}

	// Tokenize the expression
	tokens, err := Tokenize(expression)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}

	// Initialize parser state
	p.tokens = tokens
	p.position = 0
	p.availableIdentifiers = nil // No aggregation support

	// Parse the expression starting from lowest precedence (OR)
	ast, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Validate that we consumed all tokens (except EOF)
	if !p.isAtEnd() {
		current := p.current()
		return nil, &ParseError{
			Position:   current.Position,
			Token:      current.Type,
			TokenValue: current.Value,
			Expected:   "end of expression",
			Context:    "unexpected tokens remain after parsing complete expression",
		}
	}

	return ast, nil
}

// ParseWithContext parses a SIGMA condition expression with context for aggregation support.
// It is similar to Parse() but also accepts a list of available detection block identifiers
// that can be referenced in aggregation expressions like "all of them" or "1 of selection_*".
//
// Parameters:
//   - expression: the SIGMA condition expression string to parse
//   - availableIdentifiers: slice of detection block names that exist in the SIGMA rule
//
// Returns an error if:
//   - The expression is empty
//   - availableIdentifiers is nil or empty (use Parse() instead if no aggregations needed)
//   - Tokenization fails
//   - Parsing encounters a syntax error
//   - There are unconsumed tokens after parsing completes
//   - An aggregation pattern matches no identifiers
//
// Example:
//
//	parser := NewConditionParser()
//	identifiers := []string{"selection_windows", "selection_linux", "filter1"}
//	ast, err := parser.ParseWithContext("1 of selection_*", identifiers)
func (p *ConditionParser) ParseWithContext(expression string, availableIdentifiers []string) (ConditionNode, error) {
	if expression == "" {
		return nil, fmt.Errorf("cannot parse empty condition expression")
	}

	if availableIdentifiers == nil {
		return nil, fmt.Errorf("availableIdentifiers cannot be nil (use Parse() if no aggregations needed)")
	}

	if len(availableIdentifiers) == 0 {
		return nil, fmt.Errorf("availableIdentifiers cannot be empty (use Parse() if no aggregations needed)")
	}

	// Tokenize the expression
	tokens, err := Tokenize(expression)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}

	// Initialize parser state
	p.tokens = tokens
	p.position = 0
	p.availableIdentifiers = availableIdentifiers

	// Parse the expression starting from lowest precedence (OR)
	ast, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Validate that we consumed all tokens (except EOF)
	if !p.isAtEnd() {
		current := p.current()
		return nil, &ParseError{
			Position:   current.Position,
			Token:      current.Type,
			TokenValue: current.Value,
			Expected:   "end of expression",
			Context:    "unexpected tokens remain after parsing complete expression",
		}
	}

	return ast, nil
}

// parseExpression is the entry point for expression parsing.
// It delegates to parseOrExpression since OR has the lowest precedence.
func (p *ConditionParser) parseExpression() (ConditionNode, error) {
	return p.parseOrExpression()
}

// parseOrExpression handles OR operators (lowest precedence).
// Grammar: or_expr := and_expr ( "OR" and_expr )*
// This implements left-associativity: "a or b or c" becomes "(a or b) or c".
func (p *ConditionParser) parseOrExpression() (ConditionNode, error) {
	// Parse left operand (AND has higher precedence)
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	// While we see OR tokens, continue building the chain
	for p.peek().Type == TokenOR {
		orToken := p.consume() // consume the OR token

		// Parse right operand
		right, err := p.parseAndExpression()
		if err != nil {
			// Check if we hit end of expression (missing right operand)
			if p.peek().Type == TokenEOF {
				return nil, &ParseError{
					Position:   orToken.Position,
					Token:      TokenOR,
					TokenValue: orToken.Value,
					Expected:   "expression after OR operator",
					Context:    "OR operator missing right operand",
				}
			}
			return nil, fmt.Errorf("expected expression after OR at position %d: %w",
				orToken.Position, err)
		}

		// Build left-associative tree: replace left with (left OR right)
		left = &BinaryOpNode{
			Operator: OpOR,
			Left:     left,
			Right:    right,
		}
	}

	return left, nil
}

// parseAndExpression handles AND operators (middle precedence).
// Grammar: and_expr := not_expr ( "AND" not_expr )*
// This implements left-associativity: "a and b and c" becomes "(a and b) and c".
func (p *ConditionParser) parseAndExpression() (ConditionNode, error) {
	// Parse left operand (NOT has higher precedence)
	left, err := p.parseNotExpression()
	if err != nil {
		return nil, err
	}

	// While we see AND tokens, continue building the chain
	for p.peek().Type == TokenAND {
		andToken := p.consume() // consume the AND token

		// Parse right operand
		right, err := p.parseNotExpression()
		if err != nil {
			// Check if we hit end of expression (missing right operand)
			if p.peek().Type == TokenEOF {
				return nil, &ParseError{
					Position:   andToken.Position,
					Token:      TokenAND,
					TokenValue: andToken.Value,
					Expected:   "expression after AND operator",
					Context:    "AND operator missing right operand",
				}
			}
			return nil, fmt.Errorf("expected expression after AND at position %d: %w",
				andToken.Position, err)
		}

		// Build left-associative tree: replace left with (left AND right)
		left = &BinaryOpNode{
			Operator: OpAND,
			Left:     left,
			Right:    right,
		}
	}

	return left, nil
}

// parseNotExpression handles NOT operators (highest precedence unary prefix).
// Grammar: not_expr := "NOT" not_expr | primary_expr
// This allows nested NOTs: "not not a" parses as NOT(NOT(a)).
func (p *ConditionParser) parseNotExpression() (ConditionNode, error) {
	// Check if we have a NOT token
	if p.peek().Type == TokenNOT {
		notToken := p.consume() // consume the NOT token

		// Recursively parse the operand (allows "not not a")
		child, err := p.parseNotExpression()
		if err != nil {
			// Check if we hit end of expression (missing operand)
			if p.peek().Type == TokenEOF {
				return nil, &ParseError{
					Position:   notToken.Position,
					Token:      TokenNOT,
					TokenValue: notToken.Value,
					Expected:   "expression after NOT operator",
					Context:    "NOT operator missing operand",
				}
			}
			return nil, fmt.Errorf("expected expression after NOT at position %d: %w",
				notToken.Position, err)
		}

		return &NotNode{Child: child}, nil
	}

	// No NOT, parse primary expression
	return p.parsePrimaryExpression()
}

// parsePrimaryExpression handles the highest precedence elements:
// - Parenthesized expressions: "(" expression ")"
// - Identifiers: "selection", "filter1", etc.
// - Aggregations: "all of them", "1 of selection_*", etc.
//
// Grammar: primary_expr := "(" expression ")" | IDENTIFIER | aggregation
//
// Note: This method requires availableIdentifiers to be set in the parser for
// aggregation support. Call ParseWithContext() instead of Parse() when using aggregations.
func (p *ConditionParser) parsePrimaryExpression() (ConditionNode, error) {
	current := p.peek()

	switch current.Type {
	case TokenLPAREN:
		// Consume the opening parenthesis
		p.consume()

		// Parse the inner expression (start from lowest precedence)
		expr, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("invalid expression inside parentheses starting at position %d: %w",
				current.Position, err)
		}

		// Expect closing parenthesis
		closeToken := p.peek()
		if err := p.expect(TokenRPAREN); err != nil {
			return nil, &ParseError{
				Position:   closeToken.Position,
				Token:      closeToken.Type,
				TokenValue: closeToken.Value,
				Expected:   "closing parenthesis ')'",
				Context:    fmt.Sprintf("unmatched opening parenthesis at position %d", current.Position),
			}
		}

		return expr, nil

	case TokenIDENTIFIER:
		// Consume the identifier token
		identToken := p.consume()

		return &IdentifierNode{Name: identToken.Value}, nil

	case TokenALL, TokenANY, TokenONE, TokenNUMBER:
		// Check if this is an aggregation by looking ahead for "OF"
		nextToken := p.peekAhead(1)
		if nextToken.Type == TokenOF {
			// This is an aggregation expression
			if len(p.availableIdentifiers) == 0 {
				return nil, fmt.Errorf("aggregation expression at position %d requires available identifiers context (use ParseWithContext)",
					current.Position)
			}
			return p.parseAggregation(p.availableIdentifiers)
		}

		// Not followed by OF, this is an error
		return nil, fmt.Errorf("unexpected %s at position %d (did you mean '%s of <pattern>'?)",
			current.Type, current.Position, strings.ToLower(current.Value))

	case TokenEOF:
		return nil, &ParseError{
			Position:   current.Position,
			Token:      TokenEOF,
			TokenValue: "",
			Expected:   "identifier or expression",
			Context:    "unexpected end of expression",
		}

	case TokenRPAREN:
		return nil, &ParseError{
			Position:   current.Position,
			Token:      TokenRPAREN,
			TokenValue: current.Value,
			Expected:   "identifier or expression",
			Context:    "unmatched closing parenthesis (no matching opening parenthesis)",
		}

	case TokenAND:
		return nil, &ParseError{
			Position:   current.Position,
			Token:      TokenAND,
			TokenValue: current.Value,
			Expected:   "identifier or expression",
			Context:    "AND operator missing left operand",
		}

	case TokenOR:
		return nil, &ParseError{
			Position:   current.Position,
			Token:      TokenOR,
			TokenValue: current.Value,
			Expected:   "identifier or expression",
			Context:    "OR operator missing left operand",
		}

	case TokenNOT:
		// This should never happen as parseNotExpression handles NOT
		return nil, fmt.Errorf("internal parser error: NOT token not handled at position %d",
			current.Position)

	case TokenOF:
		return nil, fmt.Errorf("unexpected OF keyword at position %d (missing quantifier before OF)",
			current.Position)

	case TokenTHEM:
		return nil, fmt.Errorf("unexpected THEM keyword at position %d (did you mean 'all of them'?)",
			current.Position)

	default:
		return nil, fmt.Errorf("unexpected token %s at position %d (expected identifier or parenthesized expression)",
			current.Type, current.Position)
	}
}

// Helper methods for parser navigation and token management

// peek returns the current token without consuming it.
// Returns an EOF token if we're at the end.
func (p *ConditionParser) peek() Token {
	if p.position >= len(p.tokens) {
		// Return EOF token if we're past the end
		if len(p.tokens) > 0 {
			return p.tokens[len(p.tokens)-1] // Should be EOF
		}
		return Token{Type: TokenEOF, Value: "", Position: 0}
	}
	return p.tokens[p.position]
}

// consume advances to the next token and returns the current one.
// Returns an EOF token if we're already at the end.
func (p *ConditionParser) consume() Token {
	if p.position >= len(p.tokens) {
		// Already at end, return EOF
		if len(p.tokens) > 0 {
			return p.tokens[len(p.tokens)-1]
		}
		return Token{Type: TokenEOF, Value: "", Position: 0}
	}

	token := p.tokens[p.position]
	p.position++
	return token
}

// expect checks that the current token matches the expected type and consumes it.
// Returns an error if the token type doesn't match.
func (p *ConditionParser) expect(expectedType TokenType) error {
	current := p.peek()

	if current.Type != expectedType {
		return fmt.Errorf("expected %s but got %s at position %d",
			expectedType, current.Type, current.Position)
	}

	p.consume()
	return nil
}

// isAtEnd returns true if we've consumed all tokens (current token is EOF).
func (p *ConditionParser) isAtEnd() bool {
	return p.peek().Type == TokenEOF
}

// current returns the current token without consuming it (alias for peek).
// Provided for readability in some contexts.
func (p *ConditionParser) current() Token {
	return p.peek()
}

// peekAhead returns the token at position (current + offset) without consuming any tokens.
// Returns an EOF token if the offset goes past the end of the token stream.
// This is useful for lookahead parsing decisions.
//
// Example:
//   - peekAhead(0) is equivalent to peek() (current token)
//   - peekAhead(1) returns the next token
//   - peekAhead(2) returns the token after next
func (p *ConditionParser) peekAhead(offset int) Token {
	targetPosition := p.position + offset

	if targetPosition >= len(p.tokens) || targetPosition < 0 {
		// Out of bounds, return EOF
		if len(p.tokens) > 0 {
			return p.tokens[len(p.tokens)-1] // Should be EOF
		}
		return Token{Type: TokenEOF, Value: "", Position: 0}
	}

	return p.tokens[targetPosition]
}

// quantifierResult holds the result of parsing an aggregation quantifier
type quantifierResult struct {
	aggType AggregationType
	count   int
}

// parseQuantifier parses the quantifier part of an aggregation expression.
// TASK 148.3: Extracted from parseAggregation to reduce cyclomatic complexity.
//
// Supported quantifiers:
//   - ALL: matches all identifiers (AggAll type)
//   - ANY: matches at least one identifier (AggAny type, count=1)
//   - ONE: matches exactly one identifier (AggCount type, count=1)
//   - NUMBER: matches at least N identifiers (AggCount type, count=N)
//
// Returns:
//   - quantifierResult: the parsed quantifier type and count
//   - error: if the quantifier is invalid or missing
func (p *ConditionParser) parseQuantifier() (quantifierResult, error) {
	startToken := p.peek()

	switch startToken.Type {
	case TokenALL:
		p.consume()
		return quantifierResult{aggType: AggAll, count: 0}, nil

	case TokenANY:
		p.consume()
		return quantifierResult{aggType: AggAny, count: 1}, nil

	case TokenONE:
		p.consume()
		return quantifierResult{aggType: AggCount, count: 1}, nil

	case TokenNUMBER:
		numToken := p.consume()
		parsedNum, err := ParseNumber(numToken)
		if err != nil {
			return quantifierResult{}, fmt.Errorf("invalid numeric quantifier in aggregation at position %d: %w",
				numToken.Position, err)
		}
		if parsedNum < 0 {
			return quantifierResult{}, fmt.Errorf("aggregation quantifier cannot be negative at position %d: got %d",
				numToken.Position, parsedNum)
		}
		if parsedNum == 0 {
			return quantifierResult{}, fmt.Errorf("aggregation quantifier cannot be zero at position %d",
				numToken.Position)
		}
		return quantifierResult{aggType: AggCount, count: parsedNum}, nil

	default:
		return quantifierResult{}, fmt.Errorf("expected aggregation quantifier (ALL, ANY, ONE, or NUMBER) at position %d, got %s",
			startToken.Position, startToken.Type)
	}
}

// targetResult holds the result of parsing an aggregation target
type targetResult struct {
	pattern            string
	matchedIdentifiers []string
	targetPosition     int
}

// parseAggregationTarget parses the target part of an aggregation expression.
// TASK 148.3: Extracted from parseAggregation to reduce cyclomatic complexity.
//
// Supported targets:
//   - THEM: matches all available identifiers
//   - IDENTIFIER: matches identifiers by pattern (supports wildcards)
//
// Parameters:
//   - availableIdentifiers: slice of detection block names to match against
//   - ofPosition: position of OF keyword for error reporting
//
// Returns:
//   - targetResult: the parsed pattern and matched identifiers
//   - error: if the target is invalid or missing
func (p *ConditionParser) parseAggregationTarget(availableIdentifiers []string, ofPosition int) (targetResult, error) {
	targetToken := p.peek()

	switch targetToken.Type {
	case TokenTHEM:
		p.consume()
		return targetResult{
			pattern:            "them",
			matchedIdentifiers: getMatchingIdentifiers("them", availableIdentifiers),
			targetPosition:     targetToken.Position,
		}, nil

	case TokenIDENTIFIER:
		pattern := targetToken.Value
		p.consume()
		return targetResult{
			pattern:            pattern,
			matchedIdentifiers: getMatchingIdentifiers(pattern, availableIdentifiers),
			targetPosition:     targetToken.Position,
		}, nil

	case TokenEOF:
		return targetResult{}, fmt.Errorf("unexpected end of expression after OF keyword at position %d (expected THEM or pattern)",
			ofPosition)

	default:
		return targetResult{}, fmt.Errorf("expected THEM or identifier pattern after OF at position %d, got %s",
			targetToken.Position, targetToken.Type)
	}
}

// parseAggregation parses aggregation expressions like "all of them", "1 of selection_*", etc.
// It expects the current token to be the quantifier (ALL, ANY, ONE, or NUMBER).
//
// Grammar: aggregation := (ALL | ANY | ONE | NUMBER) "OF" (THEM | pattern)
//
// The function:
//  1. Parses the quantifier (all/any/one/number) via parseQuantifier
//  2. Expects and consumes the "OF" keyword
//  3. Parses the target (them or wildcard pattern) via parseAggregationTarget
//  4. Validates the aggregation and returns an AggregationNode
//
// Security considerations:
//   - Pattern matching is bounded to prevent ReDoS attacks
//   - All errors include position information for debugging
//   - Empty identifier lists are rejected with descriptive errors
//
// Parameters:
//   - availableIdentifiers: slice of all detection block names available in the SIGMA rule
//
// Returns:
//   - *AggregationNode: the parsed aggregation node
//   - error: detailed error with position information if parsing fails
func (p *ConditionParser) parseAggregation(availableIdentifiers []string) (*AggregationNode, error) {
	startToken := p.peek()

	// Step 1: Parse the quantifier
	qr, err := p.parseQuantifier()
	if err != nil {
		return nil, err
	}

	// Step 2: Expect the "OF" keyword
	ofToken := p.peek()
	if ofToken.Type != TokenOF {
		return nil, fmt.Errorf("expected OF keyword after aggregation quantifier at position %d, got %s",
			ofToken.Position, ofToken.Type)
	}
	p.consume()

	// Step 3: Parse the target (THEM or pattern)
	tr, err := p.parseAggregationTarget(availableIdentifiers, ofToken.Position)
	if err != nil {
		return nil, err
	}

	// Step 4: Validate that pattern matched at least one identifier
	if len(tr.matchedIdentifiers) == 0 {
		return nil, &AggregationError{
			Pattern:              tr.pattern,
			Position:             tr.targetPosition,
			Reason:               "matched no identifiers",
			RequiredCount:        qr.count,
			ActualCount:          0,
			AvailableIdentifiers: availableIdentifiers,
		}
	}

	// Step 5: Validate count doesn't exceed matched identifiers for COUNT type
	if qr.aggType == AggCount && qr.count > len(tr.matchedIdentifiers) {
		return nil, &AggregationError{
			Pattern:              tr.pattern,
			Position:             startToken.Position,
			Reason:               "insufficient matches",
			RequiredCount:        qr.count,
			ActualCount:          len(tr.matchedIdentifiers),
			AvailableIdentifiers: availableIdentifiers,
		}
	}

	// Build and return the aggregation node
	return &AggregationNode{
		Type:        qr.aggType,
		Pattern:     tr.pattern,
		Identifiers: tr.matchedIdentifiers,
		Count:       qr.count,
	}, nil
}

// getMatchingIdentifiers resolves a pattern to a list of matching identifiers.
// It supports three types of patterns:
//
//  1. "them" - matches all available identifiers
//  2. Wildcard patterns - containing '*' character(s) for glob-style matching
//  3. Exact match - literal identifier name without wildcards
//
// Wildcard matching examples:
//   - "selection_*" matches "selection_windows", "selection_linux", "selection_1"
//   - "*_process" matches "create_process", "inject_process"
//   - "*windows*" matches "selection_windows", "filter_windows_registry"
//   - "exact_name" matches only "exact_name" (no wildcards)
//
// Security considerations:
//   - Wildcard matching uses simple string operations, not regex, to prevent ReDoS
//   - Pattern complexity is O(n*m) where n=len(availableIdentifiers), m=len(pattern)
//   - No backtracking or exponential-time algorithms
//
// Parameters:
//   - pattern: the pattern to match (e.g., "them", "selection_*", "exact_name")
//   - availableIdentifiers: slice of all detection block names to match against
//
// Returns:
//   - []string: slice of identifiers that match the pattern (may be empty)
func getMatchingIdentifiers(pattern string, availableIdentifiers []string) []string {
	// Special case: "them" matches all identifiers
	if strings.ToLower(pattern) == "them" {
		return availableIdentifiers
	}

	// Check if pattern contains wildcards
	if !strings.Contains(pattern, "*") {
		// Exact match - no wildcards
		for _, identifier := range availableIdentifiers {
			if identifier == pattern {
				return []string{identifier}
			}
		}
		return []string{} // No exact match found
	}

	// Wildcard matching - split pattern by '*' to get segments
	// Example: "selection_*_windows" -> ["selection_", "_windows"]
	segments := strings.Split(pattern, "*")

	var matches []string
	for _, identifier := range availableIdentifiers {
		if matchesWildcardPattern(identifier, segments) {
			matches = append(matches, identifier)
		}
	}

	return matches
}

// matchesWildcardPattern checks if an identifier matches a wildcard pattern.
// The pattern is represented as segments between wildcards.
//
// Algorithm:
//  1. First segment must be a prefix (or empty if pattern starts with *)
//  2. Last segment must be a suffix (or empty if pattern ends with *)
//  3. Middle segments must appear in order
//
// Examples:
//
//   - Pattern "sel*" -> segments ["sel", ""]
//     Matches: "selection", "sel_windows"
//     No match: "filter_sel"
//
//   - Pattern "*_windows" -> segments ["", "_windows"]
//     Matches: "selection_windows", "filter_windows"
//     No match: "windows_registry"
//
//   - Pattern "sel*win*reg" -> segments ["sel", "win", "reg"]
//     Matches: "selection_windows_registry"
//     No match: "sel_reg_win" (wrong order)
//
// Security: Uses simple string operations with bounded complexity O(n*m).
func matchesWildcardPattern(identifier string, segments []string) bool {
	if len(segments) == 0 {
		return false // Invalid pattern
	}

	// Single segment means no wildcards (should not happen here, but handle it)
	if len(segments) == 1 {
		return identifier == segments[0]
	}

	position := 0

	// Check each segment in order
	for i, segment := range segments {
		if segment == "" {
			// Empty segment means wildcard at start/end or consecutive wildcards
			continue
		}

		if i == 0 {
			// First segment: must be a prefix
			if !strings.HasPrefix(identifier, segment) {
				return false
			}
			position = len(segment)

		} else if i == len(segments)-1 {
			// Last segment: must be a suffix
			if !strings.HasSuffix(identifier, segment) {
				return false
			}
			// Also verify it appears after the current position
			lastIndex := strings.LastIndex(identifier, segment)
			if lastIndex < position {
				return false
			}

		} else {
			// Middle segment: must appear somewhere after current position
			index := strings.Index(identifier[position:], segment)
			if index == -1 {
				return false
			}
			position += index + len(segment)
		}
	}

	return true
}
