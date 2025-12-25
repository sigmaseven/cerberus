package search

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TokenType represents the type of token
type TokenType int

const (
	TokenField TokenType = iota
	TokenOperator
	TokenValue
	TokenLogic
	TokenLParen
	TokenRParen
	TokenComma
	TokenEOF
)

// Token represents a lexical token
type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

// NodeType represents AST node types
type NodeType int

const (
	NodeCondition NodeType = iota
	NodeLogical
	NodeGroup
)

// ASTNode represents a node in the abstract syntax tree
type ASTNode struct {
	Type     NodeType
	Field    string
	Operator string
	Value    interface{}
	Logic    string // AND, OR, NOT
	Left     *ASTNode
	Right    *ASTNode
	Children []*ASTNode
}

// Parser parses CQL queries
type Parser struct {
	input   string
	tokens  []Token
	current int
}

// NewParser creates a new parser
func NewParser(query string) *Parser {
	return &Parser{
		input:   strings.TrimSpace(query),
		current: 0,
	}
}

// Parse parses the query and returns an AST
func (p *Parser) Parse() (*ASTNode, error) {
	// Tokenize
	if err := p.tokenize(); err != nil {
		return nil, err
	}

	// Parse tokens into AST
	ast, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	return ast, nil
}

// tokenize breaks the input into tokens
func (p *Parser) tokenize() error {
	input := p.input
	pos := 0

	for pos < len(input) {
		// Skip whitespace
		if input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\n' {
			pos++
			continue
		}

		// Parentheses
		if input[pos] == '(' {
			p.tokens = append(p.tokens, Token{Type: TokenLParen, Value: "(", Pos: pos})
			pos++
			continue
		}
		if input[pos] == ')' {
			p.tokens = append(p.tokens, Token{Type: TokenRParen, Value: ")", Pos: pos})
			pos++
			continue
		}

		// Comma
		if input[pos] == ',' {
			p.tokens = append(p.tokens, Token{Type: TokenComma, Value: ",", Pos: pos})
			pos++
			continue
		}

		// Operators (must check BEFORE logical operators to handle "not exists", "not in")
		// Use lowercase for comparison, but check case-insensitively for text operators
		operators := []string{
			"not_equals", "not in", "not exists",
			"equals", "contains", "startswith", "endswith", "matches",
			"exists", "in",
			">=", "<=", "!=", "~=",
			"gte", "lte", "gt", "lt",
			"=", ">", "<",
		}

		matched := false
		inputLower := strings.ToLower(input[pos:])
		for _, op := range operators {
			if strings.HasPrefix(inputLower, op) && (pos+len(op) >= len(input) || !isAlphaNum(input[pos+len(op)])) {
				// Store operator in lowercase (normalized form)
				p.tokens = append(p.tokens, Token{Type: TokenOperator, Value: op, Pos: pos})
				pos += len(op)
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// Logical operators (case-insensitive) - checked AFTER compound operators like "not exists"
		upperInput := strings.ToUpper(input[pos:])
		if strings.HasPrefix(upperInput, "AND") && (pos+3 >= len(input) || !isAlphaNum(input[pos+3])) {
			p.tokens = append(p.tokens, Token{Type: TokenLogic, Value: "AND", Pos: pos})
			pos += 3
			continue
		}
		if strings.HasPrefix(upperInput, "OR") && (pos+2 >= len(input) || !isAlphaNum(input[pos+2])) {
			p.tokens = append(p.tokens, Token{Type: TokenLogic, Value: "OR", Pos: pos})
			pos += 2
			continue
		}
		if strings.HasPrefix(upperInput, "NOT") && (pos+3 >= len(input) || !isAlphaNum(input[pos+3])) {
			p.tokens = append(p.tokens, Token{Type: TokenLogic, Value: "NOT", Pos: pos})
			pos += 3
			continue
		}
		if strings.HasPrefix(input[pos:], "&&") {
			p.tokens = append(p.tokens, Token{Type: TokenLogic, Value: "AND", Pos: pos})
			pos += 2
			continue
		}
		if strings.HasPrefix(input[pos:], "||") {
			p.tokens = append(p.tokens, Token{Type: TokenLogic, Value: "OR", Pos: pos})
			pos += 2
			continue
		}

		// Quoted strings
		if input[pos] == '"' {
			start := pos + 1
			pos++
			for pos < len(input) && input[pos] != '"' {
				if input[pos] == '\\' && pos+1 < len(input) {
					pos++ // Skip escaped character
				}
				pos++
			}
			if pos >= len(input) {
				return fmt.Errorf("unterminated string at position %d", start-1)
			}
			value := input[start:pos]
			// Unescape string
			value = strings.ReplaceAll(value, `\"`, `"`)
			value = strings.ReplaceAll(value, `\\`, `\`)
			p.tokens = append(p.tokens, Token{Type: TokenValue, Value: value, Pos: start - 1})
			pos++ // Skip closing quote
			continue
		}

		// Arrays [value1, value2, ...]
		if input[pos] == '[' {
			start := pos
			pos++
			depth := 1
			for pos < len(input) && depth > 0 {
				if input[pos] == '[' {
					depth++
				} else if input[pos] == ']' {
					depth--
				}
				pos++
			}
			if depth > 0 {
				return fmt.Errorf("unterminated array at position %d", start)
			}
			value := input[start:pos]
			p.tokens = append(p.tokens, Token{Type: TokenValue, Value: value, Pos: start})
			continue
		}

		// Field names or unquoted values
		start := pos
		for pos < len(input) && (isAlphaNum(input[pos]) || input[pos] == '.' || input[pos] == '_' || input[pos] == '@') {
			pos++
		}
		if pos > start {
			value := input[start:pos]

			// Check if this looks like a field (contains . or @ prefix, or is followed by operator)
			// Otherwise treat as unquoted value
			tokenType := TokenField
			if p.isNextTokenOperator(pos, input) || strings.HasPrefix(value, "@") || strings.Contains(value, ".") {
				tokenType = TokenField
			} else {
				// Could be a number or boolean
				tokenType = TokenValue
			}

			p.tokens = append(p.tokens, Token{Type: tokenType, Value: value, Pos: start})
			continue
		}

		return fmt.Errorf("unexpected character '%c' at position %d", input[pos], pos)
	}

	p.tokens = append(p.tokens, Token{Type: TokenEOF, Value: "", Pos: len(input)})
	return nil
}

// Helper to check if next non-whitespace token would be an operator
func (p *Parser) isNextTokenOperator(pos int, input string) bool {
	// Skip whitespace
	for pos < len(input) && (input[pos] == ' ' || input[pos] == '\t') {
		pos++
	}
	if pos >= len(input) {
		return false
	}

	operators := []string{"=", "!=", ">", "<", ">=", "<=", "~=", "equals", "not_equals",
		"contains", "startswith", "endswith", "matches", "in", "not in", "exists", "not exists",
		"gt", "lt", "gte", "lte"}

	// Check case-insensitively for text operators
	inputLower := strings.ToLower(input[pos:])
	for _, op := range operators {
		if strings.HasPrefix(inputLower, op) {
			return true
		}
	}
	return false
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// parseExpression parses a complete expression
func (p *Parser) parseExpression() (*ASTNode, error) {
	return p.parseOrExpression()
}

// parseOrExpression handles OR logic
func (p *Parser) parseOrExpression() (*ASTNode, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.matchLogic("OR") {
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &ASTNode{
			Type:  NodeLogical,
			Logic: "OR",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

// parseAndExpression handles AND logic
func (p *Parser) parseAndExpression() (*ASTNode, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for p.matchLogic("AND") {
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		left = &ASTNode{
			Type:  NodeLogical,
			Logic: "AND",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

// parsePrimary parses primary expressions (conditions or groups)
func (p *Parser) parsePrimary() (*ASTNode, error) {
	// Handle parentheses
	if p.match(TokenLParen) {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.match(TokenRParen) {
			return nil, fmt.Errorf("expected closing parenthesis at position %d", p.peek().Pos)
		}
		return &ASTNode{
			Type:     NodeGroup,
			Children: []*ASTNode{expr},
		}, nil
	}

	// Handle NOT
	if p.matchLogic("NOT") {
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &ASTNode{
			Type:  NodeLogical,
			Logic: "NOT",
			Left:  expr,
		}, nil
	}

	// Handle condition
	return p.parseCondition()
}

// parseCondition parses a single condition
func (p *Parser) parseCondition() (*ASTNode, error) {
	if !p.match(TokenField) {
		return nil, fmt.Errorf("expected field name at position %d", p.peek().Pos)
	}
	field := p.previous().Value

	if !p.match(TokenOperator) {
		return nil, fmt.Errorf("expected operator at position %d", p.peek().Pos)
	}
	operator := p.previous().Value

	// exists and not exists don't need a value
	if operator == "exists" || operator == "not exists" {
		return &ASTNode{
			Type:     NodeCondition,
			Field:    field,
			Operator: operator,
			Value:    nil,
		}, nil
	}

	if !p.match(TokenValue) {
		return nil, fmt.Errorf("expected value at position %d", p.peek().Pos)
	}
	value := p.previous().Value

	// Parse value type
	parsedValue, err := p.parseValue(value, operator)
	if err != nil {
		return nil, err
	}

	return &ASTNode{
		Type:     NodeCondition,
		Field:    field,
		Operator: operator,
		Value:    parsedValue,
	}, nil
}

// parseValue parses and converts value to appropriate type
func (p *Parser) parseValue(value string, operator string) (interface{}, error) {
	// Array values
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		arrayContent := strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
		if arrayContent == "" {
			return []interface{}{}, nil
		}

		// Split by comma, handling quoted strings
		var items []interface{}
		current := ""
		inQuotes := false

		for _, c := range arrayContent {
			if c == '"' {
				inQuotes = !inQuotes
			} else if c == ',' && !inQuotes {
				items = append(items, strings.TrimSpace(strings.Trim(current, `"`)))
				current = ""
				continue
			}
			current += string(c)
		}
		if current != "" {
			items = append(items, strings.TrimSpace(strings.Trim(current, `"`)))
		}

		return items, nil
	}

	// Try to parse as number
	if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
		return intVal, nil
	}
	if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
		return floatVal, nil
	}

	// Boolean
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}

	// Time range parsing for @timestamp
	if strings.HasPrefix(value, "last ") {
		duration, err := parseTimeDuration(strings.TrimPrefix(value, "last "))
		if err != nil {
			return nil, err
		}
		return time.Now().Add(-duration), nil
	}

	// Default to string
	return value, nil
}

// parseTimeDuration parses time duration strings like "24h", "7d", "30d"
func parseTimeDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}

	numStr := s[:len(s)-1]
	unit := s[len(s)-1:]

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration number: %s", numStr)
	}

	switch unit {
	case "s":
		return time.Duration(num) * time.Second, nil
	case "m":
		return time.Duration(num) * time.Minute, nil
	case "h":
		return time.Duration(num) * time.Hour, nil
	case "d":
		return time.Duration(num) * 24 * time.Hour, nil
	case "w":
		return time.Duration(num) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration unit: %s", unit)
	}
}

// Helper methods
func (p *Parser) match(types ...TokenType) bool {
	for _, t := range types {
		if p.check(t) {
			p.advance()
			return true
		}
	}
	return false
}

func (p *Parser) matchLogic(values ...string) bool {
	if p.check(TokenLogic) {
		for _, v := range values {
			if p.peek().Value == v {
				p.advance()
				return true
			}
		}
	}
	return false
}

func (p *Parser) check(t TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == t
}

func (p *Parser) advance() Token {
	if !p.isAtEnd() {
		p.current++
	}
	return p.previous()
}

func (p *Parser) isAtEnd() bool {
	return p.current >= len(p.tokens) || p.peek().Type == TokenEOF
}

func (p *Parser) peek() Token {
	if p.current >= len(p.tokens) {
		return Token{Type: TokenEOF, Value: "", Pos: len(p.input)}
	}
	return p.tokens[p.current]
}

func (p *Parser) previous() Token {
	return p.tokens[p.current-1]
}

// Validate performs semantic validation on the AST
func (ast *ASTNode) Validate() error {
	if ast == nil {
		return nil
	}

	switch ast.Type {
	case NodeCondition:
		// Validate field name exists
		if ast.Field == "" {
			return fmt.Errorf("empty field name")
		}
		// Validate operator
		validOperators := map[string]bool{
			"=": true, "equals": true, "!=": true, "not_equals": true,
			">": true, "gt": true, "<": true, "lt": true,
			">=": true, "gte": true, "<=": true, "lte": true,
			"contains": true, "startswith": true, "endswith": true,
			"matches": true, "~=": true,
			"in": true, "not in": true,
			"exists": true, "not exists": true,
		}
		if !validOperators[ast.Operator] {
			return fmt.Errorf("invalid operator: %s", ast.Operator)
		}
		// exists and not exists don't need a value
		if ast.Operator != "exists" && ast.Operator != "not exists" && ast.Value == nil {
			return fmt.Errorf("missing value for operator %s", ast.Operator)
		}

	case NodeLogical:
		if ast.Logic != "AND" && ast.Logic != "OR" && ast.Logic != "NOT" {
			return fmt.Errorf("invalid logical operator: %s", ast.Logic)
		}
		if err := ast.Left.Validate(); err != nil {
			return err
		}
		if ast.Logic != "NOT" && ast.Right != nil {
			if err := ast.Right.Validate(); err != nil {
				return err
			}
		}

	case NodeGroup:
		for _, child := range ast.Children {
			if err := child.Validate(); err != nil {
				return err
			}
		}
	}

	return nil
}
