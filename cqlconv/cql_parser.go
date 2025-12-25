package cqlconv

import (
	"fmt"
	"regexp"
	"strings"
)

// TokenType represents the type of a CQL token
type TokenType int

const (
	// Token types for CQL lexer
	TOKEN_SELECT TokenType = iota
	TOKEN_FROM
	TOKEN_WHERE
	TOKEN_AND
	TOKEN_OR
	TOKEN_LIKE
	TOKEN_IN
	TOKEN_NOT
	TOKEN_GROUP_BY
	TOKEN_HAVING
	TOKEN_COUNT
	TOKEN_SUM
	TOKEN_AVG
	TOKEN_MIN
	TOKEN_MAX
	TOKEN_DISTINCT
	TOKEN_IDENTIFIER
	TOKEN_STRING
	TOKEN_NUMBER
	TOKEN_OPERATOR // =, >, <, >=, <=, !=
	TOKEN_LPAREN
	TOKEN_RPAREN
	TOKEN_COMMA
	TOKEN_ASTERISK
	TOKEN_NULL
	TOKEN_IS
	TOKEN_EOF
	TOKEN_ERROR
)

// Token represents a lexical token in CQL
type Token struct {
	Type    TokenType
	Literal string
	Pos     int
}

// Lexer tokenizes CQL query strings
type Lexer struct {
	input        string
	position     int
	readPosition int
	ch           byte
}

// NewLexer creates a new CQL lexer
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

// readChar advances to the next character
func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0 // EOF
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition++
}

// peekChar looks ahead without advancing
func (l *Lexer) peekChar() byte {
	if l.readPosition >= len(l.input) {
		return 0
	}
	return l.input[l.readPosition]
}

// skipWhitespace advances past whitespace characters
func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

// readIdentifier reads an identifier or keyword
func (l *Lexer) readIdentifier() string {
	start := l.position
	for isLetter(l.ch) || isDigit(l.ch) || l.ch == '_' {
		l.readChar()
	}
	return l.input[start:l.position]
}

// readNumber reads a numeric literal
func (l *Lexer) readNumber() string {
	start := l.position
	for isDigit(l.ch) || l.ch == '.' {
		l.readChar()
	}
	return l.input[start:l.position]
}

// readString reads a string literal (single or double quoted)
func (l *Lexer) readString(quote byte) string {
	l.readChar() // skip opening quote
	start := l.position
	for l.ch != quote && l.ch != 0 {
		if l.ch == '\\' {
			l.readChar() // skip escape character
		}
		l.readChar()
	}
	str := l.input[start:l.position]
	l.readChar() // skip closing quote
	return str
}

// NextToken returns the next token from the input
// PRODUCTION: CCN <= 10 (operator logic extracted to readOperator)
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	tok := Token{Pos: l.position}

	switch l.ch {
	case '(':
		tok.Type = TOKEN_LPAREN
		tok.Literal = string(l.ch)
	case ')':
		tok.Type = TOKEN_RPAREN
		tok.Literal = string(l.ch)
	case ',':
		tok.Type = TOKEN_COMMA
		tok.Literal = string(l.ch)
	case '*':
		tok.Type = TOKEN_ASTERISK
		tok.Literal = string(l.ch)
	case '=', '!', '>', '<':
		// Delegate operator parsing to dedicated method
		return l.readOperator()
	case '\'', '"':
		tok.Type = TOKEN_STRING
		tok.Literal = l.readString(l.ch)
		return tok
	case 0:
		tok.Type = TOKEN_EOF
		tok.Literal = ""
		return tok
	default:
		if isLetter(l.ch) {
			literal := l.readIdentifier()
			tok.Type = lookupKeyword(literal)
			tok.Literal = literal
			return tok
		} else if isDigit(l.ch) {
			tok.Type = TOKEN_NUMBER
			tok.Literal = l.readNumber()
			return tok
		} else {
			tok.Type = TOKEN_ERROR
			tok.Literal = string(l.ch)
		}
	}

	l.readChar()
	return tok
}

// readOperator reads comparison operators (=, !=, >, >=, <, <=)
// PRODUCTION: Extracted from NextToken to reduce cyclomatic complexity
func (l *Lexer) readOperator() Token {
	tok := Token{Pos: l.position, Type: TOKEN_OPERATOR}

	switch l.ch {
	case '=':
		tok.Literal = "="
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Literal = "!="
		} else {
			tok.Type = TOKEN_ERROR
			tok.Literal = string(l.ch)
		}
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Literal = ">="
		} else {
			tok.Literal = ">"
		}
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			tok.Literal = "<="
		} else {
			tok.Literal = "<"
		}
	}

	l.readChar()
	return tok
}

// lookupKeyword maps identifiers to keywords
func lookupKeyword(ident string) TokenType {
	keywords := map[string]TokenType{
		"SELECT":   TOKEN_SELECT,
		"FROM":     TOKEN_FROM,
		"WHERE":    TOKEN_WHERE,
		"AND":      TOKEN_AND,
		"OR":       TOKEN_OR,
		"LIKE":     TOKEN_LIKE,
		"IN":       TOKEN_IN,
		"NOT":      TOKEN_NOT,
		"GROUP":    TOKEN_GROUP_BY,
		"BY":       TOKEN_GROUP_BY,
		"HAVING":   TOKEN_HAVING,
		"COUNT":    TOKEN_COUNT,
		"SUM":      TOKEN_SUM,
		"AVG":      TOKEN_AVG,
		"MIN":      TOKEN_MIN,
		"MAX":      TOKEN_MAX,
		"DISTINCT": TOKEN_DISTINCT,
		"NULL":     TOKEN_NULL,
		"IS":       TOKEN_IS,
	}

	upper := strings.ToUpper(ident)
	if tok, ok := keywords[upper]; ok {
		return tok
	}
	return TOKEN_IDENTIFIER
}

// isLetter returns true if ch is a letter
func isLetter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z')
}

// isDigit returns true if ch is a digit
func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

// Parser parses CQL queries into an AST
type Parser struct {
	lexer       *Lexer
	currentToken Token
	peekToken    Token
	errors      []string
}

// NewParser creates a new CQL parser
func NewParser(input string) *Parser {
	p := &Parser{
		lexer:  NewLexer(input),
		errors: []string{},
	}
	// Read two tokens to initialize current and peek
	p.nextToken()
	p.nextToken()
	return p
}

// nextToken advances to the next token
func (p *Parser) nextToken() {
	p.currentToken = p.peekToken
	p.peekToken = p.lexer.NextToken()
}

// currentTokenIs checks if current token matches type
func (p *Parser) currentTokenIs(t TokenType) bool {
	return p.currentToken.Type == t
}

// peekTokenIs checks if peek token matches type
func (p *Parser) peekTokenIs(t TokenType) bool {
	return p.peekToken.Type == t
}

// expectPeek checks peek token and advances if match
func (p *Parser) expectPeek(t TokenType) bool {
	if p.peekTokenIs(t) {
		p.nextToken()
		return true
	}
	p.errors = append(p.errors, fmt.Sprintf("expected token %v, got %v at position %d", t, p.peekToken.Type, p.peekToken.Pos))
	return false
}

// ParseQuery parses a CQL query into a CQLQuery AST
func (p *Parser) ParseQuery() (*CQLQuery, error) {
	if !p.currentTokenIs(TOKEN_SELECT) {
		return nil, fmt.Errorf("query must start with SELECT")
	}

	query := &CQLQuery{
		Conditions: []Condition{},
	}

	// Parse SELECT
	p.nextToken()
	if p.currentTokenIs(TOKEN_ASTERISK) {
		query.Select = []string{"*"}
		p.nextToken()
	} else {
		// Parse field list
		for {
			if p.currentTokenIs(TOKEN_IDENTIFIER) {
				query.Select = append(query.Select, p.currentToken.Literal)
				p.nextToken()
				if !p.currentTokenIs(TOKEN_COMMA) {
					break
				}
				p.nextToken()
			} else {
				break
			}
		}
	}

	// Parse FROM
	if !p.currentTokenIs(TOKEN_FROM) {
		return nil, fmt.Errorf("expected FROM clause")
	}
	p.nextToken()
	if !p.currentTokenIs(TOKEN_IDENTIFIER) {
		return nil, fmt.Errorf("expected table name after FROM")
	}
	query.From = p.currentToken.Literal
	p.nextToken()

	// Parse WHERE (optional)
	if p.currentTokenIs(TOKEN_WHERE) {
		p.nextToken()
		conditions, err := p.parseWhereClause()
		if err != nil {
			return nil, err
		}
		query.Conditions = conditions
	}

	// Parse GROUP BY (optional)
	if p.currentTokenIs(TOKEN_GROUP_BY) || (p.currentToken.Literal == "GROUP" && p.peekToken.Literal == "BY") {
		p.nextToken()
		if p.currentToken.Literal == "BY" {
			p.nextToken()
		}
		query.GroupBy = p.parseFieldList()
	}

	// Parse HAVING (optional)
	if p.currentTokenIs(TOKEN_HAVING) {
		p.nextToken()
		having, err := p.parseHaving()
		if err != nil {
			return nil, err
		}
		query.Having = having
	}

	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", p.errors)
	}

	return query, nil
}

// parseWhereClause parses WHERE conditions
// PRODUCTION: Function length <= 50 lines (operator parsing extracted)
func (p *Parser) parseWhereClause() ([]Condition, error) {
	conditions := []Condition{}

	for !p.currentTokenIs(TOKEN_EOF) && !p.currentTokenIs(TOKEN_GROUP_BY) &&
	    !p.currentTokenIs(TOKEN_HAVING) && p.currentToken.Literal != "GROUP" {

		// Handle NOT prefix
		negated := false
		if p.currentTokenIs(TOKEN_NOT) {
			negated = true
			p.nextToken()
		}

		// Parse field name
		if !p.currentTokenIs(TOKEN_IDENTIFIER) {
			break
		}
		field := p.currentToken.Literal
		p.nextToken()

		// Parse operator and value
		operator, value, err := p.parseOperatorAndValue()
		if err != nil {
			return nil, err
		}

		conditions = append(conditions, Condition{
			Field:    field,
			Operator: operator,
			Value:    value,
			Negated:  negated,
		})

		// Check for AND/OR
		if p.currentTokenIs(TOKEN_AND) || p.currentTokenIs(TOKEN_OR) {
			p.nextToken()
			continue
		} else {
			break
		}
	}

	return conditions, nil
}

// parseOperatorAndValue parses the operator and its associated value
// PRODUCTION: Extracted from parseWhereClause to reduce function length
func (p *Parser) parseOperatorAndValue() (operator string, value interface{}, err error) {
	if p.currentTokenIs(TOKEN_IS) {
		return p.parseIsCondition()
	} else if p.currentTokenIs(TOKEN_LIKE) {
		return p.parseLikeCondition()
	} else if p.currentTokenIs(TOKEN_IN) {
		return p.parseInClause()
	} else if p.currentTokenIs(TOKEN_OPERATOR) {
		return p.parseComparisonOperator()
	}
	return "", nil, nil
}

// parseIsCondition parses IS [NOT] NULL conditions
func (p *Parser) parseIsCondition() (operator string, value interface{}, err error) {
	p.nextToken()
	if p.currentTokenIs(TOKEN_NOT) {
		operator = "IS NOT"
		p.nextToken()
	} else {
		operator = "IS"
	}
	if p.currentTokenIs(TOKEN_NULL) {
		value = nil
		p.nextToken()
	}
	return operator, value, nil
}

// parseLikeCondition parses LIKE 'pattern' conditions
func (p *Parser) parseLikeCondition() (operator string, value interface{}, err error) {
	operator = "LIKE"
	p.nextToken()
	if p.currentTokenIs(TOKEN_STRING) {
		value = p.currentToken.Literal
		p.nextToken()
	}
	return operator, value, nil
}

// parseInClause parses IN (value1, value2, ...) conditions
func (p *Parser) parseInClause() (operator string, value interface{}, err error) {
	operator = "IN"
	p.nextToken()

	if !p.currentTokenIs(TOKEN_LPAREN) {
		return "", nil, fmt.Errorf("expected ( after IN")
	}
	p.nextToken()

	values := []interface{}{}
	for !p.currentTokenIs(TOKEN_RPAREN) && !p.currentTokenIs(TOKEN_EOF) {
		if p.currentTokenIs(TOKEN_STRING) || p.currentTokenIs(TOKEN_NUMBER) {
			values = append(values, p.currentToken.Literal)
			p.nextToken()
		}
		if p.currentTokenIs(TOKEN_COMMA) {
			p.nextToken()
		}
	}

	if !p.currentTokenIs(TOKEN_RPAREN) {
		return "", nil, fmt.Errorf("expected ) to close IN list")
	}
	p.nextToken()

	return operator, values, nil
}

// parseComparisonOperator parses comparison operators (=, >, <, etc.)
func (p *Parser) parseComparisonOperator() (operator string, value interface{}, err error) {
	operator = p.currentToken.Literal
	p.nextToken()

	if p.currentTokenIs(TOKEN_STRING) {
		value = p.currentToken.Literal
		p.nextToken()
	} else if p.currentTokenIs(TOKEN_NUMBER) {
		value = p.currentToken.Literal
		p.nextToken()
	}

	return operator, value, nil
}

// parseFieldList parses a comma-separated list of fields
func (p *Parser) parseFieldList() []string {
	fields := []string{}
	for p.currentTokenIs(TOKEN_IDENTIFIER) {
		fields = append(fields, p.currentToken.Literal)
		p.nextToken()
		if p.currentTokenIs(TOKEN_COMMA) {
			p.nextToken()
		} else {
			break
		}
	}
	return fields
}

// parseHaving parses HAVING clause with aggregation
func (p *Parser) parseHaving() (*HavingClause, error) {
	having := &HavingClause{}

	// Expect aggregation function
	if p.currentTokenIs(TOKEN_COUNT) || p.currentTokenIs(TOKEN_SUM) ||
	   p.currentTokenIs(TOKEN_AVG) || p.currentTokenIs(TOKEN_MIN) ||
	   p.currentTokenIs(TOKEN_MAX) {
		having.Function = strings.ToUpper(p.currentToken.Literal)
		p.nextToken()

		// Expect parentheses
		if !p.currentTokenIs(TOKEN_LPAREN) {
			return nil, fmt.Errorf("expected ( after aggregation function")
		}
		p.nextToken()

		// Parse * or field name
		if p.currentTokenIs(TOKEN_ASTERISK) || p.currentTokenIs(TOKEN_IDENTIFIER) {
			p.nextToken()
		}

		if !p.currentTokenIs(TOKEN_RPAREN) {
			return nil, fmt.Errorf("expected ) after aggregation field")
		}
		p.nextToken()

		// Parse operator
		if !p.currentTokenIs(TOKEN_OPERATOR) {
			return nil, fmt.Errorf("expected operator in HAVING clause")
		}
		having.Operator = p.currentToken.Literal
		p.nextToken()

		// Parse value
		if !p.currentTokenIs(TOKEN_NUMBER) {
			return nil, fmt.Errorf("expected number in HAVING clause")
		}
		fmt.Sscanf(p.currentToken.Literal, "%d", &having.Value)
		p.nextToken()
	}

	return having, nil
}

// CQLQuery represents a parsed CQL query AST
type CQLQuery struct {
	Select     []string      // Selected fields or *
	From       string        // Source table/category
	Conditions []Condition   // WHERE conditions
	GroupBy    []string      // GROUP BY fields
	Having     *HavingClause // HAVING clause
}

// Condition represents a WHERE condition
type Condition struct {
	Field    string
	Operator string      // =, LIKE, IN, >, <, IS, etc.
	Value    interface{} // String, number, list, or nil
	Negated  bool        // NOT prefix
}

// HavingClause represents a HAVING clause with aggregation
type HavingClause struct {
	Function string // COUNT, SUM, etc.
	Operator string // >, <, =, etc.
	Value    int    // Threshold value
}

// DetectLikePattern detects the pattern type for LIKE operator
func (c *Condition) DetectLikePattern() (prefix, suffix, contains string) {
	if c.Operator != "LIKE" {
		return "", "", ""
	}

	str, ok := c.Value.(string)
	if !ok {
		return "", "", ""
	}

	hasPrefix := strings.HasPrefix(str, "%")
	hasSuffix := strings.HasSuffix(str, "%")

	if hasPrefix && hasSuffix {
		// %pattern% -> contains
		return "", "", strings.Trim(str, "%")
	} else if hasPrefix {
		// %pattern -> endswith
		return "", strings.TrimPrefix(str, "%"), ""
	} else if hasSuffix {
		// pattern% -> startswith
		return strings.TrimSuffix(str, "%"), "", ""
	}
	// No wildcards -> exact match
	return "", "", str
}

// Validate performs basic validation on the parsed query
func (q *CQLQuery) Validate() error {
	if q.From == "" {
		return fmt.Errorf("FROM clause is required")
	}
	if len(q.Select) == 0 {
		return fmt.Errorf("SELECT clause is required")
	}

	// Security: Validate identifiers to prevent injection
	idPattern := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	for _, field := range q.Select {
		if field != "*" && !idPattern.MatchString(field) {
			return fmt.Errorf("invalid field name in SELECT: %s", field)
		}
	}

	if !idPattern.MatchString(q.From) {
		return fmt.Errorf("invalid table name: %s", q.From)
	}

	for _, field := range q.GroupBy {
		if !idPattern.MatchString(field) {
			return fmt.Errorf("invalid field name in GROUP BY: %s", field)
		}
	}

	for _, cond := range q.Conditions {
		if !idPattern.MatchString(cond.Field) {
			return fmt.Errorf("invalid field name in WHERE: %s", cond.Field)
		}
	}

	return nil
}
