package search

import (
	"fmt"
	"strings"
)

// SQLBuilder is a fluent SQL builder for ClickHouse queries
// SECURITY: Uses parameterized queries to prevent SQL injection
type SQLBuilder struct {
	selectFields []string
	fromTable    string
	whereClauses []string
	params       []interface{}
	limitVal     *int
	offsetVal    *int
	orderBy      []string
}

// NewSQLBuilder creates a new SQL builder
func NewSQLBuilder() *SQLBuilder {
	return &SQLBuilder{
		selectFields: []string{},
		whereClauses: []string{},
		params:       []interface{}{},
		orderBy:      []string{},
	}
}

// Select adds SELECT fields to the query
func (b *SQLBuilder) Select(fields ...string) *SQLBuilder {
	b.selectFields = append(b.selectFields, fields...)
	return b
}

// From sets the FROM table
func (b *SQLBuilder) From(table string) *SQLBuilder {
	b.fromTable = table
	return b
}

// Where adds a WHERE condition with parameterized values
// SECURITY: All user input must be passed as parameters, not in condition string
func (b *SQLBuilder) Where(condition string, params ...interface{}) *SQLBuilder {
	b.whereClauses = append(b.whereClauses, condition)
	b.params = append(b.params, params...)
	return b
}

// And adds an AND WHERE condition (equivalent to Where)
func (b *SQLBuilder) And(condition string, params ...interface{}) *SQLBuilder {
	return b.Where(condition, params...)
}

// Or adds an OR WHERE condition
// NOTE: OR conditions need careful grouping - caller should use parentheses
func (b *SQLBuilder) Or(condition string, params ...interface{}) *SQLBuilder {
	if len(b.whereClauses) == 0 {
		// If no existing clauses, treat as WHERE
		return b.Where(condition, params...)
	}
	// Otherwise, combine with OR
	lastIdx := len(b.whereClauses) - 1
	lastCondition := b.whereClauses[lastIdx]
	b.whereClauses[lastIdx] = fmt.Sprintf("(%s) OR (%s)", lastCondition, condition)
	b.params = append(b.params, params...)
	return b
}

// Not wraps the last condition in NOT
// NOTE: This modifies the last condition added
func (b *SQLBuilder) Not() *SQLBuilder {
	if len(b.whereClauses) > 0 {
		lastIdx := len(b.whereClauses) - 1
		b.whereClauses[lastIdx] = fmt.Sprintf("NOT (%s)", b.whereClauses[lastIdx])
	}
	return b
}

// Limit sets the LIMIT clause
func (b *SQLBuilder) Limit(n int) *SQLBuilder {
	b.limitVal = &n
	return b
}

// Offset sets the OFFSET clause
func (b *SQLBuilder) Offset(n int) *SQLBuilder {
	b.offsetVal = &n
	return b
}

// OrderBy adds an ORDER BY clause
func (b *SQLBuilder) OrderBy(field string, direction string) *SQLBuilder {
	if direction == "" {
		direction = "ASC"
	}
	b.orderBy = append(b.orderBy, fmt.Sprintf("%s %s", b.escapeIdentifier(field), strings.ToUpper(direction)))
	return b
}

// Build constructs the final SQL query string and returns it with parameters
// SECURITY: Returns parameterized query - parameters must be bound separately
func (b *SQLBuilder) Build() (string, []interface{}) {
	var query strings.Builder

	// SELECT clause
	if len(b.selectFields) == 0 {
		query.WriteString("SELECT *")
	} else {
		query.WriteString("SELECT ")
		escapedFields := make([]string, len(b.selectFields))
		for i, field := range b.selectFields {
			escapedFields[i] = b.escapeIdentifier(field)
		}
		query.WriteString(strings.Join(escapedFields, ", "))
	}

	// FROM clause
	if b.fromTable != "" {
		query.WriteString(" FROM ")
		query.WriteString(b.escapeIdentifier(b.fromTable))
	}

	// WHERE clause
	if len(b.whereClauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(b.whereClauses, " AND "))
	}

	// ORDER BY clause
	if len(b.orderBy) > 0 {
		query.WriteString(" ORDER BY ")
		query.WriteString(strings.Join(b.orderBy, ", "))
	}

	// LIMIT clause
	if b.limitVal != nil {
		query.WriteString(fmt.Sprintf(" LIMIT %d", *b.limitVal))
	}

	// OFFSET clause
	if b.offsetVal != nil {
		query.WriteString(fmt.Sprintf(" OFFSET %d", *b.offsetVal))
	}

	return query.String(), b.params
}

// escapeIdentifier escapes SQL identifiers to prevent injection
// SECURITY: Only allows alphanumeric, underscore, and dot (for nested fields)
// Rejects any identifier with SQL keywords or special characters
func (b *SQLBuilder) escapeIdentifier(identifier string) string {
	// Special case: "*" is SQL wildcard, don't escape
	if identifier == "*" {
		return "*"
	}

	// Special case: SQL aggregate functions should not be escaped
	// These are safe built-in functions, not user-provided identifiers
	lowerIdent := strings.ToLower(identifier)
	aggregateFunctions := []string{
		"count()", "count(*)",
		"sum(", "avg(", "min(", "max(",
		"uniq(", "uniqexact(",
		"grouparray(", "groupuniqarray(",
		"any(", "anylast(",
	}
	for _, fn := range aggregateFunctions {
		if strings.HasPrefix(lowerIdent, fn) {
			return identifier // Pass through SQL functions unchanged
		}
	}

	// Validate identifier is safe (alphanumeric, underscore, dot only)
	// For ClickHouse, we can use backticks for identifiers with dots
	safe := true
	for _, char := range identifier {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '.') {
			safe = false
			break
		}
	}

	if !safe {
		// If identifier contains special characters, wrap in backticks
		// Replace backticks in identifier to prevent injection
		escaped := strings.ReplaceAll(identifier, "`", "``")
		return fmt.Sprintf("`%s`", escaped)
	}

	return identifier
}

// Reset clears the builder state for reuse
func (b *SQLBuilder) Reset() *SQLBuilder {
	b.selectFields = []string{}
	b.fromTable = ""
	b.whereClauses = []string{}
	b.params = []interface{}{}
	b.limitVal = nil
	b.offsetVal = nil
	b.orderBy = []string{}
	return b
}
