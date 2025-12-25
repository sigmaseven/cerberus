package search

import (
	"fmt"
	"strings"
	"time"
)

// Translator translates CQL AST nodes to ClickHouse SQL
// SECURITY: Uses parameterized queries to prevent SQL injection
type Translator struct {
	builder *SQLBuilder
	params  []interface{}
}

// NewTranslator creates a new AST to SQL translator
func NewTranslator() *Translator {
	return &Translator{
		builder: NewSQLBuilder(),
		params:  []interface{}{},
	}
}

// TranslateAST translates a CQL AST to ClickHouse SQL query and parameters
// TASK 4.2: AST-to-SQL translation for basic operators
func (t *Translator) TranslateAST(ast *ASTNode, opts QueryOptions) (string, []interface{}, error) {
	// Reset translator state
	t.builder = NewSQLBuilder()
	t.params = []interface{}{}

	// Start building SELECT query
	t.builder.Select("*").From("events")

	// Translate WHERE clause from AST
	if ast != nil {
		whereClause, err := t.translateCondition(ast)
		if err != nil {
			return "", nil, fmt.Errorf("failed to translate condition: %w", err)
		}
		if whereClause != "" {
			// Split clause and params - whereClause may contain multiple conditions
			// For now, we'll use a single Where call with all params
			// The builder will handle parameter ordering
			t.builder.Where(whereClause, t.params...)
			// Clear params since builder now owns them
			t.params = []interface{}{}
		}
	}

	// Add time range filtering (default: last 24 hours)
	// Check if StartTime/EndTime are set (not nil and not zero time)
	if opts.StartTime != nil {
		if startTime, ok := opts.StartTime.(time.Time); ok && !startTime.IsZero() {
			t.builder.Where("timestamp >= ?", startTime)
		}
	}
	if opts.EndTime != nil {
		if endTime, ok := opts.EndTime.(time.Time); ok && !endTime.IsZero() {
			t.builder.Where("timestamp <= ?", endTime)
		}
	}

	// Add pagination
	if opts.Limit > 0 {
		t.builder.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		t.builder.Offset(opts.Offset)
	}

	// Add ordering (default: timestamp DESC)
	if opts.OrderBy != "" {
		t.builder.OrderBy(opts.OrderBy, opts.OrderDirection)
	} else {
		t.builder.OrderBy("timestamp", "DESC")
	}

	// Build final query
	query, params := t.builder.Build()
	return query, params, nil
}

// QueryOptions contains query execution options
type QueryOptions struct {
	StartTime      interface{} // time.Time or nil
	EndTime        interface{} // time.Time or nil
	Limit          int
	Offset         int
	OrderBy        string
	OrderDirection string // ASC or DESC
}

// translateCondition recursively translates an AST node to SQL WHERE clause
// TASK 4.2: Translate basic operators (equals, contains, startswith, endswith)
func (t *Translator) translateCondition(node *ASTNode) (string, error) {
	if node == nil {
		return "", nil
	}

	switch node.Type {
	case NodeCondition:
		return t.translateBasicCondition(node)

	case NodeLogical:
		return t.translateLogicalCondition(node)

	case NodeGroup:
		if len(node.Children) > 0 {
			return t.translateCondition(node.Children[0])
		}
		return "", nil
	}

	return "", fmt.Errorf("unknown node type: %d", node.Type)
}

// translateBasicCondition translates a basic condition (field operator value)
// TASK 4.2: Basic operator translation
func (t *Translator) translateBasicCondition(node *ASTNode) (string, error) {
	field := node.Field
	operator := node.Operator
	value := node.Value

	// Get field reference (handle nested fields)
	fieldRef := t.getFieldReference(field)

	// Check if this is a JSON field (needs type conversion for numeric comparisons)
	isJSONField := strings.Contains(fieldRef, "JSONExtractString")

	// Translate operator to SQL
	switch operator {
	case "=", "equals":
		// equals -> field = ?
		// For JSON fields with numeric values, convert to string for comparison
		paramValue := t.normalizeValueForJSON(value, isJSONField)
		t.params = append(t.params, paramValue)
		return fmt.Sprintf("%s = ?", fieldRef), nil

	case "!=", "not_equals":
		// not_equals -> field != ?
		paramValue := t.normalizeValueForJSON(value, isJSONField)
		t.params = append(t.params, paramValue)
		return fmt.Sprintf("%s != ?", fieldRef), nil

	case ">", "gt":
		// gt -> field > ?
		// For numeric comparisons on JSON fields, we need to cast to number
		if isJSONField {
			t.params = append(t.params, value)
			return fmt.Sprintf("toFloat64OrZero(%s) > ?", fieldRef), nil
		}
		t.params = append(t.params, value)
		return fmt.Sprintf("%s > ?", fieldRef), nil

	case "<", "lt":
		// lt -> field < ?
		if isJSONField {
			t.params = append(t.params, value)
			return fmt.Sprintf("toFloat64OrZero(%s) < ?", fieldRef), nil
		}
		t.params = append(t.params, value)
		return fmt.Sprintf("%s < ?", fieldRef), nil

	case ">=", "gte":
		// gte -> field >= ?
		if isJSONField {
			t.params = append(t.params, value)
			return fmt.Sprintf("toFloat64OrZero(%s) >= ?", fieldRef), nil
		}
		t.params = append(t.params, value)
		return fmt.Sprintf("%s >= ?", fieldRef), nil

	case "<=", "lte":
		// lte -> field <= ?
		if isJSONField {
			t.params = append(t.params, value)
			return fmt.Sprintf("toFloat64OrZero(%s) <= ?", fieldRef), nil
		}
		t.params = append(t.params, value)
		return fmt.Sprintf("%s <= ?", fieldRef), nil

	case "contains":
		// contains -> field LIKE '%value%' (case-insensitive)
		// TASK 4.2: String matching with LIKE and wildcard escaping
		valueStr := fmt.Sprintf("%v", value)
		// Escape LIKE wildcards (%, _) in the value
		escapedValue := escapeLikeWildcards(valueStr)
		t.params = append(t.params, fmt.Sprintf("%%%s%%", escapedValue))
		return fmt.Sprintf("lower(%s) LIKE lower(?)", fieldRef), nil

	case "startswith":
		// startswith -> field LIKE 'value%'
		valueStr := fmt.Sprintf("%v", value)
		escapedValue := escapeLikeWildcards(valueStr)
		t.params = append(t.params, fmt.Sprintf("%s%%", escapedValue))
		return fmt.Sprintf("lower(%s) LIKE lower(?)", fieldRef), nil

	case "endswith":
		// endswith -> field LIKE '%value'
		valueStr := fmt.Sprintf("%v", value)
		escapedValue := escapeLikeWildcards(valueStr)
		t.params = append(t.params, fmt.Sprintf("%%%s", escapedValue))
		return fmt.Sprintf("lower(%s) LIKE lower(?)", fieldRef), nil

	case "exists":
		// exists -> check field exists and is not empty
		// For JSON fields, JSONExtractString returns '' for missing fields, not NULL
		if isJSONField {
			// For JSON fields, check that the extracted value is not empty
			return fmt.Sprintf("%s != ''", fieldRef), nil
		}
		// For actual columns, use IS NOT NULL
		return fmt.Sprintf("%s IS NOT NULL AND %s != ''", fieldRef, fieldRef), nil

	case "not exists":
		// not exists -> field is NULL or empty
		if isJSONField {
			// For JSON fields, check that the extracted value is empty
			return fmt.Sprintf("%s = ''", fieldRef), nil
		}
		// For actual columns, use IS NULL or empty
		return fmt.Sprintf("(%s IS NULL OR %s = '')", fieldRef, fieldRef), nil

	case "in":
		// in -> field IN (?, ?, ?)
		return t.translateInOperator(fieldRef, value)

	case "not in":
		// not in -> field NOT IN (?, ?, ?)
		return t.translateNotInOperator(fieldRef, value)

	case "matches", "~=":
		// regex -> match(field, ?)
		// TASK 4.3: Complex operator translation
		return t.translateRegexOperator(fieldRef, value)

	default:
		return "", fmt.Errorf("unsupported operator: %s", operator)
	}
}

// translateLogicalCondition translates logical operators (AND, OR, NOT)
func (t *Translator) translateLogicalCondition(node *ASTNode) (string, error) {
	switch node.Logic {
	case "AND":
		if node.Left == nil || node.Right == nil {
			return "", fmt.Errorf("AND operator requires both left and right operands")
		}
		leftClause, err := t.translateCondition(node.Left)
		if err != nil {
			return "", err
		}
		rightClause, err := t.translateCondition(node.Right)
		if err != nil {
			return "", err
		}
		if leftClause == "" {
			return rightClause, nil
		}
		if rightClause == "" {
			return leftClause, nil
		}
		return fmt.Sprintf("(%s) AND (%s)", leftClause, rightClause), nil

	case "OR":
		if node.Left == nil || node.Right == nil {
			return "", fmt.Errorf("OR operator requires both left and right operands")
		}
		leftClause, err := t.translateCondition(node.Left)
		if err != nil {
			return "", err
		}
		rightClause, err := t.translateCondition(node.Right)
		if err != nil {
			return "", err
		}
		if leftClause == "" {
			return rightClause, nil
		}
		if rightClause == "" {
			return leftClause, nil
		}
		return fmt.Sprintf("(%s) OR (%s)", leftClause, rightClause), nil

	case "NOT":
		if node.Left == nil {
			return "", fmt.Errorf("NOT operator requires left operand")
		}
		clause, err := t.translateCondition(node.Left)
		if err != nil {
			return "", err
		}
		if clause == "" {
			return "", nil
		}
		return fmt.Sprintf("NOT (%s)", clause), nil

	default:
		return "", fmt.Errorf("unsupported logical operator: %s", node.Logic)
	}
}

// translateInOperator translates IN operator
// TASK 4.3: Complex operator translation
func (t *Translator) translateInOperator(fieldRef string, value interface{}) (string, error) {
	var values []interface{}
	switch v := value.(type) {
	case []interface{}:
		values = v
	case []string:
		// Convert []string to []interface{}
		values = make([]interface{}, len(v))
		for i, s := range v {
			values[i] = s
		}
	default:
		return "", fmt.Errorf("IN operator requires array value, got %T", value)
	}

	if len(values) == 0 {
		return "1 = 0", nil // Always false
	}

	// Build IN clause with placeholders
	placeholders := make([]string, len(values))
	for i := range placeholders {
		placeholders[i] = "?"
		t.params = append(t.params, values[i])
	}

	return fmt.Sprintf("%s IN (%s)", fieldRef, strings.Join(placeholders, ", ")), nil
}

// translateNotInOperator translates NOT IN operator
// TASK 4.3: Complex operator translation
func (t *Translator) translateNotInOperator(fieldRef string, value interface{}) (string, error) {
	inClause, err := t.translateInOperator(fieldRef, value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("NOT (%s)", inClause), nil
}

// translateRegexOperator translates regex/matches operator
// TASK 4.3: Complex operator translation
func (t *Translator) translateRegexOperator(fieldRef string, value interface{}) (string, error) {
	pattern := fmt.Sprintf("%v", value)
	t.params = append(t.params, pattern)
	// ClickHouse uses match() function for regex
	return fmt.Sprintf("match(%s, ?)", fieldRef), nil
}

// getFieldReference converts a CQL field name to a SQL field reference
// Handles nested fields using JSONExtract for ClickHouse
func (t *Translator) getFieldReference(field string) string {
	// Handle nested fields (e.g., "user.name" -> JSONExtractString(fields, 'user', 'name'))
	parts := strings.Split(field, ".")
	if len(parts) > 1 {
		// TASK 4.3: Nested field support with JSONExtract
		// For now, assume all nested fields are strings
		// In task 4.4, we'll add type detection
		jsonPath := strings.Join(parts[:len(parts)-1], ".")
		lastField := parts[len(parts)-1]
		return fmt.Sprintf("JSONExtractString(fields, '%s', '%s')", jsonPath, lastField)
	}

	// Map common field names to actual table columns
	// Only fields that exist as columns in the ClickHouse events table
	// Other fields like source_ip, dest_ip, etc. are stored in the 'fields' JSON column
	fieldMap := map[string]string{
		"event_id":      "event_id",
		"id":            "event_id",
		"timestamp":     "timestamp",
		"@timestamp":    "timestamp",
		"ingested_at":   "ingested_at",
		"listener_id":   "listener_id",
		"listener_name": "listener_name",
		"source":        "source",
		"source_format": "source_format",
		"SourceFormat":  "source_format",
		"raw_data":      "raw_data",
		"raw_log":       "raw_data",
		"fields":        "fields",
	}

	if mapped, ok := fieldMap[field]; ok {
		return mapped
	}

	// For other fields, assume they're in the 'fields' JSON column
	return fmt.Sprintf("JSONExtractString(fields, '%s')", field)
}

// escapeLikeWildcards escapes LIKE wildcard characters (%, _) in the value
// SECURITY: Prevents LIKE injection by escaping wildcards
func escapeLikeWildcards(value string) string {
	// Escape % and _ by replacing with \% and \_
	escaped := strings.ReplaceAll(value, "\\", "\\\\") // Escape backslashes first
	escaped = strings.ReplaceAll(escaped, "%", "\\%")
	escaped = strings.ReplaceAll(escaped, "_", "\\_")
	return escaped
}

// normalizeValueForJSON converts numeric values to strings when comparing against JSON fields
// This is necessary because JSONExtractString returns strings, and ClickHouse
// doesn't allow comparing String to numeric types directly
func (t *Translator) normalizeValueForJSON(value interface{}, isJSONField bool) interface{} {
	if !isJSONField {
		return value
	}

	// Convert numeric types to string for JSON field comparison
	switch v := value.(type) {
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case float64:
		// Check if it's a whole number
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case float32:
		if v == float32(int32(v)) {
			return fmt.Sprintf("%d", int32(v))
		}
		return fmt.Sprintf("%g", v)
	default:
		return value
	}
}
