package search

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/util"
)

const (
	// MaxRegexCacheSize limits the regex cache to prevent unbounded memory growth
	// SECURITY: Prevents DoS through cache exhaustion attacks
	MaxRegexCacheSize = 1000
)

// Evaluator evaluates CQL queries against single events
type Evaluator struct {
	// Cache compiled regexes for performance
	regexCache map[string]*regexp.Regexp
	// TASK 138.3: Removed unused cacheMu sync.RWMutex field
}

// NewEvaluator creates a new CQL evaluator
func NewEvaluator() *Evaluator {
	return &Evaluator{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// Evaluate evaluates a CQL query against an event
func (e *Evaluator) Evaluate(query string, event *core.Event) (bool, map[string]interface{}, error) {
	// Parse the query
	parser := NewParser(query)
	ast, err := parser.Parse()
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse query: %w", err)
	}

	// Validate the AST
	if err := ast.Validate(); err != nil {
		return false, nil, fmt.Errorf("invalid query: %w", err)
	}

	// Evaluate the AST against the event
	matched, matchedFields := e.evaluateNode(ast, event)
	return matched, matchedFields, nil
}

// evaluateNode recursively evaluates an AST node against an event
func (e *Evaluator) evaluateNode(node *ASTNode, event *core.Event) (bool, map[string]interface{}) {
	if node == nil {
		return false, nil
	}

	matchedFields := make(map[string]interface{})

	switch node.Type {
	case NodeCondition:
		matched, field, value := e.evaluateCondition(node, event)
		if matched && field != "" {
			matchedFields[field] = value
		}
		return matched, matchedFields

	case NodeLogical:
		switch node.Logic {
		case "AND":
			leftMatched, leftFields := e.evaluateNode(node.Left, event)
			if !leftMatched {
				return false, nil
			}
			rightMatched, rightFields := e.evaluateNode(node.Right, event)
			if !rightMatched {
				return false, nil
			}
			// Merge matched fields
			for k, v := range leftFields {
				matchedFields[k] = v
			}
			for k, v := range rightFields {
				matchedFields[k] = v
			}
			return true, matchedFields

		case "OR":
			leftMatched, leftFields := e.evaluateNode(node.Left, event)
			if leftMatched {
				return true, leftFields
			}
			rightMatched, rightFields := e.evaluateNode(node.Right, event)
			return rightMatched, rightFields

		case "NOT":
			matched, _ := e.evaluateNode(node.Left, event)
			return !matched, matchedFields
		}

	case NodeGroup:
		if len(node.Children) > 0 {
			return e.evaluateNode(node.Children[0], event)
		}
	}

	return false, nil
}

// evaluateCondition evaluates a single condition against an event
func (e *Evaluator) evaluateCondition(node *ASTNode, event *core.Event) (bool, string, interface{}) {
	// Get the field value from the event
	fieldValue := e.getFieldValue(node.Field, event)

	// Handle exists/not exists operators
	if node.Operator == "exists" {
		return fieldValue != nil, node.Field, fieldValue
	}
	if node.Operator == "not exists" {
		return fieldValue == nil, node.Field, nil
	}

	// If field doesn't exist, condition fails
	if fieldValue == nil {
		return false, "", nil
	}

	// Evaluate the operator
	matched := e.evaluateOperator(node.Operator, fieldValue, node.Value)
	if matched {
		return true, node.Field, fieldValue
	}
	return false, "", nil
}

// GetFieldValue retrieves a field value from an event (exported for correlation engine)
func (e *Evaluator) GetFieldValue(field string, event *core.Event) interface{} {
	return e.getFieldValue(field, event)
}

// getFieldValue retrieves a field value from an event
func (e *Evaluator) getFieldValue(field string, event *core.Event) interface{} {
	// Handle nested fields with dot notation (e.g., "user.name")
	parts := strings.Split(field, ".")

	// Map common field names to event struct fields
	var value interface{}

	switch parts[0] {
	case "event_id", "EventID", "id", "ID":
		value = event.EventID
	case "timestamp", "@timestamp":
		value = event.Timestamp
	case "source_format", "SourceFormat":
		value = event.SourceFormat
	case "source_ip", "SourceIP":
		// Extract from Fields map
		if event.Fields != nil {
			value = event.Fields["source_ip"]
		}
	case "event_type", "EventType":
		// Extract from Fields map
		if event.Fields != nil {
			value = event.Fields["event_type"]
		}
	case "severity", "Severity":
		// Extract from Fields map
		if event.Fields != nil {
			value = event.Fields["severity"]
		}
	case "raw_data", "RawData", "raw_log", "RawLog":
		value = event.RawData
	default:
		// All other fields are in the Fields map
		if event.Fields != nil {
			value = event.Fields[parts[0]]
		}
	}

	// Handle nested field access
	if len(parts) > 1 && value != nil {
		for _, part := range parts[1:] {
			if m, ok := value.(map[string]interface{}); ok {
				value = m[part]
			} else {
				return nil
			}
		}
	}

	return value
}

// evaluateOperator evaluates an operator against field and query values
func (e *Evaluator) evaluateOperator(operator string, fieldValue interface{}, queryValue interface{}) bool {
	switch operator {
	case "=", "equals":
		return e.equals(fieldValue, queryValue)

	case "!=", "not_equals":
		return !e.equals(fieldValue, queryValue)

	case ">", "gt":
		return e.greaterThan(fieldValue, queryValue)

	case "<", "lt":
		return e.lessThan(fieldValue, queryValue)

	case ">=", "gte":
		return e.greaterThanOrEqual(fieldValue, queryValue)

	case "<=", "lte":
		return e.lessThanOrEqual(fieldValue, queryValue)

	case "contains":
		return e.contains(fieldValue, queryValue)

	case "startswith":
		return e.startsWith(fieldValue, queryValue)

	case "endswith":
		return e.endsWith(fieldValue, queryValue)

	case "matches", "~=":
		return e.matches(fieldValue, queryValue)

	case "in":
		return e.in(fieldValue, queryValue)

	case "not in":
		return !e.in(fieldValue, queryValue)
	}

	return false
}

// equals checks if two values are equal
func (e *Evaluator) equals(fieldValue, queryValue interface{}) bool {
	// Convert to comparable types
	fieldStr := e.toString(fieldValue)
	queryStr := e.toString(queryValue)

	// Try case-insensitive string comparison
	if strings.EqualFold(fieldStr, queryStr) {
		return true
	}

	// Try numeric comparison
	if e.isNumeric(fieldValue) && e.isNumeric(queryValue) {
		return e.toFloat64(fieldValue) == e.toFloat64(queryValue)
	}

	return false
}

// greaterThan checks if fieldValue > queryValue
func (e *Evaluator) greaterThan(fieldValue, queryValue interface{}) bool {
	if !e.isNumeric(fieldValue) || !e.isNumeric(queryValue) {
		return false
	}
	return e.toFloat64(fieldValue) > e.toFloat64(queryValue)
}

// lessThan checks if fieldValue < queryValue
func (e *Evaluator) lessThan(fieldValue, queryValue interface{}) bool {
	if !e.isNumeric(fieldValue) || !e.isNumeric(queryValue) {
		return false
	}
	return e.toFloat64(fieldValue) < e.toFloat64(queryValue)
}

// greaterThanOrEqual checks if fieldValue >= queryValue
func (e *Evaluator) greaterThanOrEqual(fieldValue, queryValue interface{}) bool {
	if !e.isNumeric(fieldValue) || !e.isNumeric(queryValue) {
		return false
	}
	return e.toFloat64(fieldValue) >= e.toFloat64(queryValue)
}

// lessThanOrEqual checks if fieldValue <= queryValue
func (e *Evaluator) lessThanOrEqual(fieldValue, queryValue interface{}) bool {
	if !e.isNumeric(fieldValue) || !e.isNumeric(queryValue) {
		return false
	}
	return e.toFloat64(fieldValue) <= e.toFloat64(queryValue)
}

// contains checks if fieldValue contains queryValue
func (e *Evaluator) contains(fieldValue, queryValue interface{}) bool {
	fieldStr := e.toString(fieldValue)
	queryStr := e.toString(queryValue)
	return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(queryStr))
}

// startsWith checks if fieldValue starts with queryValue
func (e *Evaluator) startsWith(fieldValue, queryValue interface{}) bool {
	fieldStr := e.toString(fieldValue)
	queryStr := e.toString(queryValue)
	return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(queryStr))
}

// endsWith checks if fieldValue ends with queryValue
func (e *Evaluator) endsWith(fieldValue, queryValue interface{}) bool {
	fieldStr := e.toString(fieldValue)
	queryStr := e.toString(queryValue)
	return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(queryStr))
}

// matches checks if fieldValue matches regex queryValue
// SECURITY: Uses safe regex compilation with ReDoS protection and timeout
// TASK 32.5: Integrate RegexWithTimeout into CQL parser regex operations
func (e *Evaluator) matches(fieldValue, queryValue interface{}) bool {
	fieldStr := e.toString(fieldValue)
	pattern := e.toString(queryValue)

	// Validate pattern complexity before execution
	if err := util.ValidateComplexity(pattern); err != nil {
		// Dangerous pattern rejected - return false (no match)
		return false
	}

	// Use RegexWithTimeout for execution with ReDoS protection
	// Default timeout: 100ms (per Task 32 spec)
	// TODO: Make timeout configurable via Evaluator config
	timeout := 100 * time.Millisecond
	result, err := util.RegexWithTimeout(pattern, fieldStr, timeout)
	if err != nil {
		// Timeout or error occurred - return false (no match) for safety
		return false
	}

	return result
}

// in checks if fieldValue is in queryValue array
func (e *Evaluator) in(fieldValue, queryValue interface{}) bool {
	fieldStr := e.toString(fieldValue)

	// Query value should be an array
	switch v := queryValue.(type) {
	case []interface{}:
		for _, item := range v {
			if strings.EqualFold(fieldStr, e.toString(item)) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if strings.EqualFold(fieldStr, item) {
				return true
			}
		}
	}

	return false
}

// Helper functions

func (e *Evaluator) toString(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func (e *Evaluator) isNumeric(value interface{}) bool {
	switch value.(type) {
	case int, int8, int16, int32, int64:
		return true
	case uint, uint8, uint16, uint32, uint64:
		return true
	case float32, float64:
		return true
	}
	return false
}

// ToFloat64 converts a value to float64 (exported for correlation engine)
func (e *Evaluator) ToFloat64(value interface{}) float64 {
	return e.toFloat64(value)
}

func (e *Evaluator) toFloat64(value interface{}) float64 {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return v.Float()
	}
	return 0
}

// EvaluateTimestamp evaluates timestamp-based conditions
func (e *Evaluator) EvaluateTimestamp(operator string, eventTime time.Time, queryTime interface{}) bool {
	var compareTime time.Time

	switch v := queryTime.(type) {
	case time.Time:
		compareTime = v
	case string:
		// Try parsing as time string
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return false
		}
		compareTime = parsed
	default:
		return false
	}

	switch operator {
	case ">", "gt":
		return eventTime.After(compareTime)
	case "<", "lt":
		return eventTime.Before(compareTime)
	case ">=", "gte":
		return eventTime.After(compareTime) || eventTime.Equal(compareTime)
	case "<=", "lte":
		return eventTime.Before(compareTime) || eventTime.Equal(compareTime)
	case "=", "equals":
		return eventTime.Equal(compareTime)
	}

	return false
}
