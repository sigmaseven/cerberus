package search

import (
	"fmt"
	"regexp"
	"strings"
)

// Schema defines field name to type mappings for query validation
// TASK 27.5: Schema for field validation
type Schema map[string]FieldType

// Validator validates CQL queries against a schema
// TASK 27.5: Query validation before execution
type Validator struct {
	schema Schema
}

// NewValidator creates a new query validator with the given schema
func NewValidator(schema Schema) *Validator {
	return &Validator{
		schema: schema,
	}
}

// DefaultSchema returns a default schema with common event fields
// TASK 27.5: Default schema based on ClickHouse table structure
func DefaultSchema() Schema {
	return Schema{
		"event_id":      FieldTypeString,
		"id":            FieldTypeString,
		"timestamp":     FieldTypeTime,
		"@timestamp":    FieldTypeTime,
		"source_ip":     FieldTypeString,
		"source_format": FieldTypeString,
		"event_type":    FieldTypeString,
		"severity":      FieldTypeString,
		"raw_data":      FieldTypeString,
		"raw_log":       FieldTypeString,
	}
}

// ValidateQuery validates a parsed CQL AST against the schema
// TASK 27.5: Validate field names, operator types, and regex patterns
func (v *Validator) ValidateQuery(ast *ASTNode) error {
	if ast == nil {
		return nil // Empty query is valid
	}

	return v.validateNode(ast)
}

// validateNode recursively validates AST nodes
func (v *Validator) validateNode(node *ASTNode) error {
	if node == nil {
		return nil
	}

	switch node.Type {
	case NodeCondition:
		return v.validateCondition(node)

	case NodeLogical:
		if node.Left != nil {
			if err := v.validateNode(node.Left); err != nil {
				return err
			}
		}
		if node.Right != nil {
			if err := v.validateNode(node.Right); err != nil {
				return err
			}
		}
		return nil

	case NodeGroup:
		for _, child := range node.Children {
			if err := v.validateNode(child); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown node type: %d", node.Type)
	}
}

// validateCondition validates a single condition node
// TASK 27.5: Validate field existence, operator-type compatibility, regex validity
func (v *Validator) validateCondition(node *ASTNode) error {
	// Validate field name exists in schema
	fieldType, exists := v.schema[node.Field]
	if !exists {
		// Check if it might be a nested field (e.g., "user.name")
		// For nested fields, we'll allow them (they'll be in JSON)
		if !strings.Contains(node.Field, ".") {
			return fmt.Errorf("unknown field: %s", node.Field)
		}
		// Nested fields are allowed but we can't validate their type
		fieldType = FieldTypeString // Default to string for nested fields
	}

	// Validate operator-type compatibility
	if err := v.validateOperatorType(node.Operator, fieldType); err != nil {
		return fmt.Errorf("field %s: %w", node.Field, err)
	}

	// Validate regex patterns if using matches operator
	if node.Operator == "matches" || node.Operator == "~=" {
		pattern, ok := node.Value.(string)
		if !ok {
			return fmt.Errorf("regex pattern must be a string")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
	}

	return nil
}

// validateOperatorType checks if an operator is compatible with a field type
// TASK 27.5: Numeric operators only on numeric fields, string operators only on string fields
func (v *Validator) validateOperatorType(operator string, fieldType FieldType) error {
	// Numeric operators
	numericOps := []string{">", "<", ">=", "<=", "gt", "lt", "gte", "lte"}
	for _, op := range numericOps {
		if operator == op {
			if fieldType != FieldTypeInt && fieldType != FieldTypeFloat && fieldType != FieldTypeTime {
				return fmt.Errorf("numeric operator '%s' not allowed on %s field", operator, fieldType)
			}
			return nil
		}
	}

	// String operators
	stringOps := []string{"contains", "startswith", "endswith", "matches", "~="}
	for _, op := range stringOps {
		if operator == op {
			if fieldType != FieldTypeString {
				return fmt.Errorf("string operator '%s' not allowed on %s field", operator, fieldType)
			}
			return nil
		}
	}

	// Equality and list operators work on all types
	return nil
}
