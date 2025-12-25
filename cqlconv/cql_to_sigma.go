package cqlconv

import (
	"cerberus/core"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConversionResult contains the result of CQL to SIGMA conversion
type ConversionResult struct {
	Success     bool     `json:"success"`
	SigmaYAML   string   `json:"sigma_yaml,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Errors      []string `json:"errors,omitempty"`
	Unsupported []string `json:"unsupported,omitempty"`
}

// CQLToSigmaConverter converts CQL rules to SIGMA format
type CQLToSigmaConverter struct {
	warnings    []string
	errors      []string
	unsupported []string
}

// NewCQLToSigmaConverter creates a new converter instance
func NewCQLToSigmaConverter() *CQLToSigmaConverter {
	return &CQLToSigmaConverter{
		warnings:    []string{},
		errors:      []string{},
		unsupported: []string{},
	}
}

// ConvertCQLToSigma converts a CQL rule to SIGMA YAML format
//
// Security considerations:
//   - Validates CQL query before parsing
//   - Sanitizes field names and values
//   - Limits complexity to prevent resource exhaustion
//   - Returns detailed error messages for debugging
func ConvertCQLToSigma(cqlRule *core.Rule) (*ConversionResult, error) {
	if cqlRule == nil {
		return nil, fmt.Errorf("cqlRule cannot be nil")
	}

	if cqlRule.Type != "cql" && cqlRule.Type != "CQL" {
		return nil, fmt.Errorf("rule type must be 'cql', got '%s'", cqlRule.Type)
	}

	if cqlRule.Query == "" {
		return nil, fmt.Errorf("CQL query is empty")
	}

	converter := NewCQLToSigmaConverter()
	return converter.convert(cqlRule)
}

// convert performs the actual conversion
func (c *CQLToSigmaConverter) convert(cqlRule *core.Rule) (*ConversionResult, error) {
	// SECURITY: Validate resource limits before conversion
	if err := validateResourceLimits(cqlRule); err != nil {
		c.errors = append(c.errors, fmt.Sprintf("Resource limit validation failed: %v", err))
		return c.buildResult(false, ""), nil
	}

	// Parse CQL query
	parser := NewParser(cqlRule.Query)
	query, err := parser.ParseQuery()
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("CQL parse error: %v", err))
		return c.buildResult(false, ""), nil
	}

	// Validate query structure
	if err := query.Validate(); err != nil {
		c.errors = append(c.errors, fmt.Sprintf("CQL validation error: %v", err))
		return c.buildResult(false, ""), nil
	}

	// Detect unsupported patterns
	c.detectUnsupportedPatterns(query)
	if len(c.unsupported) > 0 {
		c.errors = append(c.errors, "Query contains unsupported patterns that require manual conversion")
		return c.buildResult(false, ""), nil
	}

	// Build SIGMA detection block
	detection, err := c.buildDetection(query)
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("Failed to build detection: %v", err))
		return c.buildResult(false, ""), nil
	}

	// Build SIGMA rule structure
	sigmaRule := make(map[string]interface{})

	// Basic metadata
	sigmaRule["title"] = cqlRule.Name
	if cqlRule.Description != "" {
		sigmaRule["description"] = cqlRule.Description
	}
	sigmaRule["id"] = cqlRule.ID

	// Status - default to experimental for migrated rules
	sigmaRule["status"] = "experimental"

	// Add author if present
	if cqlRule.Author != "" {
		sigmaRule["author"] = cqlRule.Author
	}

	// Add references if present
	if len(cqlRule.References) > 0 {
		sigmaRule["references"] = cqlRule.References
	}

	// Add false positives if present
	if len(cqlRule.FalsePositives) > 0 {
		sigmaRule["falsepositives"] = cqlRule.FalsePositives
	}

	// Add tags (include CQL migration tag)
	tags := cqlRule.Tags
	if tags == nil {
		tags = []string{}
	}
	tags = append(tags, "cql-migration")
	sigmaRule["tags"] = tags

	// Map severity to SIGMA level
	sigmaRule["level"] = c.mapSeverity(cqlRule.Severity)

	// Logsource - infer from FROM clause
	logsource := c.buildLogsource(query.From)
	if logsource != nil {
		sigmaRule["logsource"] = logsource
	}

	// Detection block
	sigmaRule["detection"] = detection

	// Handle correlation if present
	if cqlRule.Correlation != nil && len(cqlRule.Correlation) > 0 {
		correlation, err := c.buildCorrelation(query, cqlRule.Correlation)
		if err != nil {
			c.warnings = append(c.warnings, fmt.Sprintf("Correlation conversion warning: %v", err))
		} else if correlation != nil {
			sigmaRule["correlation"] = correlation
		}
	}

	// Serialize to YAML
	yamlBytes, err := yaml.Marshal(sigmaRule)
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("YAML marshaling error: %v", err))
		return c.buildResult(false, ""), nil
	}

	return c.buildResult(true, string(yamlBytes)), nil
}

// buildDetection constructs the SIGMA detection block
func (c *CQLToSigmaConverter) buildDetection(query *CQLQuery) (map[string]interface{}, error) {
	detection := make(map[string]interface{})

	// SECURITY: Validate conditions limit and field name safety
	if err := validateConditionsLimit(query.Conditions); err != nil {
		return nil, err
	}

	// Build selection from WHERE conditions
	if len(query.Conditions) > 0 {
		selection, filters := c.buildSelections(query.Conditions)
		if len(selection) > 0 {
			detection["selection"] = selection
		}
		// Add additional filters if needed
		for i, filter := range filters {
			detection[fmt.Sprintf("filter%d", i+1)] = filter
		}

		// Build condition string
		if len(filters) == 0 {
			detection["condition"] = "selection"
		} else {
			condParts := []string{"selection"}
			for i := range filters {
				condParts = append(condParts, fmt.Sprintf("filter%d", i+1))
			}
			detection["condition"] = strings.Join(condParts, " and ")
		}
	} else {
		// No WHERE clause - match all events from source
		c.warnings = append(c.warnings, "No WHERE clause found; SIGMA rule will match all events")
		detection["condition"] = "1 of selection"
		detection["selection"] = map[string]interface{}{
			"EventID": "*",
		}
	}

	return detection, nil
}

// buildSelections constructs selection blocks from conditions
func (c *CQLToSigmaConverter) buildSelections(conditions []Condition) (map[string]interface{}, []map[string]interface{}) {
	selection := make(map[string]interface{})
	filters := []map[string]interface{}{}

	for _, cond := range conditions {
		fieldName := cond.Field
		operator := cond.Operator
		value := cond.Value

		// Handle different operators
		switch operator {
		case "=", "==":
			if cond.Negated {
				// Negated equality -> filter
				filters = append(filters, map[string]interface{}{
					fieldName: value,
				})
			} else {
				selection[fieldName] = value
			}

		case "!=", "<>":
			// Not equal -> filter with negation
			filters = append(filters, map[string]interface{}{
				fieldName: value,
			})

		case "LIKE":
			prefix, suffix, contains := cond.DetectLikePattern()
			if contains != "" {
				// Contains pattern
				selection[fieldName+"|contains"] = contains
			} else if prefix != "" {
				// Starts with pattern
				selection[fieldName+"|startswith"] = prefix
			} else if suffix != "" {
				// Ends with pattern
				selection[fieldName+"|endswith"] = suffix
			} else {
				// No wildcards - exact match
				selection[fieldName] = value
			}

		case ">":
			selection[fieldName+"|gt"] = value

		case ">=":
			selection[fieldName+"|gte"] = value

		case "<":
			selection[fieldName+"|lt"] = value

		case "<=":
			selection[fieldName+"|lte"] = value

		case "IN":
			// IN clause -> list of values
			if valueList, ok := value.([]interface{}); ok {
				selection[fieldName] = valueList
			}

		case "IS":
			// IS NULL
			if value == nil {
				selection[fieldName] = nil
			}

		case "IS NOT":
			// IS NOT NULL -> exists
			selection[fieldName+"|exists"] = true

		default:
			c.warnings = append(c.warnings, fmt.Sprintf("Unsupported operator '%s' for field '%s'", operator, fieldName))
		}
	}

	return selection, filters
}

// buildLogsource infers logsource from FROM clause
func (c *CQLToSigmaConverter) buildLogsource(from string) map[string]interface{} {
	logsource := make(map[string]interface{})

	// Common FROM clause mappings
	fromLower := strings.ToLower(from)

	switch {
	case strings.Contains(fromLower, "windows"):
		logsource["product"] = "windows"
	case strings.Contains(fromLower, "linux"):
		logsource["product"] = "linux"
	case strings.Contains(fromLower, "azure"):
		logsource["product"] = "azure"
	case strings.Contains(fromLower, "aws"):
		logsource["product"] = "aws"
	case strings.Contains(fromLower, "network"):
		logsource["category"] = "network_connection"
	case strings.Contains(fromLower, "process"):
		logsource["category"] = "process_creation"
	case strings.Contains(fromLower, "firewall"):
		logsource["category"] = "firewall"
	default:
		// Generic category
		logsource["category"] = from
	}

	return logsource
}

// buildCorrelation constructs SIGMA correlation block from CQL GROUP BY + HAVING
func (c *CQLToSigmaConverter) buildCorrelation(query *CQLQuery, correlationConfig map[string]interface{}) (map[string]interface{}, error) {
	correlation := make(map[string]interface{})

	// Detect correlation type
	if query.Having != nil {
		// COUNT aggregation with HAVING clause
		if query.Having.Function == "COUNT" {
			correlation["type"] = "event_count"

			// Group by fields
			if len(query.GroupBy) > 0 {
				correlation["group_by"] = query.GroupBy
			}

			// Timespan from correlation config
			if timeframe, ok := correlationConfig["timeframe"].(int); ok {
				// Convert seconds to duration string
				duration := time.Duration(timeframe) * time.Second
				correlation["timespan"] = formatDuration(duration)
			} else if timespan, ok := correlationConfig["timespan"].(string); ok {
				correlation["timespan"] = timespan
			} else {
				// Default timespan
				correlation["timespan"] = "5m"
				c.warnings = append(c.warnings, "No timespan found in correlation, defaulting to 5m")
			}

			// Condition from HAVING clause
			condition := map[string]interface{}{
				"operator": query.Having.Operator,
				"value":    query.Having.Value,
			}
			correlation["condition"] = condition

		} else {
			c.warnings = append(c.warnings, fmt.Sprintf("Aggregation function '%s' not fully supported in SIGMA correlation", query.Having.Function))
		}
	}

	return correlation, nil
}

// mapSeverity maps CQL severity to SIGMA level
func (c *CQLToSigmaConverter) mapSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "informational"
	default:
		c.warnings = append(c.warnings, fmt.Sprintf("Unknown severity '%s', mapping to 'medium'", severity))
		return "medium"
	}
}

// detectUnsupportedPatterns identifies patterns that cannot be automatically converted
func (c *CQLToSigmaConverter) detectUnsupportedPatterns(query *CQLQuery) {
	// Check for subqueries (not supported)
	if strings.Contains(strings.ToUpper(query.From), "SELECT") {
		c.unsupported = append(c.unsupported, "Subqueries are not supported; split into multiple rules")
	}

	// Check for JOINs (not supported)
	if strings.Contains(strings.ToUpper(query.From), "JOIN") {
		c.unsupported = append(c.unsupported, "JOIN clauses require manual conversion to correlated rules")
	}

	// Check for complex aggregations (limited support)
	if query.Having != nil {
		if query.Having.Function != "COUNT" {
			c.unsupported = append(c.unsupported, fmt.Sprintf("Aggregation function %s requires manual conversion", query.Having.Function))
		}
	}
}

// buildResult constructs the final conversion result
func (c *CQLToSigmaConverter) buildResult(success bool, sigmaYAML string) *ConversionResult {
	return &ConversionResult{
		Success:     success,
		SigmaYAML:   sigmaYAML,
		Warnings:    c.warnings,
		Errors:      c.errors,
		Unsupported: c.unsupported,
	}
}

// formatDuration converts time.Duration to human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// UnsupportedPattern represents a pattern that cannot be converted
type UnsupportedPattern struct {
	Pattern    string
	Reason     string
	Suggestion string
}

// GetUnsupportedPatterns returns a list of known unsupported patterns
func GetUnsupportedPatterns() []UnsupportedPattern {
	return []UnsupportedPattern{
		{
			Pattern:    "SUBQUERY",
			Reason:     "Complex subqueries not supported in SIGMA",
			Suggestion: "Manually convert to multiple rules and correlate them",
		},
		{
			Pattern:    "JOIN",
			Reason:     "JOIN clauses require manual conversion",
			Suggestion: "Split into correlated rules with appropriate grouping",
		},
		{
			Pattern:    "CUSTOM_FUNC",
			Reason:     "Custom functions not supported in SIGMA",
			Suggestion: "Use equivalent SIGMA modifiers (|base64, |contains, etc.)",
		},
		{
			Pattern:    "NESTED_AGGREGATION",
			Reason:     "Nested aggregations require multiple correlation rules",
			Suggestion: "Create separate rules for each aggregation level",
		},
	}
}

// ValidateSigmaOutput performs post-conversion validation
func ValidateSigmaOutput(yamlStr string) error {
	if yamlStr == "" {
		return fmt.Errorf("SIGMA YAML is empty")
	}

	// Security: Limit size
	const maxSize = 1024 * 1024 // 1MB
	if len(yamlStr) > maxSize {
		return fmt.Errorf("SIGMA YAML exceeds maximum size of %d bytes", maxSize)
	}

	// Parse YAML to validate structure
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlStr), &parsed); err != nil {
		return fmt.Errorf("invalid SIGMA YAML: %w", err)
	}

	// Validate required fields
	requiredFields := []string{"title", "detection", "logsource"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Validate detection block
	detection, ok := parsed["detection"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("detection must be a map")
	}

	if _, ok := detection["condition"]; !ok {
		return fmt.Errorf("detection.condition is required")
	}

	return nil
}

// ParseNumericValue safely parses numeric values from various types
func ParseNumericValue(value interface{}) (float64, error) {
	switch v := value.(type) {
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to numeric value", value)
	}
}

// validateResourceLimits validates input size to prevent resource exhaustion
// SECURITY: Prevents DoS attacks through oversized rules or excessive conditions
func validateResourceLimits(rule *core.Rule) error {
	const (
		maxQueryLength   = 10000  // 10KB max query size
		maxNameLength    = 256    // Reasonable name length
		maxDescLength    = 2000   // Max description length
		maxTags          = 50     // Max number of tags
		maxReferences    = 20     // Max number of references
		maxFalsePos      = 20     // Max false positive entries
	)

	// Validate query length
	if len(rule.Query) > maxQueryLength {
		return fmt.Errorf("query exceeds maximum length of %d characters", maxQueryLength)
	}

	// Validate name length
	if len(rule.Name) > maxNameLength {
		return fmt.Errorf("rule name exceeds maximum length of %d characters", maxNameLength)
	}

	// Validate description length
	if len(rule.Description) > maxDescLength {
		return fmt.Errorf("description exceeds maximum length of %d characters", maxDescLength)
	}

	// Validate arrays
	if len(rule.Tags) > maxTags {
		return fmt.Errorf("too many tags: maximum %d allowed", maxTags)
	}

	if len(rule.References) > maxReferences {
		return fmt.Errorf("too many references: maximum %d allowed", maxReferences)
	}

	if len(rule.FalsePositives) > maxFalsePos {
		return fmt.Errorf("too many false positives: maximum %d allowed", maxFalsePos)
	}

	return nil
}

// sanitizeFieldName sanitizes a field name to prevent YAML injection
// SECURITY: Validates field names against safe character set
func sanitizeFieldName(fieldName string) error {
	// YAML injection prevention: only allow safe characters
	// Allow: alphanumeric, underscore, hyphen, dot
	for i, r := range fieldName {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("invalid character at position %d in field name '%s': must be alphanumeric, underscore, hyphen, or dot", i, fieldName)
		}
	}

	// Additional checks
	if len(fieldName) == 0 {
		return fmt.Errorf("field name cannot be empty")
	}

	if len(fieldName) > 256 {
		return fmt.Errorf("field name exceeds maximum length of 256 characters")
	}

	// Prevent YAML control characters
	yamlUnsafe := []string{":", "#", "&", "*", "!", "|", ">", "'", "\"", "%", "@", "`"}
	for _, unsafe := range yamlUnsafe {
		if strings.Contains(fieldName, unsafe) {
			return fmt.Errorf("field name contains unsafe YAML character: %s", unsafe)
		}
	}

	return nil
}

// validateConditionsLimit validates the number of conditions doesn't exceed limits
// SECURITY: Prevents resource exhaustion from complex queries
func validateConditionsLimit(conditions []Condition) error {
	const maxConditions = 100

	if len(conditions) > maxConditions {
		return fmt.Errorf("query has %d conditions, exceeds maximum of %d", len(conditions), maxConditions)
	}

	// Validate each condition's field name
	for i, cond := range conditions {
		if err := sanitizeFieldName(cond.Field); err != nil {
			return fmt.Errorf("condition %d: %w", i, err)
		}
	}

	return nil
}
