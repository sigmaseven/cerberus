package core

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SIGMA YAML validation constants - defense in depth against malicious payloads
const (
	// MaxSigmaYAMLSize limits YAML payload size to prevent memory exhaustion attacks
	MaxSigmaYAMLSize = 1024 * 1024 // 1MB maximum

	// MaxYAMLDepth prevents deeply nested YAML structures that could cause stack overflow
	MaxYAMLDepth = 50

	// MaxYAMLAnchorsAliases limits YAML anchors/aliases to prevent billion laughs attack
	MaxYAMLAnchorsAliases = 10

	// MaxRegexRiskLevel is the maximum acceptable risk level for regex patterns
	// Values: "low", "medium", "high", "critical"
	// We reject "high" and "critical" patterns to prevent ReDoS attacks
	MaxRegexRiskLevel = "medium"
)

// ValidSigmaLevels defines the allowed severity levels in SIGMA rules
var ValidSigmaLevels = map[string]bool{
	"informational": true,
	"low":           true,
	"medium":        true,
	"high":          true,
	"critical":      true,
}

// SigmaValidationError represents a SIGMA YAML validation error with context
type SigmaValidationError struct {
	Field   string // Field that failed validation
	Message string // Human-readable error message
	Err     error  // Underlying error (optional)
}

// Error implements the error interface
func (e *SigmaValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("SIGMA validation failed for field '%s': %s: %v", e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("SIGMA validation failed for field '%s': %s", e.Field, e.Message)
}

// Unwrap implements error unwrapping for errors.Is/As
func (e *SigmaValidationError) Unwrap() error {
	return e.Err
}

// ValidateSigmaYAML validates a SIGMA rule YAML string for security and correctness.
//
// Security validations:
//   - Size limit: Rejects payloads > 1MB to prevent memory exhaustion
//   - Depth check: Rejects YAML with > 50 nesting levels to prevent stack overflow
//   - Anchor/alias count: Rejects YAML with > 10 anchors to prevent billion laughs attack
//   - Regex validation: Analyzes all regex patterns for ReDoS vulnerabilities
//
// Structural validations:
//   - Required fields: title, detection
//   - Detection must contain 'condition' field
//   - Level field must be valid SIGMA severity (if present)
//
// Returns:
//   - parsed map[string]interface{}: The validated and parsed SIGMA rule structure
//   - error: Detailed validation error with context, or nil if valid
//
// Example usage:
//
//	parsed, err := ValidateSigmaYAML(yamlString)
//	if err != nil {
//	    return fmt.Errorf("invalid SIGMA rule: %w", err)
//	}
//	title := parsed["title"].(string)
func ValidateSigmaYAML(yamlData string) (map[string]interface{}, error) {
	// Input validation: Check for empty input
	trimmed := strings.TrimSpace(yamlData)
	if trimmed == "" {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: "YAML data is empty",
		}
	}

	// Security check 1: Size limit to prevent memory exhaustion
	if len(yamlData) > MaxSigmaYAMLSize {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: fmt.Sprintf("YAML size (%d bytes) exceeds maximum allowed size (%d bytes)", len(yamlData), MaxSigmaYAMLSize),
		}
	}

	// Security check 2: Anchor/alias count to prevent billion laughs attack
	anchorCount := countAnchorsAliases(yamlData)
	if anchorCount > MaxYAMLAnchorsAliases {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: fmt.Sprintf("YAML contains too many anchors/aliases (%d), maximum allowed is %d (possible billion laughs attack)", anchorCount, MaxYAMLAnchorsAliases),
		}
	}

	// Parse YAML into intermediate node structure for depth checking
	var rootNode yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &rootNode); err != nil {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: "failed to parse YAML",
			Err:     err,
		}
	}

	// Security check 3: Depth limit to prevent stack overflow
	depth := checkYAMLDepth(&rootNode, 0)
	if depth > MaxYAMLDepth {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: fmt.Sprintf("YAML nesting depth (%d) exceeds maximum allowed depth (%d)", depth, MaxYAMLDepth),
		}
	}

	// Parse YAML into map structure for field validation
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlData), &parsed); err != nil {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: "failed to parse YAML into map structure",
			Err:     err,
		}
	}

	// Handle nil parsed result (shouldn't happen after successful unmarshal, but defensive)
	if parsed == nil {
		return nil, &SigmaValidationError{
			Field:   "yaml",
			Message: "parsed YAML is nil",
		}
	}

	// Structural validation 1: Required field - title
	title, titleExists := parsed["title"]
	if !titleExists {
		return nil, &SigmaValidationError{
			Field:   "title",
			Message: "required field 'title' is missing",
		}
	}
	if title == nil || fmt.Sprintf("%v", title) == "" {
		return nil, &SigmaValidationError{
			Field:   "title",
			Message: "required field 'title' is empty",
		}
	}

	// Structural validation 2: Required field - detection
	detection, detectionExists := parsed["detection"]
	if !detectionExists {
		return nil, &SigmaValidationError{
			Field:   "detection",
			Message: "required field 'detection' is missing",
		}
	}

	// Detection must be a map
	detectionMap, ok := detection.(map[string]interface{})
	if !ok {
		return nil, &SigmaValidationError{
			Field:   "detection",
			Message: fmt.Sprintf("field 'detection' must be a map, got %T", detection),
		}
	}

	// Structural validation 3: Detection must have 'condition' field
	condition, conditionExists := detectionMap["condition"]
	if !conditionExists {
		return nil, &SigmaValidationError{
			Field:   "detection.condition",
			Message: "required field 'condition' is missing in detection block",
		}
	}
	if condition == nil || fmt.Sprintf("%v", condition) == "" {
		return nil, &SigmaValidationError{
			Field:   "detection.condition",
			Message: "field 'condition' in detection block is empty",
		}
	}

	// Structural validation 4: Level validation (optional field, but if present must be valid)
	if level, levelExists := parsed["level"]; levelExists {
		levelStr, ok := level.(string)
		if !ok {
			return nil, &SigmaValidationError{
				Field:   "level",
				Message: fmt.Sprintf("field 'level' must be a string, got %T", level),
			}
		}
		levelLower := strings.ToLower(strings.TrimSpace(levelStr))
		if !ValidSigmaLevels[levelLower] {
			validLevels := make([]string, 0, len(ValidSigmaLevels))
			for k := range ValidSigmaLevels {
				validLevels = append(validLevels, k)
			}
			return nil, &SigmaValidationError{
				Field:   "level",
				Message: fmt.Sprintf("invalid level '%s', must be one of: %s", levelStr, strings.Join(validLevels, ", ")),
			}
		}
	}

	// Security check 4: Validate regex patterns in detection block
	if err := validateDetectionRegexPatterns(detectionMap); err != nil {
		return nil, err // Already wrapped in SigmaValidationError
	}

	return parsed, nil
}

// checkYAMLDepth recursively calculates the maximum nesting depth of a YAML node tree.
// This prevents stack overflow attacks from deeply nested YAML structures.
//
// Parameters:
//   - node: The YAML node to analyze
//   - currentDepth: The current depth in the recursion (starts at 0)
//
// Returns:
//   - int: The maximum depth found in the node tree
func checkYAMLDepth(node *yaml.Node, currentDepth int) int {
	if node == nil {
		return currentDepth
	}

	// Integer overflow protection: if depth exceeds MaxYAMLDepth, return immediately
	// This prevents integer overflow attacks that could bypass depth limits
	if currentDepth >= MaxYAMLDepth {
		return MaxYAMLDepth + 1 // Signal exceeded limit without risking overflow
	}

	maxDepth := currentDepth

	// Recursively check all child nodes
	for _, child := range node.Content {
		depth := checkYAMLDepth(child, currentDepth+1)
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	return maxDepth
}

// countAnchorsAliases counts the number of YAML anchors (&) and aliases (*) in the YAML data.
// This prevents "billion laughs" attacks where repeated references exponentially expand.
//
// Parameters:
//   - yamlData: The raw YAML string to analyze
//
// Returns:
//   - int: The total count of anchors and aliases
func countAnchorsAliases(yamlData string) int {
	count := 0

	// Count anchors (&name) and aliases (*name)
	// This provides security against billion laughs attacks
	//
	// Escape handling:
	// - \& or \* → escaped, NOT counted (single backslash escapes next char)
	// - \\& or \\* → backslash escapes backslash, & or * IS counted
	// - Escapes only apply within quoted strings in standard YAML
	//
	// Note: We use a conservative approach - count ALL unquoted & and * chars
	// even if some might be in contexts where they're not anchors/aliases.
	// This provides defense in depth (over-counting is safer than under-counting).
	inString := false
	stringChar := byte(0)
	i := 0

	for i < len(yamlData) {
		char := yamlData[i]

		// Track string boundaries (single or double quoted)
		// Only the matching quote char ends the string
		if !inString && (char == '"' || char == '\'') {
			inString = true
			stringChar = char
			i++
			continue
		}

		if inString {
			// Handle escape sequences ONLY inside strings
			if char == '\\' && i+1 < len(yamlData) {
				// Skip the escaped character (could be \\, \", \', etc.)
				i += 2
				continue
			}
			// Check for end of string
			if char == stringChar {
				inString = false
				stringChar = 0
			}
			i++
			continue
		}

		// Outside strings: count anchors/aliases
		// Note: In unquoted YAML values, backslash is a literal character
		// (not an escape), so \& in unquoted context has a literal backslash
		// followed by an anchor. We count the & in this case (conservative).
		if char == '&' || char == '*' {
			count++
		}
		i++
	}

	return count
}

// validateDetectionRegexPatterns recursively walks the detection block and validates
// all regex patterns for ReDoS vulnerabilities.
//
// SIGMA regex patterns are identified by the "|re" modifier in YAML.
// Example:
//
//	detection:
//	  selection:
//	    fieldName|re: '(a+)+'  # This would be rejected as high risk
//
// Parameters:
//   - detection: The detection block from the SIGMA rule
//
// Returns:
//   - error: SigmaValidationError if any regex pattern is unsafe, nil otherwise
func validateDetectionRegexPatterns(detection map[string]interface{}) error {
	// Recursively walk the detection block looking for fields with |re modifier
	for key, value := range detection {
		// Check if this is a regex field (ends with "|re")
		if strings.HasSuffix(key, "|re") {
			// Validate the regex pattern
			if err := validateRegexValue(key, value); err != nil {
				return err // Already wrapped in SigmaValidationError
			}
		}

		// Recursively check nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			if err := validateDetectionRegexPatterns(nestedMap); err != nil {
				return err
			}
		}

		// Recursively check arrays (slices)
		if slice, ok := value.([]interface{}); ok {
			for _, item := range slice {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if err := validateDetectionRegexPatterns(itemMap); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// validateRegexValue validates a single regex pattern value from the detection block.
// Handles both string patterns and arrays of patterns.
//
// Parameters:
//   - fieldName: The field name for error reporting
//   - value: The regex pattern(s) to validate
//
// Returns:
//   - error: SigmaValidationError if pattern is unsafe, nil otherwise
func validateRegexValue(fieldName string, value interface{}) error {
	switch v := value.(type) {
	case string:
		// Single regex pattern
		return validateSingleRegex(fieldName, v)

	case []interface{}:
		// Array of regex patterns
		for i, item := range v {
			if pattern, ok := item.(string); ok {
				if err := validateSingleRegex(fmt.Sprintf("%s[%d]", fieldName, i), pattern); err != nil {
					return err
				}
			} else {
				return &SigmaValidationError{
					Field:   fmt.Sprintf("%s[%d]", fieldName, i),
					Message: fmt.Sprintf("regex pattern must be a string, got %T", item),
				}
			}
		}
		return nil

	default:
		return &SigmaValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("regex pattern must be a string or array of strings, got %T", value),
		}
	}
}

// validateSingleRegex validates a single regex pattern for ReDoS vulnerabilities.
// This is a simplified version of detect.AnalyzeRegexComplexity to avoid import cycles.
//
// Parameters:
//   - fieldName: The field name for error reporting
//   - pattern: The regex pattern to validate
//
// Returns:
//   - error: SigmaValidationError if pattern has high risk level, nil otherwise
func validateSingleRegex(fieldName string, pattern string) error {
	// Empty pattern is safe
	if pattern == "" {
		return nil
	}

	// Security limits for regex patterns
	const (
		maxRegexLength  = 1000
		maxNestingDepth = 3
		maxAlternations = 50
	)

	issues := []string{}
	riskLevel := "low"
	complexityScore := 0

	// Check 1: Pattern length
	if len(pattern) > maxRegexLength {
		issues = append(issues, fmt.Sprintf("pattern length (%d) exceeds maximum (%d)", len(pattern), maxRegexLength))
		riskLevel = "critical"
		complexityScore += 100
	}

	// Check 2: Nested quantifiers - catastrophic backtracking patterns
	hasNested, nestingDepth := detectNestedQuantifiers(pattern)
	if hasNested {
		if riskLevel == "low" {
			riskLevel = "high"
		}
		issues = append(issues, fmt.Sprintf("nested quantifiers detected (depth: %d) - potential ReDoS vulnerability", nestingDepth))
		complexityScore += 50 * nestingDepth
	} else if nestingDepth > maxNestingDepth {
		if riskLevel == "low" {
			riskLevel = "medium"
		}
		issues = append(issues, fmt.Sprintf("deep nesting (depth: %d) exceeds maximum (%d)", nestingDepth, maxNestingDepth))
		complexityScore += 20 * (nestingDepth - maxNestingDepth)
	}

	// Check 3: Excessive alternations
	altCount := strings.Count(pattern, "|")
	if altCount > maxAlternations {
		if riskLevel == "low" {
			riskLevel = "medium"
		}
		issues = append(issues, fmt.Sprintf("excessive alternations (%d) exceed maximum (%d)", altCount, maxAlternations))
		complexityScore += altCount - maxAlternations
	}

	// Check 4: Exponential repetition patterns
	if hasExponentialRepetition(pattern) {
		if riskLevel != "critical" {
			riskLevel = "high"
		}
		issues = append(issues, "exponential repetition pattern detected - potential ReDoS vulnerability")
		complexityScore += 40
	}

	// Check 5: Very large repetition ranges
	if hasLargeRepetitionRange(pattern) {
		if riskLevel == "low" {
			riskLevel = "medium"
		}
		issues = append(issues, "very large repetition range detected - potential performance issue")
		complexityScore += 15
	}

	// Determine final risk level based on complexity score
	// Thresholds based on ReDoS research:
	// - >100: Critical - patterns that can cause >1s delays
	// - 50-100: High - patterns that can cause 100ms-1s delays
	// - 20-50: Medium - patterns that can cause 10-100ms delays
	//
	// IMPORTANT: Only UPGRADE risk level, never downgrade.
	// Individual checks may set riskLevel directly (e.g., nested quantifiers → high),
	// and score-based assessment should only increase risk, not decrease it.
	riskLevels := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	currentRiskInt := riskLevels[riskLevel]

	var scoredRiskLevel string
	if complexityScore > 100 {
		scoredRiskLevel = "critical"
	} else if complexityScore > 50 {
		scoredRiskLevel = "high"
	} else if complexityScore > 20 {
		scoredRiskLevel = "medium"
	} else {
		scoredRiskLevel = "low"
	}

	// Use the higher of the two risk levels
	if riskLevels[scoredRiskLevel] > currentRiskInt {
		riskLevel = scoredRiskLevel
	}

	// Reject high and critical risk patterns
	if riskLevel == "high" || riskLevel == "critical" {
		issuesStr := strings.Join(issues, "; ")
		return &SigmaValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("regex pattern '%s' has %s risk level: %s", pattern, riskLevel, issuesStr),
		}
	}

	return nil
}

// detectNestedQuantifiers detects patterns like (a+)+, (a*)*, (a+)*, etc.
// These patterns can cause catastrophic backtracking (ReDoS).
// Returns (hasNested, maxDepth)
//
// Detection logic:
// - A "nested quantifier" is a quantified group that contains any quantifier
// - Example: (a+)+ → the group (...) has + quantifier, and contains a+ inside
// - This causes exponential backtracking on non-matching input
func detectNestedQuantifiers(pattern string) (bool, int) {
	maxDepth := 0
	depth := 0
	hasNested := false

	// Track if we've seen a quantifier at each depth level
	// quantifierAtDepth[d] = true if we've seen +, *, ?, or {n,m} at depth d
	quantifierAtDepth := make([]bool, 100) // Support up to 100 nesting levels

	i := 0
	for i < len(pattern) {
		char := pattern[i]

		// Handle escape sequences
		if char == '\\' && i+1 < len(pattern) {
			i += 2
			continue
		}

		switch char {
		case '(':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			// Reset quantifier tracking for this new depth
			if depth < len(quantifierAtDepth) {
				quantifierAtDepth[depth] = false
			}
		case ')':
			// Check if next character is a quantifier
			if i+1 < len(pattern) {
				next := pattern[i+1]
				if next == '+' || next == '*' || next == '?' || next == '{' {
					// This group has a quantifier
					// Check if there was ANY quantifier inside this group
					if depth > 0 && depth < len(quantifierAtDepth) && quantifierAtDepth[depth] {
						hasNested = true
					}
					// Also check nested groups (depth > 1 means we're inside another group)
					if depth > 1 {
						hasNested = true
					}
					// Skip the quantifier
					if next == '{' {
						// Skip the entire {n,m} pattern
						j := i + 2
						for j < len(pattern) && pattern[j] != '}' {
							j++
						}
						if j < len(pattern) {
							i = j
						}
					} else {
						i++ // Skip the quantifier char
					}
					// Mark parent depth as having a quantifier
					if depth > 1 && depth-1 < len(quantifierAtDepth) {
						quantifierAtDepth[depth-1] = true
					}
				}
			}
			depth--
		case '+', '*', '?':
			// Mark current depth as having a quantifier
			if depth > 0 && depth < len(quantifierAtDepth) {
				quantifierAtDepth[depth] = true
			}
			// Check for stacked quantifiers: ++, **, *+, +*, etc.
			if i > 0 {
				prev := pattern[i-1]
				if prev == '+' || prev == '*' || prev == '}' || prev == '?' {
					hasNested = true
				}
			}
		case '{':
			// Mark current depth as having a quantifier ({n,m} is a quantifier)
			if depth > 0 && depth < len(quantifierAtDepth) {
				quantifierAtDepth[depth] = true
			}
			// Check for {n,m} after groups
			if i > 0 && pattern[i-1] == ')' && depth >= 1 {
				hasNested = true
			}
			// Skip the entire {n,m} pattern
			j := i + 1
			for j < len(pattern) && pattern[j] != '}' {
				j++
			}
			if j < len(pattern) {
				i = j
			}
		}
		i++
	}

	return hasNested, maxDepth
}

// hasExponentialRepetition detects patterns that can cause exponential backtracking
func hasExponentialRepetition(pattern string) bool {
	// Known problematic patterns
	dangerousPatterns := []string{
		"(a+)+", "(a*)*", "(a+)*", "(a*)+",
		"(.*)+", "(.*)*", "(.+)+", "(.+)*",
		"(a|a)+", "(a|a)*",
	}

	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return true
		}
	}

	return false
}

// hasLargeRepetitionRange detects {n,m} patterns with very large values
func hasLargeRepetitionRange(pattern string) bool {
	i := 0
	for i < len(pattern) {
		if pattern[i] == '{' {
			// Parse the range
			j := i + 1
			start := 0
			end := -1

			// Read start number
			for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
				start = start*10 + int(pattern[j]-'0')
				j++
			}

			// Check if there's a comma
			if j < len(pattern) && pattern[j] == ',' {
				j++
				// Read end number (if present)
				if j < len(pattern) && pattern[j] == '}' {
					// {n,} - unbounded upper
					if start > 1000 {
						return true
					}
				} else {
					// Read end number
					for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
						if end == -1 {
							end = 0
						}
						end = end*10 + int(pattern[j]-'0')
						j++
					}
					if end > 1000 || (end-start) > 1000 {
						return true
					}
				}
			} else {
				// {n} - exact repetition
				if start > 1000 {
					return true
				}
			}
		}
		i++
	}

	return false
}
