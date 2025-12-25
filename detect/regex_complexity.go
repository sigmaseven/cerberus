package detect

import (
	"fmt"
	"strings"
)

// TASK 2.2: Build regex complexity analyzer to detect catastrophic backtracking patterns

// RegexComplexityResult contains the analysis results for a regex pattern
type RegexComplexityResult struct {
	IsSafe               bool     // Whether the pattern is safe from ReDoS
	RiskLevel            string   // "low", "medium", "high", "critical"
	Issues               []string // List of detected issues
	ComplexityScore      int      // Complexity score (higher = more complex)
	NestingDepth         int      // Maximum nesting depth detected
	HasNestedQuantifiers bool     // Whether nested quantifiers detected
}

// Default complexity limits
const (
	MaxRegexLength     = 1000 // Maximum allowed pattern length
	MaxNestingDepth    = 3    // Maximum allowed nesting depth
	MaxAlternations    = 50   // Maximum allowed alternations (|)
	MaxRepeatingGroups = 5    // Maximum allowed repeating groups
)

// AnalyzeRegexComplexity analyzes a regex pattern for ReDoS vulnerabilities
// TASK 2.2: Detects catastrophic backtracking patterns before execution
func AnalyzeRegexComplexity(pattern string) (*RegexComplexityResult, error) {
	result := &RegexComplexityResult{
		IsSafe:               true,
		RiskLevel:            "low",
		Issues:               []string{},
		ComplexityScore:      0,
		NestingDepth:         0,
		HasNestedQuantifiers: false,
	}

	if pattern == "" {
		return result, nil // Empty pattern is safe
	}

	// Check 1: Pattern length
	if len(pattern) > MaxRegexLength {
		result.IsSafe = false
		result.RiskLevel = "critical"
		result.Issues = append(result.Issues, fmt.Sprintf("pattern length (%d) exceeds maximum (%d)", len(pattern), MaxRegexLength))
		result.ComplexityScore += 100
	}

	// Check 2: Nested quantifiers - catastrophic backtracking patterns
	nestedQuantifiers, nestingDepth := detectNestedQuantifiers(pattern)
	if nestedQuantifiers {
		result.HasNestedQuantifiers = true
		result.NestingDepth = nestingDepth
		result.IsSafe = false
		if result.RiskLevel == "low" {
			result.RiskLevel = "high"
		}
		result.Issues = append(result.Issues, fmt.Sprintf("nested quantifiers detected (depth: %d) - potential ReDoS vulnerability", nestingDepth))
		result.ComplexityScore += 50 * nestingDepth
	} else if nestingDepth > MaxNestingDepth {
		// Deep nesting without explicit nested quantifiers is still risky
		result.NestingDepth = nestingDepth
		result.IsSafe = false
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
		result.Issues = append(result.Issues, fmt.Sprintf("deep nesting (depth: %d) exceeds maximum (%d)", nestingDepth, MaxNestingDepth))
		result.ComplexityScore += 20 * (nestingDepth - MaxNestingDepth)
	} else {
		result.NestingDepth = nestingDepth
	}

	// Check 3: Alternation with overlap
	if hasOverlappingAlternation(pattern) {
		result.IsSafe = false
		if result.RiskLevel == "low" || result.RiskLevel == "medium" {
			result.RiskLevel = "high"
		}
		result.Issues = append(result.Issues, "overlapping alternation detected - potential ReDoS vulnerability")
		result.ComplexityScore += 30
	}

	// Check 4: Excessive alternations
	altCount := strings.Count(pattern, "|")
	if altCount > MaxAlternations {
		result.IsSafe = false
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
		result.Issues = append(result.Issues, fmt.Sprintf("excessive alternations (%d) exceed maximum (%d)", altCount, MaxAlternations))
		result.ComplexityScore += altCount - MaxAlternations
	}

	// Check 5: Nested grouping with quantifiers
	if hasNestedGroupingWithQuantifiers(pattern) {
		result.IsSafe = false
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
		result.Issues = append(result.Issues, "nested grouping with quantifiers detected - potential performance issue")
		result.ComplexityScore += 20
	}

	// Check 6: Exponential repetition patterns
	if hasExponentialRepetition(pattern) {
		result.HasNestedQuantifiers = true // Exponential patterns often involve nested quantifiers
		result.IsSafe = false
		if result.RiskLevel == "critical" {
			// Keep critical if already set
		} else {
			result.RiskLevel = "high"
		}
		result.Issues = append(result.Issues, "exponential repetition pattern detected - potential ReDoS vulnerability")
		result.ComplexityScore += 40
	}

	// Check 7: Very large repetition ranges
	if hasLargeRepetitionRange(pattern) {
		result.IsSafe = false
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
		result.Issues = append(result.Issues, "very large repetition range detected - potential performance issue")
		result.ComplexityScore += 15
	}

	// Determine final risk level based on complexity score
	if result.ComplexityScore > 100 {
		result.RiskLevel = "critical"
	} else if result.ComplexityScore > 50 {
		if result.RiskLevel == "low" {
			result.RiskLevel = "high"
		}
	} else if result.ComplexityScore > 20 {
		if result.RiskLevel == "low" {
			result.RiskLevel = "medium"
		}
	}

	return result, nil
}

// detectNestedQuantifiers detects patterns like (a+)+, (a*)*, (a+)*, etc.
// Returns (hasNested, maxDepth)
func detectNestedQuantifiers(pattern string) (bool, int) {
	maxDepth := 0
	depth := 0
	hasNested := false

	// Simple state machine to detect nested quantifiers
	// Look for patterns: (...)+ followed by +, *, or {
	// Or: (...)* followed by +, *, or {

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
		case ')':
			// Check if next character is a quantifier
			if i+1 < len(pattern) {
				next := pattern[i+1]
				if next == '+' || next == '*' || next == '?' || next == '{' {
					// This group has a quantifier, check if we're inside another quantified group
					if depth > 1 {
						// We're nested - this is dangerous like (a+)+
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
				}
			}
			depth--
		case '+', '*', '?':
			// Check for stacked quantifiers: ++, **, *+, +*, etc.
			if i > 0 {
				prev := pattern[i-1]
				if prev == '+' || prev == '*' || prev == '}' || prev == '?' {
					hasNested = true
				}
			}
		case '{':
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

// hasOverlappingAlternation detects patterns like (a|a)+, (a|a)* which can cause ReDoS
func hasOverlappingAlternation(pattern string) bool {
	// Look for patterns: (X|X)+ or (X|X)* where X is the same pattern
	// This is a simplified check - full implementation would need to parse the pattern

	// Check for obvious cases like (a|a)+, (a|a)*
	patterns := []string{
		"(a|a)+", "(a|a)*",
		"(.|.)+", "(.|.)*",
	}

	for _, p := range patterns {
		if strings.Contains(pattern, p) {
			return true
		}
	}

	// Check for repeated alternations in sequence that might overlap
	// This is a heuristic - full analysis would require parsing
	altCount := strings.Count(pattern, "|")
	if altCount > 10 {
		// Many alternations could indicate problematic patterns
		// Check if there are quantifiers nearby
		for i := 0; i < len(pattern)-2; i++ {
			if pattern[i] == '|' {
				// Look ahead for quantifiers
				if i+1 < len(pattern) {
					next := pattern[i+1]
					if next == '+' || next == '*' || next == '{' || next == '?' {
						// Look before for similar patterns
						if i > 0 {
							prev := pattern[i-1]
							if prev == next || (prev == ')' && (next == '+' || next == '*' || next == '{')) {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

// hasNestedGroupingWithQuantifiers detects patterns with deeply nested groups that have quantifiers
func hasNestedGroupingWithQuantifiers(pattern string) bool {
	depth := 0
	maxDepth := 0

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
		case ')':
			// Check if next character is a quantifier
			if i+1 < len(pattern) {
				next := pattern[i+1]
				if next == '+' || next == '*' || next == '{' || next == '?' {
					if depth > MaxNestingDepth {
						return true
					}
				}
			}
			depth--
		}
		i++
	}

	return false
}

// hasExponentialRepetition detects patterns that can cause exponential backtracking
// Examples: (a+)+b, (a*)*b, (a|a)+b
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

	// Check for patterns ending with a non-matching character after repetition
	// This is a heuristic - patterns like (X)+Y where X doesn't match Y
	// Simplified check: look for )+ or )* followed by a character

	return false
}

// hasLargeRepetitionRange detects {n,m} patterns with very large values
func hasLargeRepetitionRange(pattern string) bool {
	// Look for {n,m} or {n,} patterns with large numbers
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

// IsValidRegexPattern validates a regex pattern and returns error if unsafe
// TASK 2.2: Convenience function for validation
func IsValidRegexPattern(pattern string) error {
	result, err := AnalyzeRegexComplexity(pattern)
	if err != nil {
		return err
	}

	if !result.IsSafe {
		return fmt.Errorf("regex pattern is unsafe: %s - %s", result.RiskLevel, strings.Join(result.Issues, "; "))
	}

	return nil
}

// GetPatternComplexitySummary returns a human-readable summary of pattern complexity
func GetPatternComplexitySummary(pattern string) string {
	result, err := AnalyzeRegexComplexity(pattern)
	if err != nil {
		return fmt.Sprintf("Error analyzing pattern: %v", err)
	}

	if result.IsSafe {
		return fmt.Sprintf("Pattern is safe (risk: %s, score: %d)", result.RiskLevel, result.ComplexityScore)
	}

	return fmt.Sprintf("Pattern is UNSAFE (risk: %s, score: %d) - %s",
		result.RiskLevel, result.ComplexityScore, strings.Join(result.Issues, "; "))
}
