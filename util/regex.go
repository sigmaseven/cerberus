package util

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// analyzeRegexComplexity performs comprehensive complexity analysis on regex patterns
func AnalyzeRegexComplexity(pattern string) error {
	// Implement graduated complexity limits instead of blanket bans
	// Allow bounded quantifiers while preventing unbounded ones to balance security and functionality

	// Define allowed character set - allow bounded quantifiers but not unbounded ones
	// Allow: {min,max} bounded ranges, prevent: *, +, ?, {min,} unbounded ranges
	// Include alternation (|), optional (?), and other valid regex constructs
	safeRegex := regexp.MustCompile(`^[\w\s\.\-\[\]\^\$\\\{\}\,\d\|\?\(\)]+$`)

	// Check if pattern matches allowed character set first
	if !safeRegex.MatchString(pattern) {
		return fmt.Errorf("regex pattern contains unsafe characters or constructs")
	}

	// Check for dangerous unbounded quantifiers
	dangerousQuantifiers := []string{"*", "+", "?"}
	for _, quantifier := range dangerousQuantifiers {
		if strings.Contains(pattern, quantifier) {
			return fmt.Errorf("regex pattern contains unbounded quantifier '%s' - use bounded quantifiers like {1,10} instead", quantifier)
		}
	}

	// Check for unbounded range quantifiers (e.g., {1,})
	unboundedRangeRegex := regexp.MustCompile(`\{\d+,\s*\}`)
	if unboundedRangeRegex.MatchString(pattern) {
		return fmt.Errorf("regex pattern contains unbounded range quantifier - use bounded ranges like {1,10}")
	}

	// Analyze bounded quantifiers for complexity limits
	boundedQuantifierRegex := regexp.MustCompile(`\{(\d+),(\d+)\}`)
	matches := boundedQuantifierRegex.FindAllStringSubmatch(pattern, -1)

	totalRepetitionComplexity := 0
	for _, match := range matches {
		if len(match) >= 3 {
			min, err1 := strconv.Atoi(match[1])
			max, err2 := strconv.Atoi(match[2])
			if err1 == nil && err2 == nil {
				// Calculate complexity as the maximum possible repetitions
				repetitions := max - min + 1
				totalRepetitionComplexity += repetitions

				// Individual quantifier limits
				if max > 100 { // Maximum 100 repetitions per quantifier
					return fmt.Errorf("quantifier {min,max} exceeds maximum allowed repetitions (100): {%d,%d}", min, max)
				}
				if repetitions > 50 { // Maximum span of 50 per quantifier
					return fmt.Errorf("quantifier span too large: {%d,%d} (max span 50)", min, max)
				}
			}
		}
	}

	// Overall complexity limit based on total repetitions
	if totalRepetitionComplexity > 200 { // Total complexity limit
		return fmt.Errorf("regex pattern too complex: total repetition complexity %d exceeds limit of 200", totalRepetitionComplexity)
	}

	// Enhanced dangerous pattern detection
	dangerousPatterns := []string{
		// Backreferences (not supported in some contexts, but dangerous)
		"\\1", "\\2", "\\3", "\\4", "\\5", "\\6", "\\7", "\\8", "\\9",
		// Lookbehinds/lookaheads (can be complex and cause issues)
		"(?<=", "(?<!", "(?=", "(?!",
		// Atomic groups (advanced features that can be abused)
		"(?>",
		// Recursive patterns
		"(?&", "(?R",
		// Conditional patterns
		"(?(", "(?<",
		// Complex character classes that could be abused
		"[^", // Negated character classes can be complex
	}

	// Check for dangerous constructs
	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return fmt.Errorf("regex pattern contains potentially dangerous construct: %s", dangerous)
		}
	}

	// Strict nesting depth check to prevent stack overflow
	nestingDepth := 0
	maxNesting := 0
	groupCount := 0
	for _, char := range pattern {
		switch char {
		case '(':
			nestingDepth++
			groupCount++
			if nestingDepth > maxNesting {
				maxNesting = nestingDepth
			}
			if nestingDepth > 3 { // Very strict nesting limit
				return fmt.Errorf("regex pattern has excessive nesting depth: %d", nestingDepth)
			}
		case ')':
			nestingDepth--
			if nestingDepth < 0 {
				return fmt.Errorf("regex pattern has unmatched parentheses")
			}
		}
	}
	if nestingDepth != 0 {
		return fmt.Errorf("regex pattern has unmatched parentheses")
	}
	if groupCount > 5 { // Limit total number of groups
		return fmt.Errorf("regex pattern has too many groups: %d", groupCount)
	}

	// Strict pattern length limit
	if len(pattern) > 200 { // Very conservative length limit
		return fmt.Errorf("regex pattern too long: %d characters (max 200)", len(pattern))
	}

	// Additional safety: limit alternation complexity
	alternationCount := strings.Count(pattern, "|")
	if alternationCount > 5 {
		return fmt.Errorf("regex pattern has too many alternations: %d (max 5)", alternationCount)
	}

	return nil
}
