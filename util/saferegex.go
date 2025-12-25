package util

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Constants for regex validation
const (
	// MaxRegexLength is the maximum allowed regex pattern length
	MaxRegexLength = 500
	// DefaultRegexTimeout is the default timeout for regex matching
	DefaultRegexTimeout = 100 * time.Millisecond
	// MaxRegexTimeout is the maximum allowed timeout for regex matching
	MaxRegexTimeout = 1 * time.Second
)

// RegexValidator validates and compiles regex patterns with safety checks
// TASK 51.2: RegexValidator with complexity validation and length limits
type RegexValidator struct {
	maxLength int
}

// NewRegexValidator creates a new RegexValidator with default settings
func NewRegexValidator() *RegexValidator {
	return &RegexValidator{
		maxLength: MaxRegexLength,
	}
}

// NewRegexValidatorWithTimeout creates a new RegexValidator with custom timeout
// Note: Timeout parameter is deprecated and ignored (Go regexp doesn't support timeout during compilation)
func NewRegexValidatorWithTimeout(timeout time.Duration) *RegexValidator {
	// Timeout parameter is ignored - timeout is applied during matching, not compilation
	return &RegexValidator{
		maxLength: MaxRegexLength,
	}
}

// ValidatePattern validates a regex pattern for safety
func (rv *RegexValidator) ValidatePattern(pattern string) error {
	// Check empty pattern
	if pattern == "" {
		return fmt.Errorf("regex pattern cannot be empty")
	}

	// Check length
	if len(pattern) > rv.maxLength {
		return fmt.Errorf("regex pattern too long: %d characters (max %d)", len(pattern), rv.maxLength)
	}

	// Check for nested quantifiers (ReDoS patterns)
	if err := rv.checkForReDoSPatterns(pattern); err != nil {
		return err
	}

	// Check for excessive alternations
	if alternationCount := strings.Count(pattern, "|"); alternationCount > 50 {
		return fmt.Errorf("too many alternations: %d (max 50)", alternationCount)
	}

	// Check for excessive repetition
	if err := rv.checkForExcessiveRepetition(pattern); err != nil {
		return err
	}

	// Validate syntax by attempting to compile
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	return nil
}

// checkForReDoSPatterns checks for dangerous nested quantifier patterns
func (rv *RegexValidator) checkForReDoSPatterns(pattern string) error {
	dangerousPatterns := []string{
		")+*", ")*+", ")+{", ")*{",
		"}+*", "}*+", "}+{", "}*{",
		"++", "**", "*+", "+*",
	}

	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return fmt.Errorf("pattern contains nested quantifiers which may cause ReDoS: found '%s'", dangerous)
		}
	}

	return nil
}

// checkForExcessiveRepetition checks for repetition ranges exceeding 1000
func (rv *RegexValidator) checkForExcessiveRepetition(pattern string) error {
	// Look for patterns like {1000}, {1001}, etc.
	repetitionRe := regexp.MustCompile(`\{(\d+)(?:,\d*)?\}`)
	matches := repetitionRe.FindAllStringSubmatch(pattern, -1)

	for _, match := range matches {
		if len(match) > 1 {
			// Check if the repetition count is >= 1000
			// For patterns like {n}, {n,}, {n,m}, we check n
			var count int
			fmt.Sscanf(match[1], "%d", &count)
			if count >= 1000 {
				return fmt.Errorf("excessive repetition: %s (max 999)", match[0])
			}
		}
	}

	return nil
}

// Compile compiles a regex pattern after validation
func (rv *RegexValidator) Compile(pattern string) (*regexp.Regexp, error) {
	if err := rv.ValidatePattern(pattern); err != nil {
		return nil, err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	return re, nil
}

// CompileWithTimeout compiles a regex pattern (timeout parameter is deprecated)
func (rv *RegexValidator) CompileWithTimeout(pattern string, timeout time.Duration) (*regexp.Regexp, error) {
	// Timeout is ignored - it's applied during matching, not compilation
	return rv.Compile(pattern)
}

// ValidateComplexity validates a regex pattern for dangerous constructs that could lead to ReDoS
// TASK 32.2: Complexity validation to reject dangerous patterns before execution
func ValidateComplexity(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("regex pattern cannot be empty")
	}

	// Check for nested quantifiers: (a*)*, (a+)+, (a?)?, etc.
	// These can cause catastrophic backtracking
	nestedQuantifierPatterns := []string{
		`\([^)]*\*\)\*`,        // (something*)*
		`\([^)]*\+\)\+`,        // (something+)+
		`\([^)]*\?\)\?`,        // (something?)?
		`\([^)]*\{[^}]*\}\)\{`, // (something{...}){...}
	}

	for _, dangerousPattern := range nestedQuantifierPatterns {
		re, err := regexp.Compile(dangerousPattern)
		if err != nil {
			continue // Skip if pattern doesn't compile
		}
		if re.MatchString(pattern) {
			return fmt.Errorf("pattern contains nested quantifiers which may cause ReDoS: %s", pattern)
		}
	}

	// Check for excessive nesting depth (max 3 levels)
	nestingDepth := 0
	maxNesting := 0
	for _, char := range pattern {
		switch char {
		case '(':
			nestingDepth++
			if nestingDepth > maxNesting {
				maxNesting = nestingDepth
			}
			if nestingDepth > 3 {
				return fmt.Errorf("pattern has excessive nesting depth: %d (max 3)", nestingDepth)
			}
		case ')':
			nestingDepth--
			if nestingDepth < 0 {
				return fmt.Errorf("pattern has unmatched closing parenthesis")
			}
		}
	}

	if nestingDepth != 0 {
		return fmt.Errorf("pattern has unmatched parentheses")
	}

	return nil
}

// CompileSafe compiles a regex pattern with complexity validation
// TASK 32.2: Safe regex compilation with complexity checks
func CompileSafe(pattern string) (*regexp.Regexp, error) {
	// Validate complexity first
	if err := ValidateComplexity(pattern); err != nil {
		return nil, fmt.Errorf("complexity validation failed: %w", err)
	}

	// Compile the pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	return re, nil
}

// AnalyzePattern provides a complexity report for a regex pattern
// TASK 32.2: Optional complexity analysis for diagnostics
type ComplexityReport struct {
	Pattern              string
	Length               int
	NestingDepth         int
	HasNestedQuantifiers bool
	QuantifierCount      int
	AlternationCount     int
	IsSafe               bool
	Warnings             []string
}

// AnalyzePattern analyzes a regex pattern and returns a complexity report
func AnalyzePattern(pattern string) ComplexityReport {
	report := ComplexityReport{
		Pattern:  pattern,
		Length:   len(pattern),
		Warnings: []string{},
	}

	// Count nesting depth
	nestingDepth := 0
	maxNesting := 0
	quantifierCount := 0
	alternationCount := strings.Count(pattern, "|")

	for _, char := range pattern {
		switch char {
		case '(':
			nestingDepth++
			if nestingDepth > maxNesting {
				maxNesting = nestingDepth
			}
		case ')':
			nestingDepth--
		case '*', '+', '?':
			quantifierCount++
		}
	}

	report.NestingDepth = maxNesting
	report.QuantifierCount = quantifierCount
	report.AlternationCount = alternationCount

	// Check for nested quantifiers
	hasNestedQuantifiers := false
	for _, dangerousPattern := range []string{
		`\([^)]*\*\)\*`,
		`\([^)]*\+\)\+`,
		`\([^)]*\?\)\?`,
	} {
		re, err := regexp.Compile(dangerousPattern)
		if err == nil && re.MatchString(pattern) {
			hasNestedQuantifiers = true
			report.Warnings = append(report.Warnings, "contains nested quantifiers")
			break
		}
	}

	report.HasNestedQuantifiers = hasNestedQuantifiers

	// Determine if pattern is safe
	report.IsSafe = !hasNestedQuantifiers && maxNesting <= 3 && len(pattern) <= 200

	if maxNesting > 3 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("excessive nesting depth: %d", maxNesting))
	}

	if len(pattern) > 200 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("pattern too long: %d characters", len(pattern)))
	}

	return report
}

// RegexWithTimeout matches a pattern against input with a timeout using goroutines
// TASK 32.1: Timeout wrapper using context.WithTimeout() and goroutines
// This provides ReDoS protection by enforcing a maximum execution time for regex matching
func RegexWithTimeout(pattern, input string, timeout time.Duration) (bool, error) {
	if pattern == "" {
		return false, fmt.Errorf("regex pattern cannot be empty")
	}

	if timeout <= 0 {
		return false, fmt.Errorf("timeout must be positive, got: %v", timeout)
	}

	// Compile the regex pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Channel to receive match result
	resultCh := make(chan bool, 1)
	// Channel to receive error
	errCh := make(chan error, 1)

	// Execute regex matching in goroutine
	go func() {
		defer func() {
			// Recover from any panic during regex matching
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("regex matching panic: %v", r)
			}
		}()
		match := re.MatchString(input)
		resultCh <- match
	}()

	// Wait for result or timeout
	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return false, err
	case <-ctx.Done():
		// Timeout occurred
		return false, fmt.Errorf("regex timeout after %v", timeout)
	}
}

// MatchWithTimeout is an alias for RegexWithTimeout for backward compatibility
// TASK 32.1: Convenience function with same signature as task specification
func MatchWithTimeout(pattern, input string, timeout time.Duration) (bool, error) {
	return RegexWithTimeout(pattern, input, timeout)
}

// SafeCompile is a convenience function that compiles a regex pattern with validation
func SafeCompile(pattern string) (*regexp.Regexp, error) {
	validator := NewRegexValidator()
	return validator.Compile(pattern)
}

// ValidateRegexPattern is a convenience function that validates a regex pattern
func ValidateRegexPattern(pattern string) error {
	validator := NewRegexValidator()
	return validator.ValidatePattern(pattern)
}

// EscapeUserInput escapes regex metacharacters in user input to make it safe for literal matching
func EscapeUserInput(input string) string {
	return regexp.QuoteMeta(input)
}
