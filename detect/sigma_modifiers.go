package detect

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Error definitions for modifier processing
var (
	// ErrUnsupportedModifier is returned when a modifier is not supported by Cerberus
	ErrUnsupportedModifier = errors.New("unsupported modifier")
)

// UnsupportedModifierError provides context for unsupported modifiers
type UnsupportedModifierError struct {
	Modifier string
	Reason   string
}

func (e *UnsupportedModifierError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("unsupported modifier '%s': %s", e.Modifier, e.Reason)
	}
	return fmt.Sprintf("unsupported modifier '%s'", e.Modifier)
}

func (e *UnsupportedModifierError) Unwrap() error {
	return ErrUnsupportedModifier
}

// Supported SIGMA modifiers as constants for validation and documentation
const (
	// Transform modifiers - applied to values before comparison
	ModifierBase64       = "base64"
	ModifierBase64Offset = "base64offset"
	ModifierUTF16LE      = "utf16le"
	ModifierUTF16BE      = "utf16be"
	ModifierWide         = "wide"
	ModifierWindash      = "windash"

	// Comparison modifiers - determine the comparison operation
	ModifierContains   = "contains"
	ModifierStartsWith = "startswith"
	ModifierEndsWith   = "endswith"
	ModifierRegex      = "re"
	ModifierCIDR       = "cidr"

	// Numeric comparison modifiers
	ModifierGreaterThan        = "gt"
	ModifierGreaterThanOrEqual = "gte"
	ModifierLessThan           = "lt"
	ModifierLessThanOrEqual    = "lte"

	// Logic modifiers - control list matching behavior
	ModifierAll = "all"

	// Default comparison operator when no comparison modifier specified
	DefaultOperator = "equals"
)

// transformModifiers is the set of modifiers that transform values before comparison
var transformModifiers = map[string]bool{
	ModifierBase64:       true,
	ModifierBase64Offset: true,
	ModifierUTF16LE:      true,
	ModifierUTF16BE:      true,
	ModifierWide:         true,
	ModifierWindash:      true,
}

// comparisonModifiers is the set of modifiers that specify comparison operations
var comparisonModifiers = map[string]bool{
	ModifierContains:           true,
	ModifierStartsWith:         true,
	ModifierEndsWith:           true,
	ModifierRegex:              true,
	ModifierCIDR:               true,
	ModifierGreaterThan:        true,
	ModifierGreaterThanOrEqual: true,
	ModifierLessThan:           true,
	ModifierLessThanOrEqual:    true,
}

// Regex safety limits to prevent DoS attacks during pattern compilation
const (
	// maxRegexPatternLength limits pattern string length to prevent memory exhaustion
	// during compilation. 10KB is sufficient for any legitimate SIGMA pattern.
	maxRegexPatternLength = 10000

	// maxRegexQuantifier limits {n,m} quantifier values to prevent slow compilation.
	// Even with RE2's O(n) matching, compilation of patterns like (a|b){1000000}
	// can take significant time and memory.
	maxRegexQuantifier = 1000

	// maxRegexInputSize limits input string size for regex matching.
	// Prevents memory exhaustion when matching against large decoded data.
	// 1MB is generous for any legitimate event field value.
	maxRegexInputSize = 1 * 1024 * 1024
)

// quantifierRegex is pre-compiled regex for validating quantifier values.
// Matches patterns like {5}, {5,}, {5,10}, {,10}
var quantifierRegex = regexp.MustCompile(`\{(\d+)(?:,(\d*))?\}`)

// windowsDashReplacer is a cached replacer for normalizing Unicode dashes to ASCII hyphen.
// Created once at package initialization to avoid allocation overhead on every call.
// This is critical for SIEM performance where events are processed at high throughput.
var windowsDashReplacer = strings.NewReplacer(
	"\u2010", "-", // HYPHEN
	"\u2011", "-", // NON-BREAKING HYPHEN
	"\u2012", "-", // FIGURE DASH
	"\u2013", "-", // EN DASH
	"\u2014", "-", // EM DASH
	"\u2015", "-", // HORIZONTAL BAR
	"\u2212", "-", // MINUS SIGN
)

// validateRegexPattern validates a regex pattern for safety before compilation.
// This prevents DoS attacks via expensive compilation of malicious patterns.
//
// Validation Rules:
//   - Pattern length must not exceed maxRegexPatternLength (10KB)
//   - Quantifier values {n,m} must not exceed maxRegexQuantifier (1000)
//
// Parameters:
//   - pattern: The regex pattern to validate
//
// Returns:
//   - error: Validation error if pattern is unsafe, nil if valid
func validateRegexPattern(pattern string) error {
	// Check pattern length
	if len(pattern) > maxRegexPatternLength {
		return fmt.Errorf("regex pattern too long: %d bytes (max %d)", len(pattern), maxRegexPatternLength)
	}

	// Check quantifier values {n}, {n,}, {n,m}
	matches := quantifierRegex.FindAllStringSubmatch(pattern, -1)
	for _, match := range matches {
		// match[1] is the first number (required)
		if len(match) > 1 && match[1] != "" {
			n, err := strconv.Atoi(match[1])
			if err == nil && n > maxRegexQuantifier {
				return fmt.Errorf("regex quantifier too large: {%d} exceeds max %d", n, maxRegexQuantifier)
			}
		}
		// match[2] is the second number (optional, after comma)
		if len(match) > 2 && match[2] != "" {
			m, err := strconv.Atoi(match[2])
			if err == nil && m > maxRegexQuantifier {
				return fmt.Errorf("regex quantifier too large: {,%d} exceeds max %d", m, maxRegexQuantifier)
			}
		}
	}

	return nil
}

// regexCache provides thread-safe caching of compiled regular expressions.
// This significantly improves performance when the same patterns are used repeatedly
// across multiple SIGMA rule evaluations.
//
// Thread-Safety Guarantees:
//   - All methods are safe for concurrent use
//   - Read operations (cache hit) use RLock, allowing concurrent reads
//   - Write operations (cache miss) use Lock, serializing writes
//   - Local copies prevent stale reads after RUnlock
//
// Performance Characteristics:
//   - Cache hit: O(1) with RLock (< 1μs latency, concurrent reads allowed)
//   - Cache miss: O(pattern_complexity) compilation + O(1) cache write
//   - Eviction: O(1) random eviction when cache reaches max size
//
// Memory Bounds:
//   - Maximum cached patterns: Configurable via max field (default: 1000)
//   - Memory per entry: ~500 bytes (pattern string) + regex automaton size
//   - Total memory bound: ~500KB + (max * average_regex_size)
//
// Note on ReDoS Safety:
//   - Go's regexp package uses RE2/Thompson NFA algorithm, NOT Perl/PCRE
//   - This GUARANTEES O(n) matching time - no catastrophic backtracking possible
//   - Patterns like "(a+)+b" that cause ReDoS in Perl/PCRE are safe in Go
//   - Pattern validation (validateRegexPattern) prevents compilation DoS
type regexCache struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
	max   int
}

// defaultRegexCacheSize balances memory usage vs. hit rate for typical SIGMA deployments:
//   - 100-500 active SIGMA rules is typical
//   - Each rule may have 1-5 regex patterns
//   - 1000 entries = ~500KB memory (500 bytes/pattern avg)
//   - Allows 2x headroom for rule diversity
const defaultRegexCacheSize = 1000

// defaultRegexCache is the package-level regex cache instance.
var defaultRegexCache = &regexCache{
	cache: make(map[string]*regexp.Regexp),
	max:   defaultRegexCacheSize,
}

// get retrieves a compiled regex from the cache or compiles and caches it.
// This method is thread-safe and uses optimistic locking for better concurrency.
//
// The method validates pattern safety before compilation to prevent DoS attacks.
//
// Parameters:
//   - pattern: The regex pattern to compile
//
// Returns:
//   - *regexp.Regexp: Compiled regex (never nil if error is nil)
//   - error: Validation or compilation error if pattern is invalid/unsafe
func (c *regexCache) get(pattern string) (*regexp.Regexp, error) {
	// Validate pattern safety BEFORE any caching operations
	if err := validateRegexPattern(pattern); err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Fast path: check cache with read lock (allows concurrent reads)
	// We take a LOCAL COPY of the regex pointer while holding the lock
	c.mu.RLock()
	re := c.cache[pattern] // Local copy is safe after RUnlock
	c.mu.RUnlock()

	// Check local copy - safe from concurrent eviction since we copied the pointer
	if re != nil {
		return re, nil
	}

	// Slow path: compile OUTSIDE lock to minimize lock contention
	// This is safe because regexp.Compile is pure (no global state)
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine may have cached it while we were compiling
	// This prevents redundant cache entries
	if existing := c.cache[pattern]; existing != nil {
		return existing, nil
	}

	// Evict random entry if at capacity
	// Random eviction is acceptable for SIEM workload where patterns are reused
	// within short time windows (detection rule evaluation batches)
	if len(c.cache) >= c.max {
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}

	c.cache[pattern] = compiled
	return compiled, nil
}

// ModifierEvaluator handles SIGMA modifier evaluation with configurable timeouts
// for ReDoS protection. It implements the SIGMA specification for value
// transformation and comparison operations.
type ModifierEvaluator struct {
	regexTimeout time.Duration // Timeout for regex operations to prevent ReDoS attacks
}

// NewModifierEvaluator creates a new ModifierEvaluator with the specified timeout
// for regex operations. The timeout is used to prevent ReDoS (Regular Expression
// Denial of Service) attacks.
//
// Parameters:
//   - timeout: Maximum duration for regex matching operations
//
// Returns:
//   - *ModifierEvaluator: Configured evaluator instance
func NewModifierEvaluator(timeout time.Duration) *ModifierEvaluator {
	return &ModifierEvaluator{
		regexTimeout: timeout,
	}
}

// EvaluateWithModifiers evaluates a value against a pattern with SIGMA modifiers.
// It implements the SIGMA specification for modifier processing:
//
//  1. Parse modifiers to identify transform vs comparison types
//  2. Apply transform modifiers to the value (base64, utf16*, wide, windash)
//  3. Determine comparison operator from modifiers (contains, re, cidr, etc.)
//  4. Handle 'all' modifier flag for list matching (ALL vs ANY semantics)
//  5. Support list patterns with OR logic (any match) or AND logic (all match)
//  6. Perform final comparison using the selected operator
//
// Parameters:
//   - value: The value to evaluate (can be single value or list)
//   - pattern: The pattern to match against (can be single value or list)
//   - modifiers: List of SIGMA modifiers to apply
//
// Returns:
//   - bool: True if the value matches the pattern with modifiers applied
//   - error: Error if modifier validation fails or comparison encounters issues
//
// Modifier Semantics:
//   - Transform modifiers (base64, utf16le, etc.): Applied to value before comparison
//   - Comparison modifiers (contains, startswith, etc.): Define the comparison operation
//   - Logic modifier 'all': Changes list matching from OR (any) to AND (all)
//   - Default: When no comparison modifier specified, uses exact equality
//
// List Handling:
//   - Pattern as list: OR logic (match any) unless 'all' modifier present
//   - Value as list: Match if any value in list matches pattern
//   - Both as lists: Match if any value matches any pattern (OR), or all patterns match (AND with 'all')
//
// Examples:
//   - value="test", pattern="test", modifiers=[] → true (equals)
//   - value="testing", pattern="test", modifiers=["contains"] → true
//   - value="dGVzdA==", pattern="test", modifiers=["base64"] → true
//   - value="x", pattern=["a","b"], modifiers=[] → false (OR logic)
//   - value="x", pattern=["a","b"], modifiers=["all"] → false (AND logic)
func (m *ModifierEvaluator) EvaluateWithModifiers(value interface{}, pattern interface{}, modifiers []string) (bool, error) {
	// Step 1: Parse and validate modifiers
	transformMods, comparisonOp, useAllLogic, err := m.parseModifiers(modifiers)
	if err != nil {
		return false, fmt.Errorf("modifier parsing failed: %w", err)
	}

	// Step 2: Apply transform modifiers to the value
	transformedValue, err := m.applyTransformModifiers(value, transformMods)
	if err != nil {
		return false, fmt.Errorf("transform modifier application failed: %w", err)
	}

	// Step 3-6: Handle list matching with appropriate logic (OR/AND)
	match, err := m.evaluateWithOperator(transformedValue, pattern, comparisonOp, useAllLogic)
	if err != nil {
		return false, fmt.Errorf("comparison failed: %w", err)
	}

	return match, nil
}

// parseModifiers separates modifiers into transform, comparison, and logic types.
// It validates that only one comparison modifier is present and returns an error
// for unknown modifiers.
//
// Returns:
//   - transformMods: List of transform modifiers to apply
//   - comparisonOp: The comparison operator to use (default: "equals")
//   - useAllLogic: True if 'all' modifier is present for AND logic
//   - error: Error if validation fails
func (m *ModifierEvaluator) parseModifiers(modifiers []string) ([]string, string, bool, error) {
	var transformMods []string
	comparisonOp := DefaultOperator
	useAllLogic := false
	comparisonCount := 0

	for _, mod := range modifiers {
		// Check for transform modifiers
		if transformModifiers[mod] {
			transformMods = append(transformMods, mod)
			continue
		}

		// Check for comparison modifiers
		if comparisonModifiers[mod] {
			comparisonCount++
			if comparisonCount > 1 {
				return nil, "", false, fmt.Errorf("multiple comparison modifiers not allowed: found %d", comparisonCount)
			}
			comparisonOp = mod
			continue
		}

		// Check for logic modifiers
		if mod == ModifierAll {
			useAllLogic = true
			continue
		}

		// Unknown modifier
		return nil, "", false, fmt.Errorf("unknown modifier: %s", mod)
	}

	return transformMods, comparisonOp, useAllLogic, nil
}

// evaluateWithOperator handles the comparison logic for single values and lists.
// It implements OR logic (any match) by default and AND logic (all match) when
// the 'all' modifier is present.
//
// Parameters:
//   - value: The (possibly transformed) value to evaluate
//   - pattern: The pattern to match against
//   - operator: The comparison operator to use
//   - useAllLogic: If true, use AND logic for list matching
//
// Returns:
//   - bool: True if the value matches the pattern
//   - error: Error if comparison fails
func (m *ModifierEvaluator) evaluateWithOperator(value interface{}, pattern interface{}, operator string, useAllLogic bool) (bool, error) {
	// Handle pattern as list
	if patternList, ok := pattern.([]interface{}); ok {
		return m.evaluatePatternList(value, patternList, operator, useAllLogic)
	}

	// Handle value as list
	if valueList, ok := value.([]interface{}); ok {
		return m.evaluateValueList(valueList, pattern, operator)
	}

	// Single value vs single pattern
	return m.compareValues(value, pattern, operator, m.regexTimeout)
}

// evaluatePatternList evaluates a value against a list of patterns.
// Uses OR logic (any match) by default, or AND logic (all match) when useAllLogic is true.
//
// Parameters:
//   - value: The value to evaluate
//   - patterns: List of patterns to match against
//   - operator: The comparison operator to use
//   - useAllLogic: If true, all patterns must match (AND), otherwise any pattern (OR)
//
// Returns:
//   - bool: True if the value matches according to the logic mode
//   - error: Error if any comparison fails
func (m *ModifierEvaluator) evaluatePatternList(value interface{}, patterns []interface{}, operator string, useAllLogic bool) (bool, error) {
	// Handle empty pattern list
	if len(patterns) == 0 {
		return false, nil
	}

	// Handle value as list vs pattern list
	if valueList, ok := value.([]interface{}); ok {
		return m.evaluateListVsList(valueList, patterns, operator, useAllLogic)
	}

	// Single value vs pattern list
	if useAllLogic {
		// AND logic: all patterns must match
		for _, p := range patterns {
			match, err := m.compareValues(value, p, operator, m.regexTimeout)
			if err != nil {
				return false, err
			}
			if !match {
				return false, nil
			}
		}
		return true, nil
	}

	// OR logic: any pattern must match (default)
	for _, p := range patterns {
		match, err := m.compareValues(value, p, operator, m.regexTimeout)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// evaluateValueList evaluates a list of values against a single pattern.
// Returns true if any value in the list matches the pattern (OR logic).
//
// Parameters:
//   - values: List of values to evaluate
//   - pattern: The pattern to match against
//   - operator: The comparison operator to use
//
// Returns:
//   - bool: True if any value matches the pattern
//   - error: Error if any comparison fails
func (m *ModifierEvaluator) evaluateValueList(values []interface{}, pattern interface{}, operator string) (bool, error) {
	// Handle empty value list
	if len(values) == 0 {
		return false, nil
	}

	// OR logic: any value must match
	for _, v := range values {
		match, err := m.compareValues(v, pattern, operator, m.regexTimeout)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// evaluateListVsList evaluates a list of values against a list of patterns.
// Uses OR logic (any value matches any pattern) by default, or AND logic
// (all patterns must match at least one value) when useAllLogic is true.
//
// Parameters:
//   - values: List of values to evaluate
//   - patterns: List of patterns to match against
//   - operator: The comparison operator to use
//   - useAllLogic: If true, all patterns must match (AND), otherwise any match (OR)
//
// Returns:
//   - bool: True if the lists match according to the logic mode
//   - error: Error if any comparison fails
func (m *ModifierEvaluator) evaluateListVsList(values []interface{}, patterns []interface{}, operator string, useAllLogic bool) (bool, error) {
	// Handle empty lists
	if len(values) == 0 || len(patterns) == 0 {
		return false, nil
	}

	if useAllLogic {
		// AND logic: all patterns must match at least one value
		for _, p := range patterns {
			patternMatched := false
			for _, v := range values {
				match, err := m.compareValues(v, p, operator, m.regexTimeout)
				if err != nil {
					return false, err
				}
				if match {
					patternMatched = true
					break
				}
			}
			if !patternMatched {
				return false, nil
			}
		}
		return true, nil
	}

	// OR logic: any value must match any pattern (default)
	for _, v := range values {
		for _, p := range patterns {
			match, err := m.compareValues(v, p, operator, m.regexTimeout)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
	}
	return false, nil
}

// applyTransformModifiers applies transform modifiers to a value before comparison.
// Modifiers are applied in the order they appear in the slice. Each modifier
// progressively transforms the value. If any modifier fails, an error is returned.
//
// Supported transform modifiers:
//   - base64: Decode base64-encoded strings (tries multiple encodings)
//   - base64offset: Decode base64 with offset boundary variations (0, 1, 2)
//   - utf16le: Decode UTF-16 little-endian byte sequences to UTF-8 text
//   - utf16be: Decode UTF-16 big-endian byte sequences to UTF-8 text
//   - wide: UNSUPPORTED - requires binary event data (UTF-16LE byte arrays)
//   - windash: Normalize Unicode dash characters to ASCII hyphen (U+002D)
//
// Parameters:
//   - value: The value to transform
//   - modifiers: List of transform modifiers to apply in order
//
// Returns:
//   - interface{}: The transformed value
//   - error: Error if transformation fails
func (m *ModifierEvaluator) applyTransformModifiers(value interface{}, modifiers []string) (interface{}, error) {
	// Handle nil value
	if value == nil {
		return nil, nil
	}

	// Handle list values: apply transforms to each element
	if valueList, ok := value.([]interface{}); ok {
		transformed := make([]interface{}, len(valueList))
		for i, v := range valueList {
			result, err := m.applyTransformModifiers(v, modifiers)
			if err != nil {
				return nil, fmt.Errorf("failed to transform list element at index %d: %w", i, err)
			}
			transformed[i] = result
		}
		return transformed, nil
	}

	// Convert value to string for transformation
	valueStr, ok := value.(string)
	if !ok {
		// If value is not a string, return it unchanged
		return value, nil
	}

	// Apply modifiers in order
	transformed := valueStr
	for _, modifier := range modifiers {
		var err error
		switch modifier {
		case ModifierBase64:
			transformed, err = decodeBase64(transformed)
			if err != nil {
				return nil, fmt.Errorf("base64 decode failed: %w", err)
			}
		case ModifierBase64Offset:
			transformed, err = decodeBase64Offset(transformed)
			if err != nil {
				return nil, fmt.Errorf("base64offset decode failed: %w", err)
			}
		case ModifierUTF16LE:
			// Convert string to bytes for UTF-16 decoding
			transformed, err = decodeUTF16LE([]byte(transformed))
			if err != nil {
				return nil, fmt.Errorf("utf16le decode failed: %w", err)
			}
		case ModifierUTF16BE:
			// Convert string to bytes for UTF-16 decoding
			transformed, err = decodeUTF16BE([]byte(transformed))
			if err != nil {
				return nil, fmt.Errorf("utf16be decode failed: %w", err)
			}
		case ModifierWide:
			// Wide modifier is unsupported - requires binary event data
			return nil, &UnsupportedModifierError{
				Modifier: ModifierWide,
				Reason:   "wide modifier is not supported for text-based event logs",
			}
		case ModifierWindash:
			transformed = normalizeWindowsDashes(transformed)
		default:
			// Should not happen if parseModifiers is working correctly
			return nil, fmt.Errorf("unknown transform modifier: %s", modifier)
		}
	}

	return transformed, nil
}

// decodeBase64 attempts to decode a base64-encoded string using multiple encoding variants.
// It tries the following encodings in order until one succeeds:
//  1. Standard base64 encoding (with padding)
//  2. URL-safe base64 encoding (with padding)
//  3. Raw standard base64 encoding (without padding)
//  4. Raw URL-safe base64 encoding (without padding)
//
// This comprehensive approach handles all common base64 encoding variations
// found in real-world data, including web-safe encodings and unpadded variants.
//
// Parameters:
//   - input: The base64-encoded string to decode
//
// Returns:
//   - string: The decoded string
//   - error: Error if all decoding attempts fail
func decodeBase64(input string) (string, error) {
	if input == "" {
		return "", nil
	}

	// Try standard base64 encoding first (most common)
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	// Try URL-safe base64 encoding
	decoded, err = base64.URLEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	// Try raw standard encoding (no padding)
	decoded, err = base64.RawStdEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	// Try raw URL-safe encoding (no padding)
	decoded, err = base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return string(decoded), nil
	}

	// All decoding attempts failed
	return "", fmt.Errorf("failed to decode base64 string: invalid encoding")
}

// decodeBase64Offset decodes a base64-encoded string that may start at byte boundary 0, 1, or 2.
// This implements the SIGMA specification for the base64offset modifier.
//
// The base64offset modifier is used when a base64-encoded string may start at different
// byte alignment boundaries. This commonly occurs when extracting base64 data from
// binary formats or when the encoding starts at an arbitrary position in a data stream.
//
// Algorithm:
//  1. For each offset in [0, 1, 2]:
//     a. Add 'A' padding characters to the beginning to simulate the offset
//     b. Add trailing '=' padding to make the length a multiple of 4
//     c. Attempt to decode the padded string
//     d. Strip the offset bytes from the beginning of the decoded result
//     e. If decoding succeeds, return the result
//  2. If all offset attempts fail, return an error
//
// The 'A' character (0x00 in base64) is used for padding because it decodes to
// zero bytes, which can be safely stripped from the result.
//
// Parameters:
//   - input: The base64-encoded string to decode
//
// Returns:
//   - string: The decoded string with offset correction
//   - error: Error if all offset attempts fail
//
// Example:
//   - Input: "SGVsbG8" (no padding)
//   - Offset 0: Try "SGVsbG8=" → decode → strip 0 bytes → "Hello"
//   - This would succeed and return "Hello"
func decodeBase64Offset(input string) (string, error) {
	if input == "" {
		return "", nil
	}

	// Try each offset: 0, 1, 2
	for offset := 0; offset <= 2; offset++ {
		// Add 'A' padding to beginning to simulate offset alignment
		// 'A' in base64 decodes to 0x00, which we'll strip later
		paddedInput := strings.Repeat("A", offset) + input

		// Calculate required trailing padding to make length multiple of 4
		paddingNeeded := (4 - (len(paddedInput) % 4)) % 4
		paddedInput += strings.Repeat("=", paddingNeeded)

		// Try to decode with standard encoding first
		decoded, err := base64.StdEncoding.DecodeString(paddedInput)
		if err == nil && len(decoded) >= offset {
			// Successfully decoded - strip the offset bytes from the beginning
			result := decoded[offset:]
			return string(result), nil
		}

		// Try URL-safe encoding
		decoded, err = base64.URLEncoding.DecodeString(paddedInput)
		if err == nil && len(decoded) >= offset {
			result := decoded[offset:]
			return string(result), nil
		}
	}

	// All offset attempts failed - try without offset correction
	// This handles cases where the input is already properly aligned
	return decodeBase64(input)
}

// matchCIDR checks if an IP address is within a CIDR network range.
// This function implements the SIGMA cidr modifier for IP address matching.
//
// Security Considerations:
//   - Validates IP address format before processing
//   - Validates CIDR notation format before processing
//   - No external network calls - pure IP parsing
//   - Thread-safe (no shared mutable state)
//   - Handles edge cases: empty strings, malformed IPs, malformed CIDR
//
// Supported Formats:
//   - IPv4 addresses: "192.168.1.100"
//   - IPv4 CIDR: "192.168.1.0/24", "10.0.0.0/8"
//   - IPv6 addresses: "2001:db8::1"
//   - IPv6 CIDR: "2001:db8::/32", "fe80::/10"
//
// Common Use Cases in SIGMA:
//   - Detecting internal network activity: source_ip|cidr: "10.0.0.0/8"
//   - Filtering private IPs: dest_ip|cidr: "192.168.0.0/16"
//   - Monitoring specific subnets: ip|cidr: "172.16.0.0/12"
//   - IPv6 network matching: ipv6|cidr: "2001:db8::/32"
//
// Parameters:
//   - ipStr: IP address string to check (e.g., "192.168.1.100" or "2001:db8::1")
//   - cidrStr: CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
//
// Returns:
//   - bool: True if IP is within the CIDR range, false if not in range or parsing fails
//   - error: Error if IP address or CIDR notation is invalid
//
// Examples:
//   - matchCIDR("192.168.1.100", "192.168.1.0/24") → true, nil
//   - matchCIDR("10.0.0.1", "192.168.1.0/24") → false, nil
//   - matchCIDR("invalid", "192.168.1.0/24") → false, error
//   - matchCIDR("192.168.1.1", "invalid") → false, error
//   - matchCIDR("2001:db8::1", "2001:db8::/32") → true, nil
func matchCIDR(ipStr string, cidrStr string) (bool, error) {
	// Validate inputs - handle empty strings
	if ipStr == "" {
		return false, fmt.Errorf("IP address is empty")
	}
	if cidrStr == "" {
		return false, fmt.Errorf("CIDR notation is empty")
	}

	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Parse CIDR range
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR notation: %s: %w", cidrStr, err)
	}

	// Check if IP is within the CIDR range
	// IPNet.Contains correctly handles both IPv4 and IPv6
	if ipNet.Contains(ip) {
		return true, nil
	}

	return false, nil
}

// compareValues performs the actual comparison between a value and pattern using
// the specified operator. It implements all SIGMA comparison operators with proper
// type handling and ReDoS protection for regex operations.
//
// Supported Operators:
//   - equals: Exact equality comparison (default)
//   - contains: Substring match (case-sensitive)
//   - startswith: Prefix match (case-sensitive)
//   - endswith: Suffix match (case-sensitive)
//   - re: Regular expression match with timeout protection against ReDoS
//   - cidr: IP/CIDR network match supporting both IPv4 and IPv6
//
// Type Handling:
//   - Values are converted to strings using fmt.Sprintf if needed
//   - Supports int, float64, bool, and string types
//   - Returns false for incompatible types (not an error)
//
// Security Considerations:
//   - Regex operations are protected with timeout to prevent ReDoS attacks
//   - Invalid regex patterns return errors, not panics
//   - All string operations are memory-safe
//   - Thread-safe: can be called concurrently
//
// Parameters:
//   - actual: The actual value to compare
//   - pattern: The pattern to match against
//   - operator: The comparison operator to use
//   - timeout: Timeout for regex operations to prevent ReDoS attacks
//
// Returns:
//   - bool: True if the comparison succeeds
//   - error: Error if comparison fails or invalid operator
//
// Examples:
//   - compareValues("test", "test", "equals", 0) → true, nil
//   - compareValues("testing", "test", "contains", 0) → true, nil
//   - compareValues("test", "te", "startswith", 0) → true, nil
//   - compareValues("test", "st", "endswith", 0) → true, nil
//   - compareValues("test123", "test\\d+", "re", 100*time.Millisecond) → true, nil
func (m *ModifierEvaluator) compareValues(actual, pattern interface{}, operator string, timeout time.Duration) (bool, error) {
	// Handle nil values - both nil is considered equal, one nil is not equal
	if actual == nil && pattern == nil {
		return true, nil
	}
	if actual == nil || pattern == nil {
		return false, nil
	}

	// Convert both values to strings for comparison
	// This handles int, float64, bool, string gracefully
	actualStr := toString(actual)
	patternStr := toString(pattern)

	// Execute comparison based on operator
	switch operator {
	case DefaultOperator: // "equals"
		// Exact string equality
		return actualStr == patternStr, nil

	case ModifierContains: // "contains"
		// Case-sensitive substring match
		return strings.Contains(actualStr, patternStr), nil

	case ModifierStartsWith: // "startswith"
		// Case-sensitive prefix match
		return strings.HasPrefix(actualStr, patternStr), nil

	case ModifierEndsWith: // "endswith"
		// Case-sensitive suffix match
		return strings.HasSuffix(actualStr, patternStr), nil

	case ModifierRegex: // "re"
		// Regular expression match with ReDoS protection
		return matchRegexWithTimeout(patternStr, actualStr, timeout)

	case ModifierCIDR: // "cidr"
		// CIDR network matching using IP/subnet validation
		// actualStr is the IP address, patternStr is the CIDR range
		return matchCIDR(actualStr, patternStr)

	case ModifierGreaterThan: // "gt"
		return compareNumeric(actual, pattern, func(a, b float64) bool { return a > b })

	case ModifierGreaterThanOrEqual: // "gte"
		return compareNumeric(actual, pattern, func(a, b float64) bool { return a >= b })

	case ModifierLessThan: // "lt"
		return compareNumeric(actual, pattern, func(a, b float64) bool { return a < b })

	case ModifierLessThanOrEqual: // "lte"
		return compareNumeric(actual, pattern, func(a, b float64) bool { return a <= b })

	default:
		// Unknown operator - this should be caught during modifier parsing
		return false, fmt.Errorf("unknown comparison operator: %s", operator)
	}
}

// toString converts various types to string representation for comparison.
// It handles common types found in SIEM event data:
//   - string: returned as-is
//   - int, int64, int32: converted to decimal string
//   - float64, float32: converted to decimal string
//   - bool: converted to "true" or "false"
//   - all other types: converted using fmt.Sprintf("%v")
//
// This function is designed to be lenient and handle type conversion gracefully,
// avoiding errors for incompatible types. The philosophy is that SIGMA rules
// should be able to compare values across type boundaries when it makes semantic
// sense (e.g., comparing number 42 with string "42").
//
// Parameters:
//   - value: The value to convert to string
//
// Returns:
//   - string: String representation of the value
//
// Examples:
//   - toString("test") → "test"
//   - toString(42) → "42"
//   - toString(3.14) → "3.14"
//   - toString(true) → "true"
func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case float32:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		// Fallback for any other type
		return fmt.Sprintf("%v", v)
	}
}

// toFloat64ForComparison converts a value to float64 for numeric comparison.
// This is an extended version that also handles string parsing.
//
// Supported Types:
//   - int, int32, int64: converted to float64
//   - float32, float64: converted directly
//   - string: parsed as float64 using strconv.ParseFloat
//
// Parameters:
//   - value: The value to convert
//
// Returns:
//   - float64: The numeric value
//   - bool: True if conversion succeeded, false otherwise
func toFloat64ForComparison(value interface{}) (float64, bool) {
	// Try the existing toFloat64 first (handles numeric types)
	if num, ok := toFloat64(value); ok {
		return num, true
	}

	// Also handle string conversion for SIGMA rules
	if s, ok := value.(string); ok {
		f, err := strconv.ParseFloat(s, 64)
		if err == nil {
			return f, true
		}
	}

	return 0, false
}

// compareNumeric performs numeric comparison between two values.
// It converts both values to float64 and applies the comparison function.
//
// This function supports the SIGMA numeric comparison modifiers:
//   - gt (greater than): actual > pattern
//   - gte (greater than or equal): actual >= pattern
//   - lt (less than): actual < pattern
//   - lte (less than or equal): actual <= pattern
//
// Parameters:
//   - actual: The actual value from the event
//   - pattern: The pattern value from the rule
//   - cmp: Comparison function that takes (actual, pattern) and returns true if comparison succeeds
//
// Returns:
//   - bool: True if the comparison succeeds
//   - error: Error if either value cannot be converted to a number
func compareNumeric(actual, pattern interface{}, cmp func(a, b float64) bool) (bool, error) {
	actualNum, ok := toFloat64ForComparison(actual)
	if !ok {
		return false, fmt.Errorf("cannot convert actual value to number: %v (type %T)", actual, actual)
	}

	patternNum, ok := toFloat64ForComparison(pattern)
	if !ok {
		return false, fmt.Errorf("cannot convert pattern value to number: %v (type %T)", pattern, pattern)
	}

	return cmp(actualNum, patternNum), nil
}

// matchRegexWithTimeout performs safe regex matching with input size limits.
//
// Security Model:
// Go's regexp uses RE2/Thompson NFA algorithm which GUARANTEES O(n) matching time.
// Unlike Perl/PCRE, there is NO catastrophic backtracking in Go's regexp.
// Therefore, we do NOT need a goroutine-based timeout - which can cause goroutine leaks.
//
// Instead, we use INPUT SIZE LIMITS as the primary defense:
//   - maxRegexInputSize (1MB) prevents memory exhaustion during matching
//   - O(n) time on 1MB input is bounded to ~100ms at typical regex throughput
//   - Pattern validation (validateRegexPattern) prevents compilation DoS
//
// Why No Goroutine Timeout:
//   - Go's RE2 is O(n) - no exponential blowup possible
//   - Goroutine-based timeouts can leak if timeout expires during match
//   - Input size limits are simpler and more effective for bounded resources
//   - The timeout parameter is retained for API compatibility but NOT used
//
// Performance Characteristics:
//   - Uses package-level regex cache (defaultRegexCache) for compiled patterns
//   - Cache hit: O(1) - immediate pattern reuse without recompilation
//   - Cache miss: O(pattern_length) for compilation + pattern validation
//   - Matching: O(input_length) guaranteed by RE2 algorithm
//
// Thread Safety:
//   - Fully thread-safe: uses cached compiled regex from regexCache
//   - No mutable shared state during matching
//   - No goroutines spawned - simple synchronous operation
//
// Parameters:
//   - pattern: The regular expression pattern to match
//   - value: The string value to match against
//   - timeout: Retained for API compatibility (NOT USED - see security model above)
//
// Returns:
//   - bool: True if the pattern matches the value
//   - error: Error if pattern is invalid, input too large, or compilation fails
//
// Examples:
//   - matchRegexWithTimeout("test\\d+", "test123", 0) → true, nil
//   - matchRegexWithTimeout("[invalid", "test", 0) → false, error
//   - matchRegexWithTimeout(".*", strings.Repeat("a", 1000000), 0) → true, nil (within 1MB limit)
//   - matchRegexWithTimeout(".*", strings.Repeat("a", 2000000), 0) → false, error (exceeds 1MB limit)
func matchRegexWithTimeout(pattern, value string, timeout time.Duration) (bool, error) {
	// SECURITY: Enforce input size limit to prevent memory exhaustion
	// O(n) matching on unbounded input could still exhaust CPU/memory
	if len(value) > maxRegexInputSize {
		return false, fmt.Errorf("regex input too large: %d bytes (max %d)", len(value), maxRegexInputSize)
	}

	// Get compiled regex from cache (includes pattern validation)
	re, err := defaultRegexCache.get(pattern)
	if err != nil {
		return false, fmt.Errorf("regex error [pattern=%s]: %w", pattern, err)
	}

	// Note: re is never nil when err is nil - this is guaranteed by regexCache.get()
	// No need for defensive nil check that would be dead code

	// Execute match directly - Go's RE2 is O(n) and CANNOT hang
	// No goroutine needed - input size limit bounds total work
	_ = timeout // Parameter retained for API compatibility, not used
	return re.MatchString(value), nil
}

// decodeUTF16LE decodes a byte slice as UTF-16 Little Endian text and returns a UTF-8 string.
// This function implements the SIGMA utf16le transform modifier.
//
// Security Considerations:
//   - Validates byte slice length is even (UTF-16 uses 2-byte code units)
//   - Handles empty input gracefully
//   - Properly decodes surrogate pairs for characters outside the BMP
//   - Uses standard library unicode/utf16 package for correct decoding
//
// UTF-16LE Encoding:
//   - Each character is represented as one or more 16-bit code units
//   - Little Endian: least significant byte first (0x41 0x00 = 'A')
//   - Surrogate pairs (0xD800-0xDFFF) encode characters U+10000 and above
//
// Common Use Cases in SIGMA:
//   - Decoding Windows Registry values (often stored as UTF-16LE)
//   - Processing Windows event log data
//   - Analyzing PowerShell command strings
//   - Decoding base64-encoded UTF-16 data (chain: base64|utf16le)
//
// Parameters:
//   - data: Byte slice containing UTF-16LE encoded text
//
// Returns:
//   - string: Decoded UTF-8 string
//   - error: Error if byte slice has odd length or decoding fails
//
// Example:
//   - Input: []byte{0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00}
//   - Output: "Hello"
func decodeUTF16LE(data []byte) (string, error) {
	// Handle empty input
	if len(data) == 0 {
		return "", nil
	}

	// Validate even length - UTF-16 uses 2-byte code units
	if len(data)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16LE data: odd number of bytes (%d)", len(data))
	}

	// Convert byte slice to uint16 slice for UTF-16 decoding
	// Security: Pre-allocate with exact size to avoid allocations
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		// Little Endian: least significant byte first
		u16[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}

	// Decode UTF-16 to runes, handling surrogate pairs correctly
	// The utf16.Decode function properly handles:
	// - Basic Multilingual Plane (BMP) characters (U+0000 to U+FFFF)
	// - Supplementary characters via surrogate pairs (U+10000 and above)
	runes := utf16.Decode(u16)

	// Convert runes to UTF-8 string
	return string(runes), nil
}

// decodeUTF16BE decodes a byte slice as UTF-16 Big Endian text and returns a UTF-8 string.
// This function implements the SIGMA utf16be transform modifier.
//
// Security Considerations:
//   - Validates byte slice length is even (UTF-16 uses 2-byte code units)
//   - Handles empty input gracefully
//   - Properly decodes surrogate pairs for characters outside the BMP
//   - Uses standard library unicode/utf16 package for correct decoding
//
// UTF-16BE Encoding:
//   - Each character is represented as one or more 16-bit code units
//   - Big Endian: most significant byte first (0x00 0x41 = 'A')
//   - Surrogate pairs (0xD800-0xDFFF) encode characters U+10000 and above
//
// Common Use Cases in SIGMA:
//   - Processing network protocol data (many use big-endian)
//   - Analyzing Java/JVM string representations
//   - Decoding certain file format headers
//   - Cross-platform data exchange
//
// BOM Handling:
//   - This function does NOT strip Byte Order Marks (BOM)
//   - If BOM is present (0xFE 0xFF), it will be decoded as U+FEFF (ZERO WIDTH NO-BREAK SPACE)
//   - SIGMA rules should handle BOM stripping at a higher level if needed
//
// Parameters:
//   - data: Byte slice containing UTF-16BE encoded text
//
// Returns:
//   - string: Decoded UTF-8 string
//   - error: Error if byte slice has odd length or decoding fails
//
// Example:
//   - Input: []byte{0x00, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f}
//   - Output: "Hello"
func decodeUTF16BE(data []byte) (string, error) {
	// Handle empty input
	if len(data) == 0 {
		return "", nil
	}

	// Validate even length - UTF-16 uses 2-byte code units
	if len(data)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16BE data: odd number of bytes (%d)", len(data))
	}

	// Convert byte slice to uint16 slice for UTF-16 decoding
	// Security: Pre-allocate with exact size to avoid allocations
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		// Big Endian: most significant byte first
		u16[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}

	// Decode UTF-16 to runes, handling surrogate pairs correctly
	// The utf16.Decode function properly handles:
	// - Basic Multilingual Plane (BMP) characters (U+0000 to U+FFFF)
	// - Supplementary characters via surrogate pairs (U+10000 and above)
	runes := utf16.Decode(u16)

	// Convert runes to UTF-8 string
	return string(runes), nil
}

// normalizeWindowsDashes normalizes various Unicode dash characters to ASCII hyphen.
// This function implements the SIGMA windash transform modifier.
//
// Security Considerations:
//   - Prevents command injection via Unicode normalization attacks
//   - Ensures consistent matching of Windows command-line arguments
//   - Handles homoglyph attacks using visually similar dash characters
//
// Windows Command Line Context:
//   - Windows command line treats various Unicode dashes inconsistently
//   - Attackers may use Unicode dashes to bypass detection rules
//   - Example: "powershell.exe –ExecutionPolicy Bypass" (U+2013 EN DASH)
//   - After normalization: "powershell.exe -ExecutionPolicy Bypass" (U+002D HYPHEN-MINUS)
//
// Normalized Dash Characters:
//   - U+2010 HYPHEN → U+002D HYPHEN-MINUS
//   - U+2011 NON-BREAKING HYPHEN → U+002D HYPHEN-MINUS
//   - U+2012 FIGURE DASH → U+002D HYPHEN-MINUS
//   - U+2013 EN DASH → U+002D HYPHEN-MINUS
//   - U+2014 EM DASH → U+002D HYPHEN-MINUS
//   - U+2015 HORIZONTAL BAR → U+002D HYPHEN-MINUS
//   - U+2212 MINUS SIGN → U+002D HYPHEN-MINUS
//
// SIGMA Specification:
//   - The windash modifier is specifically designed for Windows command detection
//   - It should be used on fields containing command-line arguments
//   - Common usage: CommandLine|windash|contains: "-ExecutionPolicy"
//
// Performance:
//   - Uses strings.NewReplacer for efficient multi-replacement
//   - Replacer is created once and reuses internal state machine
//   - Optimized for hot-path usage in rule evaluation
//
// Parameters:
//   - s: Input string potentially containing Unicode dash characters
//
// Returns:
//   - string: String with all Unicode dashes normalized to ASCII hyphen (U+002D)
//
// Example:
//   - Input: "powershell –ExecutionPolicy Bypass" (U+2013 EN DASH)
//   - Output: "powershell -ExecutionPolicy Bypass" (U+002D HYPHEN-MINUS)
func normalizeWindowsDashes(s string) string {
	// Use the cached package-level replacer for optimal performance.
	// The replacer is initialized once at package load time to avoid
	// allocation overhead on every call - critical for SIEM throughput.
	return windowsDashReplacer.Replace(s)
}
