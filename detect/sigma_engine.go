package detect

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cerberus/core"
	"cerberus/metrics"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// SigmaEngineConfig holds configuration options for the SIGMA detection engine.
type SigmaEngineConfig struct {
	// CacheConfig configures the rule cache (nil = use defaults)
	CacheConfig *SigmaRuleCacheConfig

	// RegexTimeout is the maximum time allowed for regex evaluation (0 = no timeout)
	RegexTimeout time.Duration

	// MaxFieldValueSize is the maximum size of field values to evaluate (bytes)
	MaxFieldValueSize int

	// EnableMetrics controls whether Prometheus metrics are recorded
	EnableMetrics bool
}

// DefaultSigmaEngineConfig returns sensible defaults for production use.
func DefaultSigmaEngineConfig() SigmaEngineConfig {
	return SigmaEngineConfig{
		CacheConfig:       nil, // Use default cache config
		RegexTimeout:      5 * time.Second,
		MaxFieldValueSize: 1024 * 1024, // 1MB max field value
		EnableMetrics:     true,
	}
}

// SigmaEngine is the main entry point for native SIGMA rule evaluation.
//
// Architecture:
//   - Integrates FieldMapper for field name translation
//   - Uses ModifierEvaluator for value comparison with modifiers
//   - Caches parsed rules via SigmaRuleCache
//   - Records metrics for observability
//
// Thread-Safety:
//   - All public methods are safe for concurrent use
//   - Internal state is protected by mutex
//   - Shared components (cache, mapper) are also thread-safe
//
// Performance:
//   - Cache hits avoid YAML parsing and condition AST building
//   - Field mapping is O(1) lookup
//   - Short-circuit evaluation in condition expressions
//   - Metrics recording has minimal overhead
//
// Usage:
//
//	engine := NewSigmaEngine(config, logger)
//	engine.Start()
//	defer engine.Stop()
//
//	if match, err := engine.Evaluate(rule, event); err == nil && match {
//	    // Rule matched, generate alert
//	}
type SigmaEngine struct {
	// fieldMapper translates SIGMA field names to event field names
	fieldMapper *FieldMapper

	// modifierEval evaluates field values with SIGMA modifiers
	modifierEval *ModifierEvaluator

	// cache stores parsed SIGMA rules for reuse
	cache *SigmaRuleCache

	// conditionParser parses SIGMA condition expressions
	conditionParser *ConditionParser

	// logger for structured logging
	logger *zap.SugaredLogger

	// config holds engine configuration
	config SigmaEngineConfig

	// mu protects engine state during hot-reload scenarios
	mu sync.RWMutex

	// metrics tracks evaluation statistics
	metrics *SigmaMetrics
}

// SigmaMetrics tracks engine performance metrics.
// Thread-safe for concurrent updates using atomic operations.
// All fields are unexported; use GetMetrics() for a snapshot.
type SigmaMetrics struct {
	evaluations          int64 // Use atomic operations
	cacheHits            int64
	cacheMisses          int64
	matches              int64
	errors               int64
	parseErrors          int64
	totalEvaluationNanos int64
}

// SigmaMetricsSnapshot is a read-only snapshot of engine metrics.
type SigmaMetricsSnapshot struct {
	Evaluations          int64
	CacheHits            int64
	CacheMisses          int64
	Matches              int64
	Errors               int64
	ParseErrors          int64
	TotalEvaluationNanos int64
}

// NewSigmaEngine creates a new SIGMA detection engine.
//
// TASK 144.4: Now accepts parent context for lifecycle coordination
//
// Parameters:
//   - parentCtx: Parent context for lifecycle management (nil = use Background)
//   - config: Engine configuration (nil = use defaults)
//   - logger: Zap logger for structured logging
//
// Returns a configured but not started engine. Call Start() before use.
func NewSigmaEngine(parentCtx context.Context, config *SigmaEngineConfig, logger *zap.SugaredLogger) *SigmaEngine {
	cfg := DefaultSigmaEngineConfig()
	if config != nil {
		if config.CacheConfig != nil {
			cfg.CacheConfig = config.CacheConfig
		}
		if config.RegexTimeout > 0 {
			cfg.RegexTimeout = config.RegexTimeout
		}
		if config.MaxFieldValueSize > 0 {
			cfg.MaxFieldValueSize = config.MaxFieldValueSize
		}
		cfg.EnableMetrics = config.EnableMetrics
	}

	// TASK 144.4: Pass parent context to cache for lifecycle coordination
	// This ensures cache cleanup goroutine respects parent context cancellation
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	return &SigmaEngine{
		fieldMapper:     NewFieldMapper(),
		modifierEval:    NewModifierEvaluator(cfg.RegexTimeout),
		cache:           NewSigmaRuleCache(parentCtx, cfg.CacheConfig),
		conditionParser: NewConditionParser(),
		logger:          logger,
		config:          cfg,
		metrics:         &SigmaMetrics{},
	}
}

// Start initializes and starts the SIGMA engine.
// This starts background goroutines (cache cleanup) and should be called
// before evaluating rules.
func (e *SigmaEngine) Start() {
	e.cache.StartCleanup()
	e.logger.Info("SIGMA engine started")
}

// Stop gracefully shuts down the SIGMA engine.
// This stops background goroutines and should be called during shutdown.
func (e *SigmaEngine) Stop() {
	e.cache.Stop()
	e.logger.Info("SIGMA engine stopped")
}

// LoadFieldMappings loads field mappings from a YAML configuration file.
// This should be called during initialization to enable field name translation.
//
// Parameters:
//   - configPath: Path to the sigma_field_mappings.yaml file
//
// Returns error if the file cannot be loaded or parsed.
func (e *SigmaEngine) LoadFieldMappings(configPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.fieldMapper.LoadMappings(configPath); err != nil {
		return fmt.Errorf("failed to load field mappings: %w", err)
	}

	if err := e.fieldMapper.ValidateMapping(); err != nil {
		return fmt.Errorf("field mapping validation failed: %w", err)
	}

	e.logger.Infof("SIGMA field mappings loaded from %s", configPath)
	return nil
}

// Evaluate evaluates a SIGMA rule against an event.
//
// Parameters:
//   - rule: The detection rule (must have Type="sigma" and SigmaYAML populated)
//   - event: The event to evaluate
//
// Returns:
//   - bool: true if the rule matches the event
//   - error: Any evaluation errors (invalid rule, parse errors, etc.)
//
// Thread-safe: Uses internal locking for cache access.
//
// Performance:
//   - Cache hit: ~50μs (condition evaluation only)
//   - Cache miss: ~500μs (includes YAML parsing and AST building)
func (e *SigmaEngine) Evaluate(rule *core.Rule, event *core.Event) (bool, error) {
	start := time.Now()

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Validate inputs
	if rule == nil {
		e.recordError()
		return false, fmt.Errorf("cannot evaluate nil rule")
	}
	if event == nil {
		e.recordError()
		return false, fmt.Errorf("cannot evaluate nil event")
	}
	if strings.ToLower(rule.Type) != "sigma" {
		e.recordError()
		return false, fmt.Errorf("rule %s is not a SIGMA rule (type=%s)", rule.ID, rule.Type)
	}

	// Get or create cached rule
	cached, err := e.getCachedRule(rule)
	if err != nil {
		e.recordParseError()
		return false, fmt.Errorf("failed to parse SIGMA rule %s: %w", rule.ID, err)
	}

	// Evaluate the detection logic
	match, err := e.evaluateDetection(cached, event)
	if err != nil {
		e.recordError()
		if e.config.EnableMetrics {
			metrics.RecordRuleEvaluationError(rule.ID)
		}
		return false, fmt.Errorf("failed to evaluate rule %s: %w", rule.ID, err)
	}

	// Record metrics
	elapsed := time.Since(start)
	e.recordEvaluation(match, elapsed, rule.ID)

	if match {
		e.logger.Debugf("SIGMA rule %s matched event %s", rule.ID, event.EventID)
	}

	return match, nil
}

// extractDetectionSection extracts and validates the detection section from parsed YAML.
// Returns the detection map and an error if validation fails.
func extractDetectionSection(parsed map[string]interface{}) (map[string]interface{}, error) {
	detectionRaw, ok := parsed["detection"]
	if !ok {
		return nil, fmt.Errorf("SIGMA rule missing required 'detection' section")
	}
	detection, ok := detectionRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("SIGMA rule 'detection' section is not a map")
	}
	return detection, nil
}

// extractCondition extracts and validates the condition string from the detection section.
// Returns the trimmed condition string and an error if validation fails.
func extractCondition(detection map[string]interface{}) (string, error) {
	conditionRaw, ok := detection["condition"]
	if !ok {
		return "", fmt.Errorf("SIGMA rule missing 'condition' in detection section")
	}
	condition, ok := conditionRaw.(string)
	if !ok {
		return "", fmt.Errorf("SIGMA rule 'condition' must be a string")
	}
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return "", fmt.Errorf("SIGMA rule 'condition' cannot be empty")
	}
	return condition, nil
}

// buildDetectionBlocks constructs detection blocks from the detection section.
// Returns a map of block names to their conditions and a list of block names.
// Skips the 'condition' key as it's not a detection block.
func buildDetectionBlocks(detection map[string]interface{}, logger *zap.SugaredLogger) (map[string]map[string]interface{}, []string, error) {
	detectionBlocks := make(map[string]map[string]interface{})
	var blockNames []string

	for name, value := range detection {
		if name == "condition" {
			continue
		}

		// Validate detection block names (security check)
		if len(name) > 100 {
			return nil, nil, fmt.Errorf("detection block name '%s...' exceeds maximum length (100)", name[:50])
		}

		switch v := value.(type) {
		case map[string]interface{}:
			detectionBlocks[name] = v
			blockNames = append(blockNames, name)
		case []interface{}:
			// List of conditions - treat as OR of maps
			detectionBlocks[name] = map[string]interface{}{"__list__": v}
			blockNames = append(blockNames, name)
		default:
			logger.Warnf("Ignoring detection block %s with unsupported type %T", name, value)
		}
	}

	if len(detectionBlocks) == 0 {
		return nil, nil, fmt.Errorf("SIGMA rule has no detection blocks (only condition)")
	}

	return detectionBlocks, blockNames, nil
}

// extractLogsource extracts the logsource section from parsed YAML.
// Returns an empty map if logsource is not present (this is valid).
func extractLogsource(parsed map[string]interface{}) map[string]interface{} {
	logsource := make(map[string]interface{})
	if ls, ok := parsed["logsource"]; ok {
		if lsMap, ok := ls.(map[string]interface{}); ok {
			logsource = lsMap
		}
	}
	return logsource
}

// getCachedRule retrieves a cached rule or parses and caches a new one.
// This function orchestrates the parsing workflow using focused helper functions.
func (e *SigmaEngine) getCachedRule(rule *core.Rule) (*CachedSigmaRule, error) {
	// Check cache first
	if cached := e.cache.Get(rule.ID); cached != nil {
		atomic.AddInt64(&e.metrics.cacheHits, 1)
		if e.config.EnableMetrics {
			metrics.RecordCacheHit()
		}
		return cached, nil
	}

	atomic.AddInt64(&e.metrics.cacheMisses, 1)
	if e.config.EnableMetrics {
		metrics.RecordCacheMiss()
	}

	// Parse the SIGMA YAML
	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		if e.config.EnableMetrics {
			metrics.RecordParseError("yaml_parse")
		}
		return nil, fmt.Errorf("failed to parse SIGMA YAML: %w", err)
	}

	// Extract and validate detection section using helper
	detection, err := extractDetectionSection(parsed)
	if err != nil {
		return nil, err
	}

	// Extract and validate condition using helper
	condition, err := extractCondition(detection)
	if err != nil {
		return nil, err
	}

	// Build detection blocks using helper
	detectionBlocks, blockNames, err := buildDetectionBlocks(detection, e.logger)
	if err != nil {
		return nil, err
	}

	// Parse condition expression
	conditionAST, err := e.conditionParser.ParseWithContext(condition, blockNames)
	if err != nil {
		if e.config.EnableMetrics {
			metrics.RecordParseError("condition_parse")
		}
		return nil, fmt.Errorf("failed to parse condition '%s': %w", condition, err)
	}

	// Validate AST was created successfully
	if conditionAST == nil {
		return nil, fmt.Errorf("condition parser returned nil AST for condition '%s'", condition)
	}

	// Extract logsource using helper
	logsource := extractLogsource(parsed)

	// Parse correlation block if present (optional)
	correlation, err := e.parseCorrelationBlock(parsed, rule.ID)
	if err != nil {
		// Log warning but don't fail - correlation is optional
		e.logger.Warnf("Failed to parse correlation block for rule %s: %v", rule.ID, err)
	}

	// Build and cache the entry
	cached := &CachedSigmaRule{
		RuleID:          rule.ID,
		ParsedYAML:      parsed,
		ConditionAST:    conditionAST,
		DetectionBlocks: detectionBlocks,
		Logsource:       logsource,
		Correlation:     correlation,
	}

	if err := e.cache.Put(cached); err != nil {
		e.logger.Warnf("Failed to cache rule %s: %v", rule.ID, err)
		// Continue without caching
	}

	return cached, nil
}

// evaluateDetection evaluates the detection logic against an event.
func (e *SigmaEngine) evaluateDetection(cached *CachedSigmaRule, event *core.Event) (bool, error) {
	// Defensive nil check for ConditionAST
	if cached.ConditionAST == nil {
		return false, fmt.Errorf("rule has nil condition AST (likely a parsing error)")
	}

	// CRITICAL FIX: Check if event matches the rule's logsource criteria
	// This ensures rules only evaluate against events from the correct source
	// Without this check, rules like "zeek/rdp" would match ALL events
	if !e.matchesLogsource(cached.Logsource, event) {
		return false, nil // Event doesn't match logsource - not a match
	}

	// Build evaluation context: map block names to their match results
	context := make(map[string]bool)

	for blockName, blockConditions := range cached.DetectionBlocks {
		match, err := e.evaluateDetectionBlock(blockConditions, cached.Logsource, event)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate block '%s': %w", blockName, err)
		}
		context[blockName] = match
	}

	// Evaluate the condition AST with the context
	result, err := cached.ConditionAST.Evaluate(context)
	if err != nil {
		return false, fmt.Errorf("condition evaluation failed: %w", err)
	}

	return result, nil
}

// evaluateDetectionBlock evaluates a single detection block against an event.
// All field conditions within a block are AND-ed together.
func (e *SigmaEngine) evaluateDetectionBlock(block map[string]interface{}, logsource map[string]interface{}, event *core.Event) (bool, error) {
	// Handle list-type blocks (OR of maps)
	if listVal, ok := block["__list__"]; ok {
		if list, ok := listVal.([]interface{}); ok {
			return e.evaluateDetectionBlockList(list, logsource, event)
		}
	}

	// Regular block: all conditions must match (AND)
	for fieldExpr, expectedValue := range block {
		match, err := e.evaluateFieldCondition(fieldExpr, expectedValue, logsource, event)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate field '%s': %w", fieldExpr, err)
		}
		if !match {
			return false, nil // Short-circuit: one non-match means block doesn't match
		}
	}

	return true, nil // All conditions matched
}

// evaluateDetectionBlockList evaluates a list of conditions (OR logic).
// Each item in the list is a separate set of conditions.
func (e *SigmaEngine) evaluateDetectionBlockList(list []interface{}, logsource map[string]interface{}, event *core.Event) (bool, error) {
	for _, item := range list {
		switch v := item.(type) {
		case map[string]interface{}:
			match, err := e.evaluateDetectionBlock(v, logsource, event)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil // Short-circuit: one match is enough (OR)
			}
		case string:
			// Simple string value - treat as equality check against all fields
			// This is rare in SIGMA but should be handled
			e.logger.Debugf("Ignoring string value in detection list: %s", v)
		default:
			e.logger.Warnf("Ignoring unsupported type in detection list: %T", v)
		}
	}

	return false, nil // No match found
}

// evaluateFieldCondition evaluates a single field condition.
//
// Parameters:
//   - fieldExpr: Field expression with optional modifiers (e.g., "Image|endswith")
//   - expectedValue: The expected value or pattern
//   - logsource: The logsource definition for field mapping
//   - event: The event to check
//
// Returns true if the field value matches the expected value with modifiers applied.
func (e *SigmaEngine) evaluateFieldCondition(fieldExpr string, expectedValue interface{}, logsource map[string]interface{}, event *core.Event) (bool, error) {
	// Parse field expression: "field|modifier1|modifier2"
	parts := strings.Split(fieldExpr, "|")
	fieldName := strings.TrimSpace(parts[0])
	modifiers := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		mod := strings.TrimSpace(parts[i])
		if mod != "" {
			modifiers = append(modifiers, mod)
		}
	}

	// Check for 'all' modifier which changes list matching behavior
	hasAllModifier := false
	filteredModifiers := make([]string, 0, len(modifiers))
	for _, mod := range modifiers {
		if mod == "all" {
			hasAllModifier = true
		} else {
			filteredModifiers = append(filteredModifiers, mod)
		}
	}
	modifiers = filteredModifiers

	// Map SIGMA field name to event field name
	mappedFieldName := e.fieldMapper.MapField(fieldName, logsource)

	// Get the event field value
	// Try mapped field name first, then fall back to original field name
	// This handles cases where:
	// 1. Field mapping config maps SIGMA fields to event fields
	// 2. Event uses the original SIGMA field name directly (common in tests)
	actualValue, found := e.fieldMapper.GetEventFieldValue(event, mappedFieldName)
	if !found && mappedFieldName != fieldName {
		// Fallback: try the original unmapped field name
		actualValue, found = e.fieldMapper.GetEventFieldValue(event, fieldName)
	}
	if !found {
		// If field is not found with either mapped or original name, this is not a match
		// Most SIGMA rules expect the field to exist
		return false, nil
	}

	// Handle different expected value types
	switch expected := expectedValue.(type) {
	case []interface{}:
		// List of values - default is OR (any match), 'all' modifier makes it AND
		return e.evaluateListCondition(actualValue, expected, modifiers, hasAllModifier)

	case map[string]interface{}:
		// Nested conditions - recursive evaluation
		return e.evaluateNestedCondition(actualValue, expected, logsource, event, modifiers)

	default:
		// Single value
		return e.modifierEval.EvaluateWithModifiers(actualValue, expected, modifiers)
	}
}

// evaluateListCondition evaluates a list of expected values.
// Default behavior is OR (any value matches). With 'all' modifier, all values must match.
func (e *SigmaEngine) evaluateListCondition(actualValue interface{}, expectedValues []interface{}, modifiers []string, requireAll bool) (bool, error) {
	if requireAll {
		// ALL mode: every expected value must match
		for _, expected := range expectedValues {
			match, err := e.modifierEval.EvaluateWithModifiers(actualValue, expected, modifiers)
			if err != nil {
				return false, err
			}
			if !match {
				return false, nil
			}
		}
		return true, nil
	}

	// ANY mode (default): at least one expected value must match
	for _, expected := range expectedValues {
		match, err := e.modifierEval.EvaluateWithModifiers(actualValue, expected, modifiers)
		if err != nil {
			// Log error but continue checking other values
			e.logger.Debugf("Error evaluating value %v: %v", expected, err)
			continue
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// evaluateNestedCondition handles nested/complex condition structures.
// This is rare in SIGMA but can occur with some advanced rules.
func (e *SigmaEngine) evaluateNestedCondition(actualValue interface{}, nested map[string]interface{}, logsource map[string]interface{}, event *core.Event, modifiers []string) (bool, error) {
	// For nested conditions, we need to check if actualValue is itself a map
	actualMap, ok := actualValue.(map[string]interface{})
	if !ok {
		// Cannot compare non-map to nested condition
		return false, nil
	}

	// Each key in nested must match the corresponding key in actualValue
	for key, expectedVal := range nested {
		actualVal, exists := actualMap[key]
		if !exists {
			return false, nil
		}

		// Check if the actual value matches expected
		match, err := e.modifierEval.EvaluateWithModifiers(actualVal, expectedVal, modifiers)
		if err != nil {
			return false, err
		}
		if !match {
			return false, nil
		}
	}

	return true, nil
}

// parseCorrelationBlock extracts and validates correlation configuration from SIGMA YAML.
// Returns nil if no correlation block is present (not an error).
// Returns error only if correlation block exists but is malformed.
//
// Security considerations:
//   - Uses core.ParseYAML for secure YAML parsing with depth validation
//   - Validates correlation configuration before caching
//   - Enforces size limits to prevent resource exhaustion (max 1MB)
func (e *SigmaEngine) parseCorrelationBlock(parsed map[string]interface{}, ruleID string) (*core.SigmaCorrelation, error) {
	// Check if correlation block exists
	correlationRaw, hasCorrelation := parsed["correlation"]
	if !hasCorrelation {
		return nil, nil // No correlation - not an error
	}

	// Serialize correlation section back to YAML for secure parsing
	// This ensures we go through core.ParseYAML's security validations
	correlationYAML, err := yaml.Marshal(correlationRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal correlation block: %w", err)
	}

	// Security: Check size before parsing to prevent resource exhaustion
	const maxCorrelationSize = 1024 * 1024 // 1MB max
	if len(correlationYAML) > maxCorrelationSize {
		return nil, fmt.Errorf("correlation block size (%d bytes) exceeds maximum allowed (%d bytes)", len(correlationYAML), maxCorrelationSize)
	}

	// Parse through core.ParseYAML for security validation
	correlation, err := core.ParseYAML(correlationYAML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse correlation YAML: %w", err)
	}

	// Validate correlation configuration
	if err := correlation.Validate(); err != nil {
		return nil, fmt.Errorf("correlation validation failed: %w", err)
	}

	e.logger.Debugf("Parsed correlation block for rule %s: type=%s", ruleID, correlation.Type)
	return correlation, nil
}

// InvalidateCache removes a rule from the cache.
// Use this when a rule is updated to force re-parsing on next evaluation.
func (e *SigmaEngine) InvalidateCache(ruleID string) {
	e.cache.Invalidate(ruleID)
}

// InvalidateAllCache clears the entire rule cache.
// Use this during bulk rule updates or when field mappings change.
func (e *SigmaEngine) InvalidateAllCache() {
	e.cache.InvalidateAll()
}

// InvalidateCorrelationRules invalidates cached rules that have correlation blocks.
// This is useful when correlation processing logic changes or when you need to
// force re-parsing of hybrid detection+correlation rules.
//
// Performance: O(n) where n is the number of cached rules.
// Thread-safe: Uses cache's internal locking via GetCorrelationRuleIDs.
func (e *SigmaEngine) InvalidateCorrelationRules() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := e.cache.GetStats()
	if stats.Size == 0 {
		return 0
	}

	// Get snapshot of rule IDs with correlation blocks
	// This uses proper encapsulation via the cache's public API
	correlationRuleIDs := e.cache.GetCorrelationRuleIDs()

	// Invalidate collected rules atomically
	for _, ruleID := range correlationRuleIDs {
		e.cache.Invalidate(ruleID)
	}

	e.logger.Infof("Invalidated %d correlation rules from cache", len(correlationRuleIDs))
	return len(correlationRuleIDs)
}

// GetMetrics returns a snapshot of engine metrics.
// Thread-safe via atomic reads.
func (e *SigmaEngine) GetMetrics() SigmaMetricsSnapshot {
	return SigmaMetricsSnapshot{
		Evaluations:          atomic.LoadInt64(&e.metrics.evaluations),
		CacheHits:            atomic.LoadInt64(&e.metrics.cacheHits),
		CacheMisses:          atomic.LoadInt64(&e.metrics.cacheMisses),
		Matches:              atomic.LoadInt64(&e.metrics.matches),
		Errors:               atomic.LoadInt64(&e.metrics.errors),
		ParseErrors:          atomic.LoadInt64(&e.metrics.parseErrors),
		TotalEvaluationNanos: atomic.LoadInt64(&e.metrics.totalEvaluationNanos),
	}
}

// GetCacheStats returns a snapshot of cache statistics.
func (e *SigmaEngine) GetCacheStats() CacheStats {
	return e.cache.GetStats()
}

// Helper methods for metrics - all use atomic operations for thread-safety

func (e *SigmaEngine) recordEvaluation(matched bool, duration time.Duration, ruleID string) {
	atomic.AddInt64(&e.metrics.evaluations, 1)
	atomic.AddInt64(&e.metrics.totalEvaluationNanos, duration.Nanoseconds())
	if matched {
		atomic.AddInt64(&e.metrics.matches, 1)
	}

	// Record to Prometheus if enabled
	if e.config.EnableMetrics {
		metrics.RecordRuleEvaluation(ruleID, matched, duration.Seconds())
	}
}

func (e *SigmaEngine) recordError() {
	atomic.AddInt64(&e.metrics.errors, 1)
}

func (e *SigmaEngine) recordParseError() {
	atomic.AddInt64(&e.metrics.parseErrors, 1)
}

// ParseSigmaYAML is a utility function for validating and parsing SIGMA YAML.
// This can be used for pre-validation before storing rules.
// This function reuses the same helper functions as getCachedRule for consistency.
//
// Returns:
//   - title: The rule title
//   - detection: The detection section
//   - correlation: The correlation section (nil if not present)
//   - err: Any parsing errors
func ParseSigmaYAML(sigmaYAML string) (title string, detection map[string]interface{}, correlation *core.SigmaCorrelation, err error) {
	if strings.TrimSpace(sigmaYAML) == "" {
		return "", nil, nil, fmt.Errorf("SIGMA YAML is empty")
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(sigmaYAML), &parsed); err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Extract title
	if t, ok := parsed["title"]; ok {
		if titleStr, ok := t.(string); ok {
			title = titleStr
		}
	}

	// Extract and validate detection section using shared helper
	detection, err = extractDetectionSection(parsed)
	if err != nil {
		return "", nil, nil, err
	}

	// Validate condition exists using shared helper
	_, err = extractCondition(detection)
	if err != nil {
		return "", nil, nil, err
	}

	// Extract and parse correlation if present (optional)
	correlation, err = parseCorrelationBlockStatic(parsed)
	if err != nil {
		return "", nil, nil, err
	}

	return title, detection, correlation, nil
}

// matchesLogsource checks if an event matches the rule's logsource criteria.
//
// SIGMA logsource semantics:
//   - category: Type of log event (e.g., "process_creation", "authentication", "network_connection")
//   - product: Source product/system (e.g., "windows", "linux", "zeek")
//   - service: Specific service/component (e.g., "sysmon", "rdp", "powershell")
//
// Matching logic:
//   - If logsource is empty, rule matches all events
//   - category matches against event.EventType
//   - product matches against event.Fields["product"] or event.SourceFormat
//   - service matches against event.Fields["service"] or event.Fields["log_type"]
//   - All specified logsource fields must match (AND logic)
//
// Returns true if the event matches all specified logsource criteria.
func (e *SigmaEngine) matchesLogsource(logsource map[string]interface{}, event *core.Event) bool {
	// If no logsource specified, rule applies to all events
	if logsource == nil || len(logsource) == 0 {
		return true
	}

	// Check category - matches against EventType
	if category, ok := logsource["category"].(string); ok && category != "" {
		if !e.matchesLogsourceField(category, event.EventType, event, "category") {
			return false
		}
	}

	// Check product - matches against Fields["product"] or SourceFormat
	if product, ok := logsource["product"].(string); ok && product != "" {
		eventProduct := e.getEventLogsourceValue(event, "product")
		if !e.matchesLogsourceField(product, eventProduct, event, "product") {
			return false
		}
	}

	// Check service - matches against Fields["service"] or Fields["log_type"]
	if service, ok := logsource["service"].(string); ok && service != "" {
		eventService := e.getEventLogsourceValue(event, "service")
		if !e.matchesLogsourceField(service, eventService, event, "service") {
			return false
		}
	}

	// All specified criteria matched
	return true
}

// getEventLogsourceValue extracts the appropriate field value for logsource matching.
// Uses fallback chain for flexible matching across different event formats.
func (e *SigmaEngine) getEventLogsourceValue(event *core.Event, field string) string {
	if event == nil || event.Fields == nil {
		if field == "product" {
			return event.SourceFormat // Fallback to SourceFormat for product
		}
		return ""
	}

	switch field {
	case "product":
		// Try Fields["product"], then SourceFormat
		if v, ok := event.Fields["product"].(string); ok && v != "" {
			return v
		}
		// Also check Fields["logsource_product"] for explicitly tagged events
		if v, ok := event.Fields["logsource_product"].(string); ok && v != "" {
			return v
		}
		return event.SourceFormat

	case "service":
		// Try Fields["service"], then Fields["log_type"]
		if v, ok := event.Fields["service"].(string); ok && v != "" {
			return v
		}
		if v, ok := event.Fields["log_type"].(string); ok && v != "" {
			return v
		}
		// Also check Fields["logsource_service"] for explicitly tagged events
		if v, ok := event.Fields["logsource_service"].(string); ok && v != "" {
			return v
		}
		return ""

	case "category":
		// Try Fields["category"] (lowercase), then Category (capital), then EventType
		if v, ok := event.Fields["category"].(string); ok && v != "" {
			return v
		}
		// SIGMA standard Category field (used by Sysmon-style events)
		if v, ok := event.Fields["Category"].(string); ok && v != "" {
			return v
		}
		// Also check Fields["logsource_category"] for explicitly tagged events
		if v, ok := event.Fields["logsource_category"].(string); ok && v != "" {
			return v
		}
		return event.EventType

	default:
		// Generic field lookup
		if v, ok := event.Fields[field].(string); ok {
			return v
		}
		return ""
	}
}

// matchesLogsourceField compares a logsource value with an event value.
// Uses case-insensitive comparison and supports common aliases.
func (e *SigmaEngine) matchesLogsourceField(ruleValue, eventValue string, event *core.Event, fieldType string) bool {
	// Normalize for comparison
	ruleValue = strings.ToLower(strings.TrimSpace(ruleValue))
	eventValue = strings.ToLower(strings.TrimSpace(eventValue))

	// Direct match
	if ruleValue == eventValue {
		return true
	}

	// Common aliases and mappings for flexibility
	switch fieldType {
	case "category":
		// Map SIGMA category names to common event types
		categoryAliases := map[string][]string{
			"process_creation":     {"process_start", "process_exec", "process", "execution"},
			"network_connection":   {"network", "connection", "socket", "netflow"},
			"authentication":       {"auth", "login", "logon", "logoff", "logout"},
			"file_event":           {"file", "file_create", "file_delete", "file_modify"},
			"registry_event":       {"registry", "reg_set", "reg_create", "reg_delete"},
			"dns_query":            {"dns", "dns_request"},
			"process_termination":  {"process_stop", "process_exit", "process_end"},
			"image_load":           {"module_load", "dll_load", "library_load"},
			"driver_load":          {"driver", "kernel_driver"},
			"create_remote_thread": {"remote_thread", "thread_injection"},
		}
		if aliases, ok := categoryAliases[ruleValue]; ok {
			for _, alias := range aliases {
				if eventValue == alias {
					return true
				}
			}
		}
		// Also check reverse mapping
		for canonical, aliases := range categoryAliases {
			if ruleValue == canonical {
				continue // Already checked above
			}
			for _, alias := range aliases {
				if ruleValue == alias && eventValue == canonical {
					return true
				}
			}
		}

	case "product":
		// Map product names
		productAliases := map[string][]string{
			"windows": {"win", "microsoft"},
			"linux":   {"unix", "centos", "ubuntu", "debian", "rhel"},
			"zeek":    {"bro", "zeek_conn", "zeek_dns", "zeek_http"},
			"aws":     {"amazon", "cloudtrail", "cloudwatch"},
			"azure":   {"microsoft_azure", "azure_ad"},
			"gcp":     {"google_cloud", "google"},
		}
		if aliases, ok := productAliases[ruleValue]; ok {
			for _, alias := range aliases {
				if eventValue == alias {
					return true
				}
			}
		}

	case "service":
		// Service names are typically exact matches
		// But support some common variations
		serviceAliases := map[string][]string{
			"sysmon":     {"microsoft-windows-sysmon", "sysmon/operational"},
			"security":   {"microsoft-windows-security-auditing", "windows_security"},
			"powershell": {"microsoft-windows-powershell", "powershell/operational"},
			"rdp":        {"remote_desktop", "terminalservices", "rdp_connection"},
		}
		if aliases, ok := serviceAliases[ruleValue]; ok {
			for _, alias := range aliases {
				if eventValue == alias {
					return true
				}
			}
		}
	}

	return false
}

// parseCorrelationBlockStatic is a static version of parseCorrelationBlock for use in ParseSigmaYAML.
// This extracts correlation parsing logic for reuse without requiring a SigmaEngine instance.
func parseCorrelationBlockStatic(parsed map[string]interface{}) (*core.SigmaCorrelation, error) {
	correlationRaw, hasCorrelation := parsed["correlation"]
	if !hasCorrelation {
		return nil, nil
	}

	correlationYAML, err := yaml.Marshal(correlationRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal correlation block: %w", err)
	}

	// Security: Check size before parsing
	const maxCorrelationSize = 1024 * 1024 // 1MB max
	if len(correlationYAML) > maxCorrelationSize {
		return nil, fmt.Errorf("correlation block size (%d bytes) exceeds maximum allowed (%d bytes)", len(correlationYAML), maxCorrelationSize)
	}

	correlation, err := core.ParseYAML(correlationYAML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse correlation YAML: %w", err)
	}

	if err := correlation.Validate(); err != nil {
		return nil, fmt.Errorf("correlation validation failed: %w", err)
	}

	return correlation, nil
}
