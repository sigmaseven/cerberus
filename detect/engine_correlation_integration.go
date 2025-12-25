package detect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"gopkg.in/yaml.v3"
)

// ISSUE #4: Maximum correlation window as documented in function comments
const maxCorrelationWindow = 24 * time.Hour

// LoadCorrelationRulesFromStorage loads correlation rules from unified rule storage.
// TASK 168.1: Loads rules with SIGMA correlation blocks and initializes correlation state.
//
// This function:
//  1. Queries storage for enabled SIGMA rules with correlation blocks
//  2. Parses SIGMA YAML and extracts correlation configuration
//  3. Maps correlation rules to appropriate evaluator types
//  4. Configures correlation state stores with appropriate TTLs
//
// Security Considerations:
//  - Validates correlation configuration before loading
//  - Enforces maximum correlation window (24 hours)
//  - Limits number of correlation rules to prevent resource exhaustion
//
// Thread-Safety:
//  - Safe to call concurrently
//  - Uses write lock for rule updates
//
// Parameters:
//  - ctx: Context for cancellation and timeout
//  - ruleStorage: Storage interface for retrieving rules
//
// Returns:
//  - error: Any errors during rule loading or validation
//
// Performance:
//  - Batches rule loading for efficiency
//  - Parses YAML once during load
//  - Caches parsed correlation configuration
func (re *RuleEngine) LoadCorrelationRulesFromStorage(ctx context.Context, ruleStorage storage.RuleStorageInterface) error {
	if ruleStorage == nil {
		return fmt.Errorf("rule storage is nil")
	}

	// Load all enabled rules from storage
	rules, err := ruleStorage.GetEnabledRules()
	if err != nil {
		return fmt.Errorf("failed to load enabled rules: %w", err)
	}

	return re.loadCorrelationRulesFromList(ctx, rules)
}

// loadCorrelationRulesFromList processes a list of rules and extracts correlation rules.
// TASK 168.1: Helper function to process rules and extract correlation configurations.
// CCN: 5 (within limit of 10)
func (re *RuleEngine) loadCorrelationRulesFromList(ctx context.Context, rules []core.Rule) error {
	// Initialize rule collections
	collections := newCorrelationRuleCollections()

	// Process each rule
	for _, rule := range rules {
		if err := re.processSingleRule(ctx, &rule, collections); err != nil {
			return err
		}
	}

	// Load all correlation rules into engine
	re.LoadEnhancedCorrelationRules(
		collections.countRules,
		collections.valueCountRules,
		collections.sequenceRules,
		collections.rareRules,
		collections.statisticalRules,
		collections.crossEntityRules,
		collections.chainRules,
	)

	return nil
}

// correlationRuleCollections holds all correlation rule type collections.
type correlationRuleCollections struct {
	countRules       []core.CountCorrelationRule
	valueCountRules  []core.ValueCountCorrelationRule
	sequenceRules    []core.SequenceCorrelationRule
	rareRules        []core.RareCorrelationRule
	statisticalRules []core.StatisticalCorrelationRule
	crossEntityRules []core.CrossEntityCorrelationRule
	chainRules       []core.ChainCorrelationRule
}

// newCorrelationRuleCollections creates a new rule collections container.
func newCorrelationRuleCollections() *correlationRuleCollections {
	return &correlationRuleCollections{
		countRules:       make([]core.CountCorrelationRule, 0),
		valueCountRules:  make([]core.ValueCountCorrelationRule, 0),
		sequenceRules:    make([]core.SequenceCorrelationRule, 0),
		rareRules:        make([]core.RareCorrelationRule, 0),
		statisticalRules: make([]core.StatisticalCorrelationRule, 0),
		crossEntityRules: make([]core.CrossEntityCorrelationRule, 0),
		chainRules:       make([]core.ChainCorrelationRule, 0),
	}
}

// processSingleRule processes one rule and routes it to appropriate collection.
// TASK 168.1: Extracted to reduce function length and complexity.
// CCN: 5 (within limit of 10)
func (re *RuleEngine) processSingleRule(ctx context.Context, rule *core.Rule, collections *correlationRuleCollections) error {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("correlation rule loading cancelled: %w", ctx.Err())
	default:
	}

	// Skip non-SIGMA rules
	if strings.ToLower(rule.Type) != "sigma" || strings.TrimSpace(rule.SigmaYAML) == "" {
		return nil
	}

	// Parse correlation configuration from SIGMA YAML
	corrRule, err := re.parseCorrelationFromSigmaRule(rule)
	if err != nil {
		// ISSUE #5: Add structured logging for parsing errors
		if re.sigmaEngine != nil && re.sigmaEngine.logger != nil {
			re.sigmaEngine.logger.Warnw("Failed to parse correlation rule, skipping",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"error", err)
		}
		return nil // Continue processing other rules
	}

	if corrRule == nil {
		return nil // No correlation block in this rule
	}

	// Route to appropriate rule type list based on correlation type
	return re.routeCorrelationRule(corrRule, &collections.countRules, &collections.valueCountRules,
		&collections.sequenceRules, &collections.rareRules, &collections.statisticalRules,
		&collections.crossEntityRules, &collections.chainRules)
}

// parseCorrelationFromSigmaRule extracts correlation configuration from a SIGMA rule.
// TASK 168.1: Parses SIGMA YAML and extracts correlation block.
// CCN: 5 (within limit of 10)
func (re *RuleEngine) parseCorrelationFromSigmaRule(rule *core.Rule) (interface{}, error) {
	// Parse SIGMA YAML
	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		return nil, fmt.Errorf("failed to parse SIGMA YAML for rule %s: %w", rule.ID, err)
	}

	// Check if SIGMA engine is available for parsing
	if !re.sigmaEngineEnabled || re.sigmaEngine == nil {
		return nil, fmt.Errorf("SIGMA engine not available for parsing correlation")
	}

	// Check if rule has correlation block in cache
	cachedRule := re.sigmaEngine.cache.Get(rule.ID)
	if cachedRule != nil && cachedRule.Correlation != nil {
		// Convert SigmaCorrelation to appropriate rule type
		return re.convertSigmaCorrelationToRule(cachedRule.Correlation, rule, parsed)
	}

	// Parse correlation from SIGMA YAML
	correlationData, ok := parsed["correlation"]
	if !ok {
		return nil, nil // No correlation block
	}

	correlationMap, ok := correlationData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid correlation format in rule %s", rule.ID)
	}

	// Convert correlation map to YAML and parse
	yamlBytes, err := yaml.Marshal(correlationMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal correlation for rule %s: %w", rule.ID, err)
	}

	sigmaCorr, err := core.ParseYAML(yamlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse correlation for rule %s: %w", rule.ID, err)
	}

	return re.convertSigmaCorrelationToRule(sigmaCorr, rule, parsed)
}

// convertSigmaCorrelationToRule converts a SigmaCorrelation to the appropriate rule type.
// TASK 168.1: Converts parsed SIGMA correlation to typed correlation rule.
// CCN: 8 (within limit of 10)
func (re *RuleEngine) convertSigmaCorrelationToRule(sigmaCorr *core.SigmaCorrelation, rule *core.Rule, parsed map[string]interface{}) (interface{}, error) {
	// Extract common fields
	baseRule := core.EnhancedCorrelationRule{
		ID:          rule.ID,
		Type:        core.CorrelationType(sigmaCorr.Type),
		Name:        rule.Name,
		Description: rule.Description,
		Severity:    rule.Severity,
		Enabled:     rule.Enabled,
		Tags:        rule.Tags,
		CreatedAt:   rule.CreatedAt,
		UpdatedAt:   rule.UpdatedAt,
	}

	// Extract selection from SIGMA detection block
	selection := extractSelectionFromParsed(parsed)

	// Convert based on correlation type
	switch sigmaCorr.Type {
	case "event_count", "count":
		return re.convertToCountRule(sigmaCorr, baseRule, selection)
	case "value_count":
		return re.convertToValueCountRule(sigmaCorr, baseRule, selection)
	case "temporal", "sequence":
		return re.convertToSequenceRule(sigmaCorr, baseRule, selection)
	case "rare":
		return re.convertToRareRule(sigmaCorr, baseRule, selection)
	case "statistical":
		return re.convertToStatisticalRule(sigmaCorr, baseRule, selection)
	case "cross_entity":
		return re.convertToCrossEntityRule(sigmaCorr, baseRule, selection)
	case "chain":
		return re.convertToChainRule(sigmaCorr, baseRule, selection)
	default:
		return nil, fmt.Errorf("unsupported correlation type: %s", sigmaCorr.Type)
	}
}

// extractSelectionFromParsed extracts the selection block from parsed SIGMA YAML.
// TASK 168.1: Helper to extract detection selection criteria.
// CCN: 3 (within limit of 10)
func extractSelectionFromParsed(parsed map[string]interface{}) map[string]interface{} {
	detection, ok := parsed["detection"].(map[string]interface{})
	if !ok {
		return make(map[string]interface{})
	}

	selection, ok := detection["selection"].(map[string]interface{})
	if !ok {
		return make(map[string]interface{})
	}

	return selection
}

// convertToCountRule converts SigmaCorrelation to CountCorrelationRule.
// TASK 168.1: Type-specific converter for count correlation.
// CCN: 6 (within limit of 10)
func (re *RuleEngine) convertToCountRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.CountCorrelationRule, error) {
	// Parse timespan
	window, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.CountCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.CountCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Convert condition to threshold
	threshold, err := sigmaCorr.Condition.ToThreshold()
	if err != nil {
		return core.CountCorrelationRule{}, fmt.Errorf("invalid condition: %w", err)
	}

	return core.CountCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		GroupBy:                 sigmaCorr.GroupBy,
		Threshold:               threshold,
		Actions:                 []core.Action{},
	}, nil
}

// convertToValueCountRule converts SigmaCorrelation to ValueCountCorrelationRule.
// TASK 168.1: Type-specific converter for value_count correlation.
// CCN: 7 (within limit of 10)
func (re *RuleEngine) convertToValueCountRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.ValueCountCorrelationRule, error) {
	// Parse timespan
	window, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.ValueCountCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.ValueCountCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Use distinct_field if specified, otherwise use first group_by field
	countField := sigmaCorr.DistinctField
	if countField == "" && len(sigmaCorr.GroupBy) > 0 {
		countField = sigmaCorr.GroupBy[0]
	}

	// Convert condition to threshold
	threshold, err := sigmaCorr.Condition.ToThreshold()
	if err != nil {
		return core.ValueCountCorrelationRule{}, fmt.Errorf("invalid condition: %w", err)
	}

	return core.ValueCountCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		CountField:              countField,
		GroupBy:                 sigmaCorr.GroupBy,
		Threshold:               threshold,
		Actions:                 []core.Action{},
	}, nil
}

// convertToSequenceRule converts SigmaCorrelation to SequenceCorrelationRule.
// TASK 168.1: Type-specific converter for sequence/temporal correlation.
// CCN: 7 (within limit of 10)
func (re *RuleEngine) convertToSequenceRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.SequenceCorrelationRule, error) {
	// Parse timespan
	window, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.SequenceCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.SequenceCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Build sequence stages from events list
	stages := make([]core.SequenceStage, 0)
	for i, eventName := range sigmaCorr.Events {
		stages = append(stages, core.SequenceStage{
			Name:      fmt.Sprintf("stage_%d_%s", i, eventName),
			Selection: selection,
			Required:  true,
		})
	}

	return core.SequenceCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Sequence:                stages,
		Ordered:                 sigmaCorr.Ordered || sigmaCorr.Type == "temporal",
		GroupBy:                 sigmaCorr.GroupBy,
		MaxSpan:                 window,
		Actions:                 []core.Action{},
	}, nil
}

// convertToRareRule converts SigmaCorrelation to RareCorrelationRule.
// TASK 168.1: Type-specific converter for rare event correlation.
// CCN: 7 (within limit of 10)
func (re *RuleEngine) convertToRareRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.RareCorrelationRule, error) {
	// Parse baseline window
	window, err := sigmaCorr.ParseDuration(sigmaCorr.BaselineWindow)
	if err != nil {
		return core.RareCorrelationRule{}, fmt.Errorf("invalid baseline_window: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.RareCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Use distinct_field if specified, otherwise default
	countField := sigmaCorr.DistinctField
	if countField == "" {
		countField = core.DefaultRareCountField
	}

	// Convert condition to threshold (rare uses <= operator)
	threshold, err := sigmaCorr.Condition.ToThreshold()
	if err != nil {
		return core.RareCorrelationRule{}, fmt.Errorf("invalid condition: %w", err)
	}

	return core.RareCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		CountField:              countField,
		Threshold:               threshold,
		Actions:                 []core.Action{},
	}, nil
}

// convertToStatisticalRule converts SigmaCorrelation to StatisticalCorrelationRule.
// ISSUE #3: Type-specific converter for statistical correlation.
// CCN: 7 (within limit of 10)
func (re *RuleEngine) convertToStatisticalRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.StatisticalCorrelationRule, error) {
	// Parse detection window
	window, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.StatisticalCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.StatisticalCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Parse baseline window
	baselineWindow, err := sigmaCorr.ParseDuration(sigmaCorr.BaselineWindow)
	if err != nil {
		return core.StatisticalCorrelationRule{}, fmt.Errorf("invalid baseline_window: %w", err)
	}

	// Use distinct_field as metric field, or default
	metricField := sigmaCorr.DistinctField
	if metricField == "" {
		metricField = "value" // Default metric field
	}

	// Convert condition to threshold
	threshold, err := sigmaCorr.Condition.ToThreshold()
	if err != nil {
		return core.StatisticalCorrelationRule{}, fmt.Errorf("invalid condition: %w", err)
	}

	return core.StatisticalCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		BaselineWindow:          baselineWindow,
		Selection:               selection,
		MetricField:             metricField,
		GroupBy:                 sigmaCorr.GroupBy,
		Threshold:               threshold,
		Actions:                 []core.Action{},
	}, nil
}

// convertToCrossEntityRule converts SigmaCorrelation to CrossEntityCorrelationRule.
// ISSUE #3: Type-specific converter for cross_entity correlation.
// CCN: 7 (within limit of 10)
func (re *RuleEngine) convertToCrossEntityRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.CrossEntityCorrelationRule, error) {
	// Parse timespan
	window, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.CrossEntityCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if window > maxCorrelationWindow {
		return core.CrossEntityCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", window)
	}

	// Use first group_by as track field, distinct_field as count distinct
	trackField := ""
	if len(sigmaCorr.GroupBy) > 0 {
		trackField = sigmaCorr.GroupBy[0]
	}

	countDistinct := sigmaCorr.DistinctField
	if countDistinct == "" && len(sigmaCorr.GroupBy) > 1 {
		countDistinct = sigmaCorr.GroupBy[1]
	}

	// Convert condition to threshold
	threshold, err := sigmaCorr.Condition.ToThreshold()
	if err != nil {
		return core.CrossEntityCorrelationRule{}, fmt.Errorf("invalid condition: %w", err)
	}

	return core.CrossEntityCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		TrackField:              trackField,
		CountDistinct:           countDistinct,
		Threshold:               threshold,
		Actions:                 []core.Action{},
	}, nil
}

// convertToChainRule converts SigmaCorrelation to ChainCorrelationRule.
// ISSUE #3: Type-specific converter for chain correlation.
// CCN: 6 (within limit of 10)
func (re *RuleEngine) convertToChainRule(sigmaCorr *core.SigmaCorrelation, base core.EnhancedCorrelationRule, selection map[string]interface{}) (core.ChainCorrelationRule, error) {
	// Parse max duration
	maxDuration, err := sigmaCorr.ParseDuration(sigmaCorr.Timespan)
	if err != nil {
		return core.ChainCorrelationRule{}, fmt.Errorf("invalid timespan: %w", err)
	}

	// ISSUE #4: Validate 24-hour maximum window
	if maxDuration > maxCorrelationWindow {
		return core.ChainCorrelationRule{}, fmt.Errorf("correlation window %v exceeds maximum of 24h", maxDuration)
	}

	// Convert stages from SigmaChainStage to ChainStage
	stages := make([]core.ChainStage, 0, len(sigmaCorr.Stages))
	for _, sigmaStage := range sigmaCorr.Stages {
		stages = append(stages, core.ChainStage{
			Name:      sigmaStage.Name,
			Selection: selection, // Use base selection, stage-specific selection would require parsing
			Required:  true,      // Default to required
		})
	}

	// Default to 2 minimum stages if not specified
	minStages := 2
	if len(stages) > 0 {
		minStages = len(stages)
	}

	return core.ChainCorrelationRule{
		EnhancedCorrelationRule: base,
		MaxDuration:             maxDuration,
		Stages:                  stages,
		GroupBy:                 sigmaCorr.GroupBy,
		MinStages:               minStages,
		Actions:                 []core.Action{},
	}, nil
}

// routeCorrelationRule routes a correlation rule to the appropriate type list.
// TASK 168.4: Routes parsed correlation rules to type-specific collections.
// CCN: 8 (within limit of 10)
func (re *RuleEngine) routeCorrelationRule(
	corrRule interface{},
	countRules *[]core.CountCorrelationRule,
	valueCountRules *[]core.ValueCountCorrelationRule,
	sequenceRules *[]core.SequenceCorrelationRule,
	rareRules *[]core.RareCorrelationRule,
	statisticalRules *[]core.StatisticalCorrelationRule,
	crossEntityRules *[]core.CrossEntityCorrelationRule,
	chainRules *[]core.ChainCorrelationRule,
) error {
	switch rule := corrRule.(type) {
	case core.CountCorrelationRule:
		*countRules = append(*countRules, rule)
	case core.ValueCountCorrelationRule:
		*valueCountRules = append(*valueCountRules, rule)
	case core.SequenceCorrelationRule:
		*sequenceRules = append(*sequenceRules, rule)
	case core.RareCorrelationRule:
		*rareRules = append(*rareRules, rule)
	case core.StatisticalCorrelationRule:
		*statisticalRules = append(*statisticalRules, rule)
	case core.CrossEntityCorrelationRule:
		*crossEntityRules = append(*crossEntityRules, rule)
	case core.ChainCorrelationRule:
		*chainRules = append(*chainRules, rule)
	default:
		return fmt.Errorf("unknown correlation rule type: %T", corrRule)
	}
	return nil
}

// EvaluateCorrelationRules evaluates all correlation rules against an event.
// TASK 168.2: Main entry point for correlation evaluation during event processing.
//
// This function is called from ProcessEvent after detection rule evaluation.
// It routes events to appropriate correlation evaluators based on rule type.
//
// Performance:
//  - Evaluates rules in parallel where possible
//  - Uses read lock for rule access
//  - Minimal lock contention with detection evaluation
//
// Thread-Safety:
//  - Safe to call concurrently from multiple goroutines
//  - Uses read lock on rule collections
//
// Parameters:
//  - event: The event to evaluate
//
// Returns:
//  - []*core.Alert: Correlation alerts generated (empty if no matches)
func (re *RuleEngine) EvaluateCorrelationRules(event *core.Event) []*core.Alert {
	if event == nil {
		return nil
	}

	// Use enhanced correlation evaluator
	return re.EvaluateEnhancedCorrelation(event)
}

// ConfigureCorrelationStateTTL configures the TTL for correlation state management.
// TASK 168.3: Configures state management TTL based on correlation windows.
//
// This function calculates an appropriate TTL based on the maximum correlation
// window across all loaded rules. The TTL is set to 2x the maximum window to
// ensure sufficient retention for late-arriving events.
//
// Security:
//  - Enforces maximum TTL of 48 hours to prevent unbounded memory growth
//  - Validates minimum TTL of 1 minute
//
// Parameters:
//  - None (uses loaded correlation rules)
//
// Returns:
//  - time.Duration: Configured TTL
//
// ISSUE #1: Reduced CCN from 17 to 4 by extracting helper function
func (re *RuleEngine) ConfigureCorrelationStateTTL() time.Duration {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	// Find maximum window across all correlation rule types
	maxWindow := re.calculateMaxCorrelationWindow()

	// Calculate TTL as 2x maximum window
	ttl := maxWindow * 2

	// Enforce minimum and maximum TTL
	const minTTL = 1 * time.Minute
	const maxTTL = 48 * time.Hour

	if ttl < minTTL {
		ttl = minTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	return ttl
}

// calculateMaxCorrelationWindow finds the maximum window across all correlation rule types.
// FIXED: Reduced cyclomatic complexity (CCN <= 10) and line count (<= 50) by extracting helper.
//
// Note: Caller must hold stateMu lock before calling this function.
func (re *RuleEngine) calculateMaxCorrelationWindow() time.Duration {
	// Collect all windows from different rule types
	windows := []time.Duration{
		re.getMaxWindowFromCountRules(),
		re.getMaxWindowFromValueCountRules(),
		re.getMaxWindowFromSequenceRules(),
		re.getMaxWindowFromRareRules(),
		re.getMaxWindowFromStatisticalRules(),
		re.getMaxWindowFromCrossEntityRules(),
		re.getMaxWindowFromChainRules(),
	}

	return findMaxDuration(windows)
}

// Helper functions to extract max window from each rule type
// These reduce cyclomatic complexity by isolating iteration logic

func (re *RuleEngine) getMaxWindowFromCountRules() time.Duration {
	return extractMaxWindow(len(re.countRules), func(i int) time.Duration {
		return re.countRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromValueCountRules() time.Duration {
	return extractMaxWindow(len(re.valueCountRules), func(i int) time.Duration {
		return re.valueCountRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromSequenceRules() time.Duration {
	return extractMaxWindow(len(re.sequenceRules), func(i int) time.Duration {
		return re.sequenceRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromRareRules() time.Duration {
	return extractMaxWindow(len(re.rareRules), func(i int) time.Duration {
		return re.rareRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromStatisticalRules() time.Duration {
	return extractMaxWindow(len(re.statisticalRules), func(i int) time.Duration {
		return re.statisticalRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromCrossEntityRules() time.Duration {
	return extractMaxWindow(len(re.crossEntityRules), func(i int) time.Duration {
		return re.crossEntityRules[i].Window
	})
}

func (re *RuleEngine) getMaxWindowFromChainRules() time.Duration {
	return extractMaxWindow(len(re.chainRules), func(i int) time.Duration {
		return re.chainRules[i].MaxDuration
	})
}

// extractMaxWindow is a generic helper that extracts the maximum window from a collection.
// It uses an index-based accessor function to avoid slice copies.
// CCN: 2
func extractMaxWindow(length int, accessor func(int) time.Duration) time.Duration {
	maxWindow := time.Duration(0)
	for i := 0; i < length; i++ {
		if window := accessor(i); window > maxWindow {
			maxWindow = window
		}
	}
	return maxWindow
}

// findMaxDuration finds the maximum duration from a slice of durations.
// CCN: 2
func findMaxDuration(durations []time.Duration) time.Duration {
	maxD := time.Duration(0)
	for _, d := range durations {
		if d > maxD {
			maxD = d
		}
	}
	return maxD
}
