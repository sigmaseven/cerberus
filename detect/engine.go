package detect

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

const (
	// MaxCorrelationEventsPerRule limits events stored per correlation rule to prevent memory exhaustion
	// SECURITY: This prevents unbounded memory growth in correlation state
	MaxCorrelationEventsPerRule = 1000
	// MaxCorrelationRulesTracked limits the number of rules with active state
	MaxCorrelationRulesTracked = 100
)

// RuleEngine evaluates rules against events
type RuleEngine struct {
	rules            []core.Rule
	correlationRules []core.CorrelationRule
	correlationState map[string][]*core.Event // ruleID -> events in window (legacy)
	stateMu          sync.RWMutex             // protects rules and correlationRules slices
	correlationMu    sync.RWMutex             // protects correlationState map (separate to avoid deadlock)
	correlationTTL   int                      // seconds
	cleanupCancel    context.CancelFunc       // for stopping cleanup goroutine
	cleanupWg        sync.WaitGroup           // for waiting on cleanup goroutine
	ctx              context.Context          // TASK 144.4: Parent context for SIGMA engine initialization

	// Enhanced correlation support
	enhancedCorrelationStore     CorrelationStateStore
	enhancedCorrelationEvaluator *EnhancedCorrelationEvaluator
	countRules                   []core.CountCorrelationRule
	valueCountRules              []core.ValueCountCorrelationRule
	sequenceRules                []core.SequenceCorrelationRule
	rareRules                    []core.RareCorrelationRule
	statisticalRules             []core.StatisticalCorrelationRule
	crossEntityRules             []core.CrossEntityCorrelationRule
	chainRules                   []core.ChainCorrelationRule

	// SIGMA engine support - Task #131.2
	sigmaEngine        *SigmaEngine // Native SIGMA detection engine
	sigmaEngineEnabled bool         // Feature flag for SIGMA engine
}

// RuleEngineConfig holds configuration for the rule engine
// TASK #131.2: Configuration structure for SIGMA engine integration
type RuleEngineConfig struct {
	// SIGMA Engine Configuration
	EnableNativeSigmaEngine    bool          // Enable native SIGMA engine
	SigmaFieldMappingConfig    string        // Path to field mapping YAML
	SigmaEngineCacheSize       int           // Cache size for parsed SIGMA rules
	SigmaEngineCacheTTL        time.Duration // Cache TTL for SIGMA rules
	SigmaEngineCleanupInterval time.Duration // Cleanup interval for cache

	// Logger for structured logging
	Logger *zap.SugaredLogger
}

// NewRuleEngine creates a new rule engine with default configuration
// BACKWARD COMPATIBILITY: This maintains the original signature for existing code
// TASK 144.4: Delegates to context-aware constructor with background context
func NewRuleEngine(rules []core.Rule, correlationRules []core.CorrelationRule, correlationTTL int) *RuleEngine {
	return NewRuleEngineWithContext(context.Background(), rules, correlationRules, correlationTTL, nil)
}

// NewRuleEngineWithConfig creates a new rule engine with explicit configuration
// BACKWARD COMPATIBILITY: Maintains config signature using background context
// TASK 144.4: Delegates to context-aware constructor
func NewRuleEngineWithConfig(rules []core.Rule, correlationRules []core.CorrelationRule, correlationTTL int, config *RuleEngineConfig) *RuleEngine {
	return NewRuleEngineWithContext(context.Background(), rules, correlationRules, correlationTTL, config)
}

// NewRuleEngineWithContext creates a new rule engine with parent context for lifecycle management
// TASK 144.4: New constructor that accepts parent context for graceful shutdown
// TASK 131.2: Supports SIGMA engine configuration
// PRODUCTION: This is the recommended constructor for new code
//
// Parameters:
//   - parentCtx: Parent context for lifecycle coordination (cancellation propagates to cleanup goroutines)
//   - rules: Detection rules to load
//   - correlationRules: Correlation rules to load
//   - correlationTTL: Time-to-live for correlation state (seconds)
//   - config: Engine configuration (nil = use defaults, SIGMA engine disabled)
//
// Returns:
//   - Configured RuleEngine instance (goroutines started automatically)
//
// Lifecycle:
//   - Cleanup goroutines start automatically in constructor
//   - Call Stop() OR cancel parentCtx to stop goroutines
//   - Stop() is safe to call multiple times
//   - Goroutines exit gracefully when context is cancelled
//
// Thread-Safety:
//   - Safe to call from multiple goroutines
//   - Engine methods are thread-safe after creation
//
// Example:
//
//	appCtx, appCancel := context.WithCancel(context.Background())
//	defer appCancel()
//
//	config := &RuleEngineConfig{
//	    EnableNativeSigmaEngine: true,
//	    SigmaFieldMappingConfig: "config/sigma_field_mappings.yaml",
//	    SigmaEngineCacheSize: 1000,
//	    SigmaEngineCacheTTL: 30 * time.Minute,
//	    SigmaEngineCleanupInterval: 5 * time.Minute,
//	    Logger: sugar,
//	}
//	engine := NewRuleEngineWithContext(appCtx, rules, correlationRules, 3600, config)
//	defer engine.Stop()
//
// Graceful Shutdown:
//   - Cancelling appCtx will stop all cleanup goroutines
//   - Stop() provides same functionality plus waits for completion
func NewRuleEngineWithContext(parentCtx context.Context, rules []core.Rule, correlationRules []core.CorrelationRule, correlationTTL int, config *RuleEngineConfig) *RuleEngine {
	// TASK 144.4: Derive cancellable context from parent for lifecycle management
	// This allows parent context cancellation to propagate to cleanup goroutines
	ctx, cancel := context.WithCancel(parentCtx)
	store := NewCorrelationStateStore(nil) // Pass nil for logger for now

	re := &RuleEngine{
		rules:                        rules,
		correlationRules:             correlationRules,
		correlationState:             make(map[string][]*core.Event),
		correlationTTL:               correlationTTL,
		cleanupCancel:                cancel,
		ctx:                          ctx, // TASK 144.4: Store context for SIGMA engine
		enhancedCorrelationStore:     store,
		enhancedCorrelationEvaluator: NewEnhancedCorrelationEvaluator(store),
		countRules:                   []core.CountCorrelationRule{},
		valueCountRules:              []core.ValueCountCorrelationRule{},
		sequenceRules:                []core.SequenceCorrelationRule{},
		rareRules:                    []core.RareCorrelationRule{},
		statisticalRules:             []core.StatisticalCorrelationRule{},
		crossEntityRules:             []core.CrossEntityCorrelationRule{},
		chainRules:                   []core.ChainCorrelationRule{},
		sigmaEngine:                  nil, // Will be initialized if enabled
		sigmaEngineEnabled:           false,
	}

	// TASK #184: Always initialize SIGMA engine (now the only evaluation path)
	// Legacy Conditions-based evaluation has been removed
	if config != nil && config.EnableNativeSigmaEngine {
		re.initializeSigmaEngine(config)
	} else {
		// Initialize SIGMA engine with defaults for rules that have SigmaYAML
		re.initializeSigmaEngineWithDefaults()
	}

	// TASK 144.4: Start periodic cleanup with parent-derived context
	// Cleanup goroutine will exit when ctx is cancelled (via Stop() or parent cancellation)
	re.startStateCleanup(ctx)

	return re
}

// initializeSigmaEngine initializes the native SIGMA detection engine
// TASK #131.2: SIGMA engine initialization with configuration
// TASK 144.4: Now passes parent context to SIGMA engine for lifecycle coordination
// SECURITY: Validates field mapping config path to prevent path traversal
// PRODUCTION: Logs initialization status for monitoring
func (re *RuleEngine) initializeSigmaEngine(config *RuleEngineConfig) {
	// Get logger (use provided or create nop logger)
	logger := config.Logger
	if logger == nil {
		// Create a no-op logger if none provided
		zapLogger := zap.NewNop()
		logger = zapLogger.Sugar()
	}

	// Build SIGMA engine configuration
	sigmaConfig := &SigmaEngineConfig{
		CacheConfig: &SigmaRuleCacheConfig{
			MaxEntries:      config.SigmaEngineCacheSize,
			TTL:             config.SigmaEngineCacheTTL,
			CleanupInterval: config.SigmaEngineCleanupInterval,
		},
		RegexTimeout:      5 * time.Second, // Use 5s timeout for SIGMA regex
		MaxFieldValueSize: 1024 * 1024,     // 1MB max field value
		EnableMetrics:     true,            // Always enable metrics
	}

	// TASK 144.4: Create SIGMA engine with parent context for lifecycle coordination
	// This ensures SIGMA cache cleanup goroutine respects parent context cancellation
	re.sigmaEngine = NewSigmaEngine(re.ctx, sigmaConfig, logger)

	// Load field mappings if config path is provided
	if config.SigmaFieldMappingConfig != "" {
		if err := re.sigmaEngine.LoadFieldMappings(config.SigmaFieldMappingConfig); err != nil {
			// Log error but continue (graceful degradation)
			// SIGMA rules will still work but field mapping may be incomplete
			logger.Warnf("Failed to load SIGMA field mappings from %s: %v", config.SigmaFieldMappingConfig, err)
		}
	}

	// Start the engine (starts background cache cleanup)
	re.sigmaEngine.Start()
	re.sigmaEngineEnabled = true

	logger.Infof("SIGMA engine initialized with cache_size=%d, ttl=%v, cleanup_interval=%v",
		config.SigmaEngineCacheSize,
		config.SigmaEngineCacheTTL,
		config.SigmaEngineCleanupInterval)
}

// initializeSigmaEngineWithDefaults initializes the SIGMA engine with default configuration
// TASK #184: This is called when NewRuleEngine is used without explicit config
// The SIGMA engine is now required since legacy Conditions evaluation was removed
func (re *RuleEngine) initializeSigmaEngineWithDefaults() {
	// Create no-op logger for default initialization
	zapLogger := zap.NewNop()
	logger := zapLogger.Sugar()

	// Build SIGMA engine configuration with sensible defaults
	sigmaConfig := &SigmaEngineConfig{
		CacheConfig: &SigmaRuleCacheConfig{
			MaxEntries:      1000,              // Default cache size
			TTL:             time.Hour,         // Default TTL
			CleanupInterval: 10 * time.Minute,  // Default cleanup interval
		},
		RegexTimeout:      5 * time.Second, // 5s timeout for SIGMA regex
		MaxFieldValueSize: 1024 * 1024,     // 1MB max field value
		EnableMetrics:     true,            // Always enable metrics
	}

	// Create SIGMA engine with parent context for lifecycle coordination
	re.sigmaEngine = NewSigmaEngine(re.ctx, sigmaConfig, logger)

	// Start the engine (starts background cache cleanup)
	re.sigmaEngine.Start()
	re.sigmaEngineEnabled = true
}

// ResetCorrelationState clears the correlation state map
func (re *RuleEngine) ResetCorrelationState() {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.correlationState = make(map[string][]*core.Event)
}

// ReloadRules atomically replaces the current rule set with a new one
// CONCURRENCY: Uses write lock to prevent race conditions during rule evaluation
// PRODUCTION: Enables dynamic rule updates without system restart
// OBSERVABILITY: Logs reload operations with before/after counts for monitoring
func (re *RuleEngine) ReloadRules(newRules []core.Rule) {
	re.stateMu.Lock()
	oldCount := len(re.rules)
	re.rules = newRules
	newCount := len(newRules)
	re.stateMu.Unlock()

	// Log AFTER releasing lock to minimize critical section
	log.Printf("INFO: Rules reloaded - old=%d new=%d", oldCount, newCount)
}

// ReloadCorrelationRules atomically replaces the current correlation rule set
// CONCURRENCY: Uses write lock to prevent race conditions during rule evaluation
// PRODUCTION: Enables dynamic correlation rule updates without system restart
// OBSERVABILITY: Logs reload operations with before/after counts for monitoring
func (re *RuleEngine) ReloadCorrelationRules(newRules []core.CorrelationRule) {
	// LOCK ORDERING: Always acquire stateMu before correlationMu to prevent deadlock
	re.stateMu.Lock()
	oldCount := len(re.correlationRules)
	re.correlationRules = newRules
	newCount := len(newRules)
	re.stateMu.Unlock()

	// Reset correlation state when rules change to prevent stale state issues
	// Use correlationMu (not stateMu) for state operations
	re.correlationMu.Lock()
	re.correlationState = make(map[string][]*core.Event)
	re.correlationMu.Unlock()

	// Log AFTER releasing locks to minimize critical section
	log.Printf("INFO: Correlation rules reloaded - old=%d new=%d (state reset)", oldCount, newCount)
}

// ReloadSigmaEngine invalidates the SIGMA engine cache to force re-parsing of rules
// TASK #131.2: Cache invalidation for SIGMA rules
// PRODUCTION: Use this when SIGMA rules are updated or field mappings change
// THREAD-SAFETY: Safe to call concurrently with rule evaluation
//
// Use Cases:
//   - After updating SIGMA rules in the database
//   - After modifying field mapping configuration
//   - During hot-reload of rule sets
//
// Performance Note:
//   - Invalidation is immediate and thread-safe
//   - Next evaluation will re-parse affected rules (higher latency)
//   - Cache will repopulate over time with frequently-used rules
func (re *RuleEngine) ReloadSigmaEngine() {
	if !re.sigmaEngineEnabled || re.sigmaEngine == nil {
		return
	}

	// Invalidate all cached SIGMA rules
	// This forces re-parsing on next evaluation
	re.sigmaEngine.InvalidateAllCache()

	log.Printf("INFO: SIGMA engine cache invalidated - rules will be re-parsed on next evaluation")
}

// ReloadSigmaEngineRule invalidates a specific SIGMA rule from the cache
// TASK #131.2: Single-rule cache invalidation
// PRODUCTION: Use this for targeted cache updates when only one rule changes
// THREAD-SAFETY: Safe to call concurrently
//
// Parameters:
//   - ruleID: The ID of the SIGMA rule to invalidate
//
// Performance Note:
//   - More efficient than ReloadSigmaEngine() when only one rule changed
//   - Other cached rules remain valid
func (re *RuleEngine) ReloadSigmaEngineRule(ruleID string) {
	if !re.sigmaEngineEnabled || re.sigmaEngine == nil {
		return
	}

	re.sigmaEngine.InvalidateCache(ruleID)
	log.Printf("INFO: SIGMA rule %s invalidated from cache", ruleID)
}

// GetRuleCount returns the current number of loaded rules (thread-safe)
func (re *RuleEngine) GetRuleCount() int {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()
	return len(re.rules)
}

// GetCorrelationRuleCount returns the current number of loaded correlation rules (thread-safe)
func (re *RuleEngine) GetCorrelationRuleCount() int {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()
	return len(re.correlationRules)
}

// GetLoadedRules returns a copy of currently loaded rules
// BLOCKING-1 FIX: Used for performance tracking instrumentation
// THREAD-SAFETY: Returns a copy to prevent race conditions
func (re *RuleEngine) GetLoadedRules() []core.Rule {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	// Return a copy to prevent external modification
	rulesCopy := make([]core.Rule, len(re.rules))
	copy(rulesCopy, re.rules)
	return rulesCopy
}

// GetCorrelationStateStats returns statistics about correlation state memory usage
// SECURITY: Provides visibility into memory consumption for monitoring
func (re *RuleEngine) GetCorrelationStateStats() map[string]interface{} {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	totalEvents := 0
	totalRules := len(re.correlationState)
	maxEventsInRule := 0

	for _, events := range re.correlationState {
		eventCount := len(events)
		totalEvents += eventCount
		if eventCount > maxEventsInRule {
			maxEventsInRule = eventCount
		}
	}

	return map[string]interface{}{
		"total_rules_tracked":       totalRules,
		"max_rules_limit":           MaxCorrelationRulesTracked,
		"total_events_in_memory":    totalEvents,
		"max_events_in_one_rule":    maxEventsInRule,
		"max_events_per_rule_limit": MaxCorrelationEventsPerRule,
		"memory_usage_warning":      totalRules > MaxCorrelationRulesTracked*0.8 || maxEventsInRule > MaxCorrelationEventsPerRule*0.8,
	}
}

// GetSigmaEngineStats returns statistics about SIGMA engine performance
// TASK #131.2: SIGMA engine metrics for monitoring and observability
// PRODUCTION: Use this for dashboard metrics and performance tuning
// THREAD-SAFETY: Safe to call concurrently (uses atomic operations internally)
//
// Returns:
//   - map with metrics: evaluations, cache_hits, cache_misses, matches, errors, etc.
//   - nil if SIGMA engine is not enabled
//
// Metrics Included:
//   - enabled: Whether SIGMA engine is active
//   - evaluations: Total SIGMA rule evaluations
//   - cache_hits: Number of cache hits (parsed rule reused)
//   - cache_misses: Number of cache misses (rule had to be parsed)
//   - matches: Number of successful rule matches
//   - errors: Number of evaluation errors
//   - parse_errors: Number of YAML/condition parsing errors
//   - avg_eval_time_ns: Average evaluation time in nanoseconds
//   - cache_hit_rate: Cache hit percentage (0-100)
func (re *RuleEngine) GetSigmaEngineStats() map[string]interface{} {
	if !re.sigmaEngineEnabled || re.sigmaEngine == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	// Get metrics snapshot from SIGMA engine
	metrics := re.sigmaEngine.GetMetrics()
	cacheStats := re.sigmaEngine.GetCacheStats()

	// Calculate derived metrics
	var avgEvalTimeNs int64
	if metrics.Evaluations > 0 {
		avgEvalTimeNs = metrics.TotalEvaluationNanos / metrics.Evaluations
	}

	var cacheHitRate float64
	totalCacheAccess := metrics.CacheHits + metrics.CacheMisses
	if totalCacheAccess > 0 {
		cacheHitRate = float64(metrics.CacheHits) / float64(totalCacheAccess) * 100.0
	}

	return map[string]interface{}{
		"enabled":          true,
		"evaluations":      metrics.Evaluations,
		"cache_hits":       metrics.CacheHits,
		"cache_misses":     metrics.CacheMisses,
		"matches":          metrics.Matches,
		"errors":           metrics.Errors,
		"parse_errors":     metrics.ParseErrors,
		"avg_eval_time_ns": avgEvalTimeNs,
		"cache_hit_rate":   cacheHitRate,
		"cache_size":       cacheStats.Size,
		"cache_evictions":  cacheStats.Evictions,
	}
}

// Stop cleanup goroutine and release resources
// TASK #131.2: Updated to stop SIGMA engine if enabled
// TASK 144.4: Ensures SIGMA engine is stopped BEFORE correlation cleanup
//
// Shutdown Order (CRITICAL for preventing race conditions):
//  1. Stop SIGMA engine first (may access RuleEngine state during cleanup)
//  2. Stop enhanced correlation store
//  3. Cancel RuleEngine's cleanup goroutine
//  4. Wait for all goroutines to complete
//
// Thread-Safety:
//   - Safe to call multiple times (idempotent)
//   - Waits for all goroutines to exit before returning
//   - No deadlocks due to proper shutdown order
func (re *RuleEngine) Stop() {
	// TASK 144.4: Stop SIGMA engine FIRST since it may depend on RuleEngine state
	// This stops the cache cleanup goroutine and waits for it to exit
	if re.sigmaEngineEnabled && re.sigmaEngine != nil {
		re.sigmaEngine.Stop()
	}

	// Stop the enhanced correlation store's cleanup goroutine
	// This fixes the goroutine leak where the store's periodic cleanup
	// would run forever because its context was never cancelled
	if re.enhancedCorrelationStore != nil {
		re.enhancedCorrelationStore.Stop()
	}

	// Cancel the RuleEngine's own cleanup goroutine
	if re.cleanupCancel != nil {
		re.cleanupCancel()
	}

	// Wait for RuleEngine's cleanup goroutine to finish
	// TASK 144.4: SIGMA engine goroutines already exited via sigmaEngine.Stop() above
	re.cleanupWg.Wait()
}

// startStateCleanup runs periodic cleanup of expired correlation state
// SECURITY: Runs more frequently to prevent memory accumulation
// BLOCKING-4 FIX: Enhanced panic recovery and added timeout protection to cleanup operation
func (re *RuleEngine) startStateCleanup(ctx context.Context) {
	// Calculate cleanup interval - run every 5 minutes or TTL/4, whichever is smaller
	// More frequent cleanup prevents memory accumulation
	cleanupInterval := time.Duration(re.correlationTTL/4) * time.Second
	if cleanupInterval < 30*time.Second {
		cleanupInterval = 30 * time.Second
	}
	if cleanupInterval > 5*time.Minute {
		cleanupInterval = 5 * time.Minute
	}

	ticker := time.NewTicker(cleanupInterval)
	re.cleanupWg.Add(1)
	go func() {
		defer re.cleanupWg.Done()
		// BLOCKING-4 FIX: Explicit panic recovery with structured logging
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ERROR: RuleEngine cleanup goroutine panicked: %v", r)
			}
		}()
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// BLOCKER-1 FIX: Call cleanup directly without timeout goroutine wrapper
				// Background cleanup is non-critical - blocking is acceptable
				// Previous timeout pattern leaked goroutines under lock contention
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("ERROR: cleanupExpiredState panicked: %v", r)
						}
					}()
					re.cleanupExpiredState()
				}()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupExpiredState removes expired entries from correlation state
func (re *RuleEngine) cleanupExpiredState() {
	re.correlationMu.Lock()
	defer re.correlationMu.Unlock()

	now := time.Now()
	ttlDuration := time.Duration(re.correlationTTL) * time.Second

	for ruleID, events := range re.correlationState {
		if len(events) == 0 {
			delete(re.correlationState, ruleID)
			continue
		}

		// Check if oldest event is expired
		oldestEvent := events[0]
		if now.Sub(oldestEvent.Timestamp) > ttlDuration {
			// Remove all expired events
			cutoff := now.Add(-ttlDuration)
			validIdx := sort.Search(len(events), func(i int) bool {
				return events[i].Timestamp.After(cutoff)
			})

			if validIdx >= len(events) {
				// All events expired
				delete(re.correlationState, ruleID)
			} else {
				// Keep only valid events
				re.correlationState[ruleID] = events[validIdx:]
			}
		}
	}
}

// Evaluate evaluates all rules against an event and returns matching rules
// CONCURRENCY: Uses read lock to prevent race conditions with ReloadRules
func (re *RuleEngine) Evaluate(event *core.Event) []core.AlertableRule {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	var matches []core.AlertableRule
	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}
		if re.evaluateRule(rule, event) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// EvaluateCorrelation evaluates correlation rules and returns matching ones
// CONCURRENCY: Uses read lock to prevent race conditions with ReloadCorrelationRules
func (re *RuleEngine) EvaluateCorrelation(event *core.Event) []core.AlertableRule {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	var matches []core.AlertableRule
	for _, rule := range re.correlationRules {
		if re.evaluateCorrelationRule(rule, event) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// correlationProcessResult holds the result of processing correlation events
// TASK 148.4: Helper struct for extracted function return values
type correlationProcessResult struct {
	windowedEvents []*core.Event
	matched        bool
}

// processCorrelationEvents processes events for correlation rule matching.
// TASK 148.4: Extracted from evaluateCorrelationRule to reduce cyclomatic complexity.
// This function performs expensive operations outside the lock.
//
// Operations performed:
//  1. Sort events by timestamp
//  2. Filter expired events (based on TTL)
//  3. Enforce memory limits (MaxCorrelationEventsPerRule)
//  4. Filter events within correlation window
//  5. Check if event sequence matches rule pattern
//
// Parameters:
//   - eventsCopy: copy of existing events plus new event
//   - event: the new event being evaluated
//   - rule: the correlation rule to evaluate
//   - ttlSeconds: TTL for correlation state in seconds
//
// Returns:
//   - correlationProcessResult: processed events and match result
func processCorrelationEvents(eventsCopy []*core.Event, event *core.Event, rule core.CorrelationRule, ttlSeconds int) correlationProcessResult {
	// Sort events by timestamp (most expensive operation)
	sort.Slice(eventsCopy, func(i, j int) bool {
		// SECURITY: Nil check to prevent panic
		if eventsCopy[i] == nil || eventsCopy[j] == nil {
			return false
		}
		if eventsCopy[i].Timestamp.Equal(eventsCopy[j].Timestamp) {
			return eventsCopy[i].EventID < eventsCopy[j].EventID
		}
		return eventsCopy[i].Timestamp.Before(eventsCopy[j].Timestamp)
	})

	// Clean up expired events
	now := event.Timestamp
	ttlDuration := time.Duration(ttlSeconds) * time.Second
	validEvents := make([]*core.Event, 0, len(eventsCopy))
	for _, e := range eventsCopy {
		if e != nil && now.Sub(e.Timestamp) <= ttlDuration {
			validEvents = append(validEvents, e)
		}
	}

	// SECURITY: Enforce maximum events per rule to prevent memory exhaustion
	if len(validEvents) > MaxCorrelationEventsPerRule {
		validEvents = validEvents[len(validEvents)-MaxCorrelationEventsPerRule:]
	}

	// Filter events within the correlation window
	windowStart := now.Add(-rule.Window)
	windowedEvents := make([]*core.Event, 0, len(validEvents))
	for _, e := range validEvents {
		if e.Timestamp.After(windowStart) || e.Timestamp.Equal(windowStart) {
			windowedEvents = append(windowedEvents, e)
		}
	}

	return correlationProcessResult{
		windowedEvents: windowedEvents,
		matched:        false, // Will be set by caller after sequence check
	}
}

// checkSequenceMatch checks if the windowed events match the correlation rule sequence.
// TASK 148.4: Extracted from evaluateCorrelationRule to reduce cyclomatic complexity.
//
// Parameters:
//   - windowedEvents: events within the correlation window
//   - sequence: the event type sequence to match
//
// Returns:
//   - bool: true if the sequence matches
func checkSequenceMatch(windowedEvents []*core.Event, sequence []string) bool {
	if len(windowedEvents) < len(sequence) {
		return false
	}

	// Check the last len(sequence) events match the sequence in order
	start := len(windowedEvents) - len(sequence)
	for i, eventType := range sequence {
		if windowedEvents[start+i].EventType != eventType {
			return false
		}
	}
	return true
}

// mergeAndFilterEvents merges concurrent state changes and reapplies filtering.
// TASK 148.4: Extracted from evaluateCorrelationRule to reduce cyclomatic complexity.
// This handles the optimistic locking merge when state changed during processing.
//
// Parameters:
//   - currentState: current state in the map
//   - event: the new event to add
//   - rule: the correlation rule for window calculation
//   - ttlSeconds: TTL for correlation state in seconds
//
// Returns:
//   - []*core.Event: merged and filtered events
func mergeAndFilterEvents(currentState []*core.Event, event *core.Event, rule core.CorrelationRule, ttlSeconds int) []*core.Event {
	mergedEvents := append(currentState, event)

	now := event.Timestamp
	windowStart := now.Add(-rule.Window)
	ttlDuration := time.Duration(ttlSeconds) * time.Second

	finalEvents := make([]*core.Event, 0, len(mergedEvents))
	for _, e := range mergedEvents {
		if e != nil && now.Sub(e.Timestamp) <= ttlDuration &&
			(e.Timestamp.After(windowStart) || e.Timestamp.Equal(windowStart)) {
			finalEvents = append(finalEvents, e)
		}
	}

	// Enforce memory limits on merged result
	if len(finalEvents) > MaxCorrelationEventsPerRule {
		finalEvents = finalEvents[len(finalEvents)-MaxCorrelationEventsPerRule:]
	}

	return finalEvents
}

// TASK #184: evaluateSimpleConditions and evaluateSimpleCondition functions deleted
// Correlation rules now use SIGMA correlation syntax instead of legacy Conditions

// evaluateCorrelationRule checks if a correlation rule matches based on event sequence
// SECURITY: Enforces memory limits to prevent unbounded growth of correlation state
// PERFORMANCE: Minimizes lock contention by performing expensive operations outside critical section
// CONCURRENCY: Uses optimistic locking to prevent race conditions during state updates
// TASK 148.4: Refactored to use extracted helper functions for lower complexity
func (re *RuleEngine) evaluateCorrelationRule(rule core.CorrelationRule, event *core.Event) bool {
	// STEP 1: Read current state with shared lock (allows concurrent reads)
	re.correlationMu.RLock()
	_, ruleExists := re.correlationState[rule.ID]

	// SECURITY: Check if we've hit the maximum number of tracked rules
	if !ruleExists && len(re.correlationState) >= MaxCorrelationRulesTracked {
		re.correlationMu.RUnlock()
		return false
	}

	// Make a deep copy of the event slice to work with outside the lock
	existingEvents := re.correlationState[rule.ID]
	originalStateLen := len(existingEvents)
	eventsCopy := make([]*core.Event, len(existingEvents))
	copy(eventsCopy, existingEvents)
	re.correlationMu.RUnlock()

	// STEP 2: Process events outside lock
	eventsCopy = append(eventsCopy, event)
	result := processCorrelationEvents(eventsCopy, event, rule, re.correlationTTL)

	// Check sequence match
	// TASK #184: Conditions field removed - correlation rules match based on sequence only
	matched := checkSequenceMatch(result.windowedEvents, rule.Sequence)

	// STEP 3: Update state with write lock
	re.correlationMu.Lock()
	defer re.correlationMu.Unlock()

	currentState := re.correlationState[rule.ID]

	// Check if state changed during processing (optimistic locking)
	if len(currentState) != originalStateLen {
		// Merge concurrent changes
		finalEvents := mergeAndFilterEvents(currentState, event, rule, re.correlationTTL)
		if len(finalEvents) == 0 {
			delete(re.correlationState, rule.ID)
		} else {
			re.correlationState[rule.ID] = finalEvents
		}
	} else {
		// State unchanged, commit our results
		if len(result.windowedEvents) == 0 {
			delete(re.correlationState, rule.ID)
		} else {
			re.correlationState[rule.ID] = result.windowedEvents
		}
	}

	// Clear state after successful match
	if matched {
		delete(re.correlationState, rule.ID)
	}

	return matched
}

// evaluateRule checks if a rule matches the event
// TASK #181: Simplified to only use SIGMA engine evaluation
// PRODUCTION: All rules must be SIGMA or CQL type with appropriate YAML/Query
// OBSERVABILITY: Logs SIGMA engine errors for monitoring
// SECURITY: Validates rule type and content before evaluation
func (re *RuleEngine) evaluateRule(rule core.Rule, event *core.Event) bool {
	// CQL rules use separate evaluation path (not yet implemented)
	if strings.ToUpper(rule.Type) == "CQL" && rule.Query != "" {
		// CQL evaluation would go here if implemented
		// For now, log warning and skip
		log.Printf("WARN: CQL rule evaluation not yet implemented for rule %s", rule.ID)
		return false
	}

	// Validate rule has SIGMA YAML
	// PRODUCTION: All detection rules must have SIGMA YAML or be CQL type
	if rule.SigmaYAML == "" {
		log.Printf("WARN: Rule %s has no SIGMA YAML, skipping evaluation (rule_type=%s)", rule.ID, rule.Type)
		return false
	}

	// Evaluate using SIGMA engine
	// TASK #131.2: Native SIGMA engine is the only supported evaluation path
	matched, err := re.sigmaEngine.Evaluate(&rule, event)
	if err != nil {
		// Log error but don't fail - graceful degradation
		// In production, this allows system to continue despite SIGMA parse errors
		log.Printf("WARN: SIGMA engine evaluation failed for rule %s: %v", rule.ID, err)
		return false
	}

	return matched
}


// TASK #181: Legacy numeric comparison functions deleted
// - isNumericValue, compareNumbers
// SIGMA engine uses strict comparison (no epsilon handling)

// getFieldValue extracts field value from event using dot notation (e.g., "fields.key")
func (re *RuleEngine) getFieldValue(field string, event *core.Event) interface{} {
	parts := strings.Split(field, ".")

	// Start with top-level fields merged with event fields
	current := make(map[string]interface{})
	current["event_id"] = event.EventID
	current["timestamp"] = event.Timestamp
	current["source_format"] = event.SourceFormat
	current["source_ip"] = event.SourceIP
	current["event_type"] = event.EventType
	current["severity"] = event.Severity
	current["raw_data"] = event.RawData
	for k, v := range event.Fields {
		current[k] = v
	}

	// Navigate through nested maps using dot notation
	for i, part := range parts {
		val := current[part]
		if i < len(parts)-1 {
			// For non-last parts, must be a map to navigate further
			if m, ok := val.(map[string]interface{}); ok {
				current = m
			} else {
				return nil
			}
		} else {
			// For the last part, return whatever value it has
			return val
		}
	}
	return nil // Should not reach here
}

// Enhanced Correlation Rule Management

// LoadEnhancedCorrelationRules loads enhanced correlation rules into the engine
func (re *RuleEngine) LoadEnhancedCorrelationRules(
	countRules []core.CountCorrelationRule,
	valueCountRules []core.ValueCountCorrelationRule,
	sequenceRules []core.SequenceCorrelationRule,
	rareRules []core.RareCorrelationRule,
	statisticalRules []core.StatisticalCorrelationRule,
	crossEntityRules []core.CrossEntityCorrelationRule,
	chainRules []core.ChainCorrelationRule,
) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()

	re.countRules = countRules
	re.valueCountRules = valueCountRules
	re.sequenceRules = sequenceRules
	re.rareRules = rareRules
	re.statisticalRules = statisticalRules
	re.crossEntityRules = crossEntityRules
	re.chainRules = chainRules
}

// AddCountRule adds a count-based correlation rule
func (re *RuleEngine) AddCountRule(rule core.CountCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.countRules = append(re.countRules, rule)
}

// AddValueCountRule adds a value count correlation rule
func (re *RuleEngine) AddValueCountRule(rule core.ValueCountCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.valueCountRules = append(re.valueCountRules, rule)
}

// AddSequenceRule adds a sequence correlation rule
func (re *RuleEngine) AddSequenceRule(rule core.SequenceCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.sequenceRules = append(re.sequenceRules, rule)
}

// AddRareRule adds a rare event correlation rule
func (re *RuleEngine) AddRareRule(rule core.RareCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.rareRules = append(re.rareRules, rule)
}

// AddStatisticalRule adds a statistical anomaly correlation rule
func (re *RuleEngine) AddStatisticalRule(rule core.StatisticalCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.statisticalRules = append(re.statisticalRules, rule)
}

// AddCrossEntityRule adds a cross-entity correlation rule
func (re *RuleEngine) AddCrossEntityRule(rule core.CrossEntityCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.crossEntityRules = append(re.crossEntityRules, rule)
}

// AddChainRule adds a chain correlation rule
func (re *RuleEngine) AddChainRule(rule core.ChainCorrelationRule) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.chainRules = append(re.chainRules, rule)
}

// evaluateCountRules evaluates all count-based correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateCountRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.countRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateCountRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateValueCountRules evaluates all value count correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateValueCountRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.valueCountRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateValueCountRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateSequenceRules evaluates all sequence correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateSequenceRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.sequenceRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateSequenceRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateRareRules evaluates all rare event correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateRareRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.rareRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateRareRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateStatisticalRules evaluates all statistical anomaly correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateStatisticalRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.statisticalRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateStatisticalRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateCrossEntityRules evaluates all cross-entity correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateCrossEntityRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.crossEntityRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateCrossEntityRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evaluateChainRules evaluates all chain correlation rules.
// TASK 148.4: Extracted from EvaluateEnhancedCorrelation to reduce complexity.
func (re *RuleEngine) evaluateChainRules(event *core.Event) []*core.Alert {
	var alerts []*core.Alert
	for _, rule := range re.chainRules {
		if !rule.Enabled {
			continue
		}
		if alert, matched := re.enhancedCorrelationEvaluator.EvaluateChainRule(rule, event); matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// EvaluateEnhancedCorrelation evaluates all enhanced correlation rules against an event.
// TASK 148.4: Refactored to use extracted helper functions for lower complexity.
func (re *RuleEngine) EvaluateEnhancedCorrelation(event *core.Event) []*core.Alert {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	var alerts []*core.Alert

	// Evaluate each rule type using extracted helper functions
	alerts = append(alerts, re.evaluateCountRules(event)...)
	alerts = append(alerts, re.evaluateValueCountRules(event)...)
	alerts = append(alerts, re.evaluateSequenceRules(event)...)
	alerts = append(alerts, re.evaluateRareRules(event)...)
	alerts = append(alerts, re.evaluateStatisticalRules(event)...)
	alerts = append(alerts, re.evaluateCrossEntityRules(event)...)
	alerts = append(alerts, re.evaluateChainRules(event)...)

	return alerts
}

// GetEnhancedCorrelationRuleCount returns the count of each type of enhanced correlation rule
func (re *RuleEngine) GetEnhancedCorrelationRuleCount() map[string]int {
	re.stateMu.RLock()
	defer re.stateMu.RUnlock()

	return map[string]int{
		"count":        len(re.countRules),
		"value_count":  len(re.valueCountRules),
		"sequence":     len(re.sequenceRules),
		"rare":         len(re.rareRules),
		"statistical":  len(re.statisticalRules),
		"cross_entity": len(re.crossEntityRules),
		"chain":        len(re.chainRules),
	}
}

// ========================================================================
// FLOAT PRECISION HANDLING
// TASK #181: Legacy float comparison functions deleted
// - floatEpsilon, floatEqual, compareFloat
// SIGMA engine uses strict comparison per specification
// See ADR-002-float-precision.md for historical context
