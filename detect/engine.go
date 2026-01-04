package detect

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/metrics"

	"go.uber.org/zap"
)

const (
	// MaxCorrelationEventsPerRule limits events stored per correlation rule to prevent memory exhaustion
	// SECURITY: This prevents unbounded memory growth in correlation state
	MaxCorrelationEventsPerRule = 1000
	// MaxCorrelationRulesTracked limits the number of rules with active state
	MaxCorrelationRulesTracked = 100
	// MaxFutureTimestampTolerance allows for clock skew between event sources
	// SECURITY: Prevents time-based DoS where attackers send future-dated events that never expire
	MaxFutureTimestampTolerance = 1 * time.Minute
)

// HealthRecorder is the interface for recording rule health metrics.
// TASK 225.3: Enables health dashboard integration without circular imports.
//
// Thread Safety:
//   - Implementations MUST be thread-safe as methods are called concurrently
//     from multiple goroutines during rule evaluation.
//   - Methods should be non-blocking and fast (< 1ms) to avoid impacting detection latency.
//   - The caller (RuleEngine) holds stateMu.RLock() when calling these methods,
//     so implementations must not attempt to acquire locks that could deadlock.
//
// Implementers: api.HealthService
type HealthRecorder interface {
	// RecordEvaluation records a successful rule evaluation with latency.
	// ruleID: correlation rule identifier
	// latencyMs: evaluation time in milliseconds
	RecordEvaluation(ruleID string, latencyMs float64)

	// RecordError records an error during rule evaluation.
	// ruleID: correlation rule identifier
	// errorType: category of error (use HealthError* constants)
	// errorMsg: human-readable error message
	RecordError(ruleID, errorType, errorMsg string)
}

// Health error type constants for consistent error categorization.
const (
	// HealthErrorEval indicates a rule evaluation error (e.g., SIGMA parse failure)
	HealthErrorEval = "eval_error"

	// HealthErrorLimitExceeded indicates the maximum tracked rules limit was exceeded
	HealthErrorLimitExceeded = "limit_exceeded"
)

// Incremental cleanup configuration
const (
	// cleanupBatchSize is the number of correlation rules to clean per tick
	// Smaller batches = shorter lock holds = less impact on evaluation throughput
	cleanupBatchSize = 50

	// cleanupMaxLockDuration is the maximum time to hold the lock per batch
	// If processing takes longer, we release and continue next tick
	cleanupMaxLockDuration = 10 * time.Millisecond
)

// RuleEngine evaluates rules against events
type RuleEngine struct {
	rules            []core.Rule
	correlationRules []core.CorrelationRule
	correlationState map[string][]*core.Event // ruleID -> events in window (legacy)
	correlationVersion map[string]uint64      // ruleID -> version counter for optimistic locking
	stateMu          sync.RWMutex             // protects rules and correlationRules slices
	correlationMu    sync.RWMutex             // protects correlationState map (separate to avoid deadlock)
	correlationTTL   int                      // seconds
	cleanupCancel    context.CancelFunc       // for stopping cleanup goroutine
	cleanupWg        sync.WaitGroup           // for waiting on cleanup goroutine
	ctx              context.Context          // TASK 144.4: Parent context for SIGMA engine initialization

	// Incremental cleanup state - processes rules in batches to minimize lock contention
	cleanupRuleIDs []string // snapshot of rule IDs to process in current cycle
	cleanupCursor  int      // current position in cleanupRuleIDs

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

	// TASK 225.3: Health dashboard integration
	healthRecorder HealthRecorder // Records rule health metrics (nil = disabled)

	// Rule indexing for O(1) logsource-based rule filtering
	// Replaces O(N) linear scan with indexed lookup by logsource fields
	ruleIndex *RuleIndex
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
		correlationVersion:           make(map[string]uint64), // Version counter for optimistic locking
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
		ruleIndex:                    NewRuleIndex(), // O(1) logsource-based rule filtering
	}

	// Build rule index for O(1) logsource-based filtering
	re.ruleIndex.Rebuild(rules)

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
			MaxEntries:      1000,             // Default cache size
			TTL:             time.Hour,        // Default TTL
			CleanupInterval: 10 * time.Minute, // Default cleanup interval
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

// ResetCorrelationState clears the correlation state and version maps
func (re *RuleEngine) ResetCorrelationState() {
	re.correlationMu.Lock()
	defer re.correlationMu.Unlock()
	re.correlationState = make(map[string][]*core.Event)
	re.correlationVersion = make(map[string]uint64)
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

	// Rebuild rule index for O(1) logsource-based filtering
	re.ruleIndex.Rebuild(newRules)

	re.stateMu.Unlock()

	// Log AFTER releasing lock to minimize critical section
	log.Printf("INFO: Rules reloaded - old=%d new=%d", oldCount, newCount)
}

// ReloadCorrelationRules atomically replaces the current correlation rule set
// CONCURRENCY: Uses write lock to prevent race conditions during rule evaluation
// PRODUCTION: Enables dynamic correlation rule updates without system restart
// OBSERVABILITY: Logs reload operations with before/after counts for monitoring
// GATEKEEPER FIX: Uses copy-on-write pattern to prevent data race with concurrent readers
func (re *RuleEngine) ReloadCorrelationRules(newRules []core.CorrelationRule) {
	// LOCK ORDERING: Always acquire stateMu before correlationMu to prevent deadlock
	re.stateMu.Lock()
	oldCount := len(re.correlationRules)

	// GATEKEEPER FIX: Create a defensive copy to prevent data race
	// Readers that captured the old slice reference will continue safely
	// while new readers get the updated slice. This prevents:
	// 1. Reading from freed memory if old slice is garbage collected
	// 2. Inconsistent length vs capacity during concurrent access
	rulesCopy := make([]core.CorrelationRule, len(newRules))
	copy(rulesCopy, newRules)
	re.correlationRules = rulesCopy

	newCount := len(rulesCopy)
	re.stateMu.Unlock()

	// Reset correlation state and version counters when rules change
	// Use correlationMu (not stateMu) for state operations
	re.correlationMu.Lock()
	re.correlationState = make(map[string][]*core.Event)
	re.correlationVersion = make(map[string]uint64)
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

// SetHealthRecorder configures the health metrics recorder for this engine.
// TASK 225.3: Health dashboard integration
//
// Thread Safety:
//   - This method acquires a write lock (stateMu.Lock) and will block until all
//     concurrent Evaluate/EvaluateCorrelation calls complete.
//   - Pass nil to disable health recording.
//
// The recorder must be thread-safe as RecordEvaluation/RecordError are called
// while stateMu.RLock is held by evaluation methods.
func (re *RuleEngine) SetHealthRecorder(recorder HealthRecorder) {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.healthRecorder = recorder
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

// cleanupExpiredState removes expired entries from correlation state using incremental processing.
// PERFORMANCE OPTIMIZATION: Instead of processing all rules in one lock hold, this processes
// rules in small batches (cleanupBatchSize) with short lock durations to minimize impact
// on concurrent correlation evaluations.
//
// The cleanup maintains a cursor to track progress across multiple ticks:
// - On first call (or after completing a full cycle), snapshots all rule IDs
// - Each tick processes up to cleanupBatchSize rules
// - Progress is tracked via cleanupCursor
// - When all rules are processed, the cycle restarts on next tick
func (re *RuleEngine) cleanupExpiredState() {
	batchStartTime := time.Now()
	defer func() {
		metrics.CorrelationCleanupDuration.Observe(time.Since(batchStartTime).Seconds())
	}()

	now := time.Now()
	ttlDuration := time.Duration(re.correlationTTL) * time.Second
	cutoff := now.Add(-ttlDuration)

	// Check if we need to start a new cleanup cycle
	if re.cleanupCursor >= len(re.cleanupRuleIDs) {
		// Snapshot current rule IDs under a brief lock
		re.correlationMu.RLock()
		re.cleanupRuleIDs = make([]string, 0, len(re.correlationState))
		for ruleID := range re.correlationState {
			re.cleanupRuleIDs = append(re.cleanupRuleIDs, ruleID)
		}
		stateSize := len(re.correlationState)
		re.correlationMu.RUnlock()
		re.cleanupCursor = 0

		// Update state size metric
		metrics.CorrelationStateSize.Set(float64(stateSize))

		// If no rules to clean, we're done
		if len(re.cleanupRuleIDs) == 0 {
			return
		}
	}

	// Calculate batch boundaries
	batchStart := re.cleanupCursor
	batchEnd := batchStart + cleanupBatchSize
	if batchEnd > len(re.cleanupRuleIDs) {
		batchEnd = len(re.cleanupRuleIDs)
	}

	// Process this batch with a lock
	// Use a deadline to ensure we don't hold the lock too long
	lockStartTime := time.Now()
	rulesProcessed := 0
	rulesExpired := 0

	re.correlationMu.Lock()
	for i := batchStart; i < batchEnd; i++ {
		// Check if we've held the lock too long
		if time.Since(lockStartTime) > cleanupMaxLockDuration {
			// Release lock early, continue next tick
			re.cleanupCursor = i
			re.correlationMu.Unlock()

			// Update metrics for partial batch
			metrics.CorrelationCleanupRulesProcessed.Add(float64(rulesProcessed))
			metrics.CorrelationCleanupRulesExpired.Add(float64(rulesExpired))
			return
		}

		ruleID := re.cleanupRuleIDs[i]
		events, exists := re.correlationState[ruleID]
		if !exists {
			rulesProcessed++
			continue
		}

		if len(events) == 0 {
			delete(re.correlationState, ruleID)
			re.correlationVersion[ruleID]++
			rulesProcessed++
			rulesExpired++
			continue
		}

		// Check if oldest event is expired
		oldestEvent := events[0]
		if now.Sub(oldestEvent.Timestamp) > ttlDuration {
			// Remove all expired events using binary search
			validIdx := sort.Search(len(events), func(j int) bool {
				return events[j].Timestamp.After(cutoff)
			})

			if validIdx >= len(events) {
				// All events expired
				delete(re.correlationState, ruleID)
				re.correlationVersion[ruleID]++
				rulesExpired++
			} else {
				// Keep only valid events
				re.correlationState[ruleID] = events[validIdx:]
				re.correlationVersion[ruleID]++
			}
		}
		rulesProcessed++
	}
	re.correlationMu.Unlock()

	// Update cursor for next tick
	re.cleanupCursor = batchEnd

	// Update metrics
	metrics.CorrelationCleanupRulesProcessed.Add(float64(rulesProcessed))
	metrics.CorrelationCleanupRulesExpired.Add(float64(rulesExpired))
}

// Evaluate evaluates rules against an event and returns matching rules.
// Uses logsource-based indexing for O(1) rule filtering when event has logsource fields.
// Falls back to O(N) linear scan for events without logsource info.
//
// CONCURRENCY: Uses read lock to prevent race conditions with ReloadRules
// PERFORMANCE: With logsource indexing, only evaluates rules matching the event's logsource
// OPTIMIZATION: Lock released before evaluation loop to minimize contention (20-50% throughput gain)
func (re *RuleEngine) Evaluate(event *core.Event) []core.AlertableRule {
	// OPTIMIZATION: Copy candidate rules under lock, then release before evaluation
	// This reduces lock hold time from O(rules * eval_time) to O(rules) for the copy
	re.stateMu.RLock()
	candidateRules := re.ruleIndex.GetRulesForEvent(event)
	// Create a snapshot of rules to evaluate (shallow copy of pointers is safe - rules are immutable after load)
	rulesToEvaluate := make([]*core.Rule, len(candidateRules))
	copy(rulesToEvaluate, candidateRules)
	re.stateMu.RUnlock()

	// Evaluate rules WITHOUT holding the lock - this is where most time is spent
	var matches []core.AlertableRule
	for _, rule := range rulesToEvaluate {
		// Index already filters disabled rules, but double-check for safety
		if !rule.Enabled {
			continue
		}
		if re.evaluateRule(*rule, event) {
			matches = append(matches, *rule)
		}
	}
	return matches
}

// EvaluateCorrelation evaluates correlation rules and returns matching ones
// CONCURRENCY: Uses read lock to prevent race conditions with ReloadCorrelationRules
// OPTIMIZATION: Lock released before evaluation loop to minimize contention
func (re *RuleEngine) EvaluateCorrelation(event *core.Event) []core.AlertableRule {
	// OPTIMIZATION: Copy correlation rules under lock, then release before evaluation
	// This reduces lock hold time significantly since correlation evaluation can be slow
	re.stateMu.RLock()
	rulesToEvaluate := make([]core.CorrelationRule, len(re.correlationRules))
	copy(rulesToEvaluate, re.correlationRules)
	re.stateMu.RUnlock()

	// Evaluate rules WITHOUT holding the lock
	var matches []core.AlertableRule
	for _, rule := range rulesToEvaluate {
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

// insertEventInOrder inserts a new event into a sorted event slice, maintaining timestamp order.
// PERFORMANCE OPTIMIZATION: Uses binary search for O(log N) position finding.
// Since events typically arrive in chronological order, this usually results in O(1) append.
//
// Amortized Complexity Analysis:
//   - Best case (in-order arrival): O(1) - append reuses capacity per Go's doubling strategy
//   - Worst case (reverse-order): O(N) per insert - full slice shift
//   - Amortized case (90%+ in-order): O(1) dominated by append, O(N) rare for stragglers
//   - Streaming workloads: Events typically arrive in chronological order due to clock sync
//
// Amortization Assumptions:
//   1. Event sources have synchronized clocks (±1s drift is typical)
//   2. Network jitter causes <10% out-of-order arrivals
//   3. Go's append() uses exponential growth (2x capacity) for amortized O(1)
//
// Parameters:
//   - events: existing sorted slice of events (by timestamp ascending)
//   - newEvent: the event to insert (must not be nil)
//
// Returns:
//   - []*core.Event: slice with event inserted in correct position
func insertEventInOrder(events []*core.Event, newEvent *core.Event) []*core.Event {
	if newEvent == nil {
		return events
	}

	n := len(events)

	// Fast path: if empty or new event is latest, just append (O(1))
	// This is the common case for in-order event arrival
	if n == 0 {
		return append(events, newEvent)
	}

	// INVARIANT: Last element must not be nil - if it is, state is corrupted
	// Panic to expose the bug rather than silently producing incorrect results
	// This is consistent with the panic in binarySearchInsertPoint
	if events[n-1] == nil {
		panic("insertEventInOrder: nil event found at end of correlation state - this indicates a bug in event filtering")
	}

	// Check if new event belongs at the end (most common case)
	// STABLE INSERTION: For equal timestamps, always insert after existing events
	// This ensures deterministic ordering regardless of EventID format (UUID, etc.)
	if newEvent.Timestamp.After(events[n-1].Timestamp) ||
		newEvent.Timestamp.Equal(events[n-1].Timestamp) {
		return append(events, newEvent)
	}

	// Binary search to find insertion point (O(log N))
	insertIdx := binarySearchInsertPoint(events, newEvent)

	// Insert at the found position using append+copy pattern to reuse capacity
	// This avoids allocation when cap(events) > len(events)
	events = append(events, nil)                  // Extend by 1 (may or may not allocate)
	copy(events[insertIdx+1:], events[insertIdx:n]) // Shift right from insertion point
	events[insertIdx] = newEvent

	return events
}

// binarySearchInsertPoint finds the index where newEvent should be inserted
// to maintain timestamp-ascending order with stable insertion.
//
// STABLE INSERTION: For events with equal timestamps, this returns the index
// AFTER all existing events with that timestamp. This ensures deterministic
// ordering regardless of EventID format (UUID, auto-increment, etc.).
//
// PRECONDITION: events slice must not contain nil elements. If a nil element
// is encountered, the function will panic - this is intentional to expose bugs
// in the calling code rather than silently producing incorrect results.
func binarySearchInsertPoint(events []*core.Event, newEvent *core.Event) int {
	lo, hi := 0, len(events)

	for lo < hi {
		mid := lo + (hi-lo)/2
		// INVARIANT: events[mid] must not be nil
		// If nil is found, panic to expose the bug in calling code
		if events[mid] == nil {
			panic("binarySearchInsertPoint: nil event found in correlation state - this indicates a bug in event filtering")
		}

		// STABLE INSERTION: Insert after events with equal timestamps
		// This finds the first event STRICTLY AFTER newEvent's timestamp
		if events[mid].Timestamp.After(newEvent.Timestamp) {
			hi = mid
		} else {
			// events[mid].Timestamp <= newEvent.Timestamp: keep searching right
			lo = mid + 1
		}
	}

	return lo
}

// requiresEventOrdering determines if a correlation rule needs events in timestamp order.
// Only sequence rules with 2+ events need ordering - single-element sequences and
// count-based rules don't care about event order.
func requiresEventOrdering(rule core.CorrelationRule) bool {
	return len(rule.Sequence) >= 2
}

// processCorrelationEvents processes events for correlation rule matching.
// TASK 148.4: Extracted from evaluateCorrelationRule to reduce cyclomatic complexity.
// PERFORMANCE: Removed O(N log N) sorting - now uses O(1) amortized insertion for in-order events.
//
// Operations performed:
//  1. Insert new event maintaining timestamp order (only for sequence rules)
//  2. Filter expired events (based on TTL)
//  3. Enforce memory limits (MaxCorrelationEventsPerRule)
//  4. Filter events within correlation window
//
// Parameters:
//   - existingEvents: copy of existing events (already sorted if sequence rule)
//   - event: the new event being evaluated
//   - rule: the correlation rule to evaluate
//   - ttlSeconds: TTL for correlation state in seconds
//
// Returns:
//   - correlationProcessResult: processed events and match result
func processCorrelationEvents(existingEvents []*core.Event, event *core.Event, rule core.CorrelationRule, ttlSeconds int) correlationProcessResult {
	// Use event timestamp as reference for all time-based calculations
	// This ensures correlation semantics are preserved even with delayed ingestion
	eventTime := event.Timestamp
	ttlDuration := time.Duration(ttlSeconds) * time.Second

	// Build the combined event list with proper ordering
	var allEvents []*core.Event
	if requiresEventOrdering(rule) {
		// For multi-step sequence rules: insert new event maintaining timestamp order
		// Uses O(log N) binary search + O(N) shift worst case, O(1) amortized for in-order events
		allEvents = insertEventInOrder(existingEvents, event)
	} else {
		// For count-based rules and single-step sequences: just append, order doesn't matter
		allEvents = append(existingEvents, event)
	}

	// Filter expired events, future events, and those outside the correlation window
	// All time calculations use event timestamp as reference for consistency
	windowStart := eventTime.Add(-rule.Window)
	ttlCutoff := eventTime.Add(-ttlDuration)

	// TOCTOU FIX: Capture wall clock immediately before checking future timestamps
	// This minimizes the window between time capture and usage
	// THEORETICAL LIMITATION: Wall clock can still advance during the loop (~100μs typical),
	// but the 1-minute tolerance makes this practically unexploitable (tolerance is 600,000x loop duration)
	maxFutureTime := time.Now().Add(MaxFutureTimestampTolerance)

	validEvents := make([]*core.Event, 0, len(allEvents))
	for _, e := range allEvents {
		// INVARIANT: Nil events indicate bugs in state management
		// Panic immediately to expose the bug rather than silently corrupt correlation results
		if e == nil {
			panic("processCorrelationEvents: nil event found in correlation state - this indicates a bug in event filtering or state management")
		}
		// SECURITY: Reject events from the future (beyond clock skew tolerance)
		// Uses wall clock time to prevent attackers from sending future-dated events
		if e.Timestamp.After(maxFutureTime) {
			continue
		}
		// Check TTL expiration (relative to event timestamp for consistent semantics)
		// Events older than TTL relative to current event are expired
		if e.Timestamp.Before(ttlCutoff) {
			continue
		}
		// Check within correlation window (relative to current event timestamp)
		if e.Timestamp.Before(windowStart) {
			continue
		}
		validEvents = append(validEvents, e)
	}

	// SECURITY: Enforce maximum events per rule to prevent memory exhaustion
	if len(validEvents) > MaxCorrelationEventsPerRule {
		// Keep the most recent events (tail of sorted slice)
		validEvents = validEvents[len(validEvents)-MaxCorrelationEventsPerRule:]
	}

	return correlationProcessResult{
		windowedEvents: validEvents,
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
// PERFORMANCE: Uses ordered insertion for sequence rules, simple append otherwise.
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
	// Merge event into state with appropriate ordering
	var mergedEvents []*core.Event
	if requiresEventOrdering(rule) {
		// For multi-step sequence rules: maintain timestamp order
		// Uses O(log N) binary search + O(N) shift worst case, O(1) amortized for in-order events
		mergedEvents = insertEventInOrder(currentState, event)
	} else {
		// For count-based rules and single-step sequences: simple append, order doesn't matter
		mergedEvents = append(currentState, event)
	}

	// Use event timestamp as reference for all time-based calculations
	// This ensures correlation semantics are preserved even with delayed ingestion
	eventTime := event.Timestamp
	windowStart := eventTime.Add(-rule.Window)
	ttlDuration := time.Duration(ttlSeconds) * time.Second
	ttlCutoff := eventTime.Add(-ttlDuration)

	// TOCTOU FIX: Capture wall clock immediately before checking future timestamps
	// This minimizes the window between time capture and usage
	// THEORETICAL LIMITATION: Wall clock can still advance during the loop (~100μs typical),
	// but the 1-minute tolerance makes this practically unexploitable (tolerance is 600,000x loop duration)
	maxFutureTime := time.Now().Add(MaxFutureTimestampTolerance)

	finalEvents := make([]*core.Event, 0, len(mergedEvents))
	for _, e := range mergedEvents {
		// INVARIANT: Nil events indicate bugs in state management
		// Panic immediately to expose the bug rather than silently corrupt correlation results
		if e == nil {
			panic("mergeAndFilterEvents: nil event found in correlation state - this indicates a bug in event filtering or state management")
		}
		// SECURITY: Reject events from the future (beyond clock skew tolerance)
		if e.Timestamp.After(maxFutureTime) {
			continue
		}
		// Check TTL expiration (relative to event timestamp for consistent semantics)
		if e.Timestamp.Before(ttlCutoff) {
			continue
		}
		// Check within correlation window (relative to current event timestamp)
		if e.Timestamp.Before(windowStart) {
			continue
		}
		finalEvents = append(finalEvents, e)
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
// TASK 225.3: Instrumented with health metrics recording
func (re *RuleEngine) evaluateCorrelationRule(rule core.CorrelationRule, event *core.Event) bool {
	// TASK 225.3: Record evaluation start time for latency tracking
	start := time.Now()

	// STEP 1: Read current state with shared lock (allows concurrent reads)
	re.correlationMu.RLock()
	_, ruleExists := re.correlationState[rule.ID]

	// SECURITY: Check if we've hit the maximum number of tracked rules
	if !ruleExists && len(re.correlationState) >= MaxCorrelationRulesTracked {
		re.correlationMu.RUnlock()
		// TASK 225.3: Record error when rule limit exceeded
		if re.healthRecorder != nil {
			re.healthRecorder.RecordError(rule.ID, HealthErrorLimitExceeded, "maximum correlation rules tracked exceeded")
		}
		return false
	}

	// Make a deep copy of the event slice to work with outside the lock
	// Also capture the version for optimistic locking
	existingEvents := re.correlationState[rule.ID]
	originalVersion := re.correlationVersion[rule.ID]
	eventsCopy := make([]*core.Event, len(existingEvents))
	copy(eventsCopy, existingEvents)
	re.correlationMu.RUnlock()

	// STEP 2: Process events outside lock
	// processCorrelationEvents handles adding the new event internally
	result := processCorrelationEvents(eventsCopy, event, rule, re.correlationTTL)

	// Check sequence match
	// TASK #184: Conditions field removed - correlation rules match based on sequence only
	matched := checkSequenceMatch(result.windowedEvents, rule.Sequence)

	// STEP 3: Update state with write lock
	re.correlationMu.Lock()
	defer re.correlationMu.Unlock()

	currentVersion := re.correlationVersion[rule.ID]

	// Check if state changed during processing (optimistic locking via version counter)
	// Version check is more reliable than length check - catches add+remove same count
	if currentVersion != originalVersion {
		// State was modified concurrently - merge changes
		currentState := re.correlationState[rule.ID]
		finalEvents := mergeAndFilterEvents(currentState, event, rule, re.correlationTTL)
		if len(finalEvents) == 0 {
			delete(re.correlationState, rule.ID)
			re.correlationVersion[rule.ID]++ // Increment, don't delete - prevents ABA
		} else {
			re.correlationState[rule.ID] = finalEvents
			re.correlationVersion[rule.ID] = currentVersion + 1
		}
	} else {
		// State unchanged, commit our results
		if len(result.windowedEvents) == 0 {
			delete(re.correlationState, rule.ID)
			re.correlationVersion[rule.ID]++ // Increment, don't delete - prevents ABA
		} else {
			re.correlationState[rule.ID] = result.windowedEvents
			re.correlationVersion[rule.ID] = originalVersion + 1
		}
	}

	// Clear state after successful match
	// IMPORTANT: Increment version instead of deleting to prevent ABA problem
	// If we delete version and new events recreate state back to same version number,
	// concurrent readers would think nothing changed
	if matched {
		delete(re.correlationState, rule.ID)
		re.correlationVersion[rule.ID]++ // Increment, don't delete - prevents ABA
	}

	// TASK 225.3: Record successful evaluation with latency
	if re.healthRecorder != nil {
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		re.healthRecorder.RecordEvaluation(rule.ID, latencyMs)
	}

	return matched
}

// evaluateRule checks if a rule matches the event
// TASK #181: Simplified to only use SIGMA engine evaluation
// TASK 225.3: Instrumented with health metrics recording
// PRODUCTION: All rules must be SIGMA or CQL type with appropriate YAML/Query
// OBSERVABILITY: Logs SIGMA engine errors for monitoring
// SECURITY: Validates rule type and content before evaluation
func (re *RuleEngine) evaluateRule(rule core.Rule, event *core.Event) bool {
	// TASK 225.3: Record evaluation start time for latency tracking
	start := time.Now()

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

	// TASK 225.3: Record health metrics (nil check for healthRecorder)
	if re.healthRecorder != nil {
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		if err != nil {
			re.healthRecorder.RecordError(rule.ID, HealthErrorEval, err.Error())
		} else {
			re.healthRecorder.RecordEvaluation(rule.ID, latencyMs)
		}
	}

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
	// PERFORMANCE OPTIMIZATION: Avoid map allocation and field copying
	// Fast path: non-nested fields (most common case) - zero allocations
	if !strings.Contains(field, ".") {
		// Check top-level event fields first (switch compiles to jump table)
		switch field {
		case "event_id":
			return event.EventID
		case "timestamp":
			return event.Timestamp
		case "source_format":
			return event.SourceFormat
		case "source_ip":
			return event.SourceIP
		case "event_type":
			return event.EventType
		case "severity":
			return event.Severity
		case "raw_data":
			return event.RawData
		}
		// Check in Fields map directly
		if event.Fields != nil {
			if val, ok := event.Fields[field]; ok {
				return val
			}
		}
		return nil
	}

	// Slow path: nested field access with dot notation
	parts := strings.Split(field, ".")

	// Get the root value without creating merged map
	var current interface{}
	switch parts[0] {
	case "event_id":
		current = event.EventID
	case "timestamp":
		current = event.Timestamp
	case "source_format":
		current = event.SourceFormat
	case "source_ip":
		current = event.SourceIP
	case "event_type":
		current = event.EventType
	case "severity":
		current = event.Severity
	case "raw_data":
		current = event.RawData
	default:
		if event.Fields != nil {
			current = event.Fields[parts[0]]
		}
	}

	// Navigate through remaining parts
	for i := 1; i < len(parts); i++ {
		if current == nil {
			return nil
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[parts[i]]
	}
	return current
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
