package api

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// SigmaRolloutConfig controls the gradual rollout of the SIGMA detection engine
//
// TASK #131.5: Feature flags for gradual SIGMA rollout (canary deployment)
//
// The rollout system provides multiple control mechanisms:
//  1. Master switch (Enabled): Global on/off for native SIGMA engine
//  2. Percentage-based rollout (RolloutPercentage): Gradual rollout using hash-based routing
//  3. Explicit whitelist (EnabledRuleIDs): Force specific rules to use native engine
//  4. Explicit blocklist (DisabledRuleIDs): Prevent specific rules from using native engine
//
// Decision precedence (highest to lowest):
//  1. Master Enabled=false → always use legacy engine
//  2. Rule in DisabledRuleIDs → use legacy engine (blocklist)
//  3. Rule in EnabledRuleIDs → use native SIGMA engine (whitelist)
//  4. Hash-based percentage routing → deterministic canary rollout
//
// PRODUCTION SAFETY:
//   - Deterministic hash-based routing ensures same rule always gets same decision
//   - Thread-safe for concurrent access across multiple goroutines
//   - Immutable after creation (no runtime modifications without reload)
//   - Clear audit trail via structured logging
//
// Example gradual rollout sequence:
//  1. Start: RolloutPercentage=0 (all legacy, test native engine health)
//  2. Canary: RolloutPercentage=5 (5% of rules use native engine)
//  3. Expand: RolloutPercentage=25 (monitor error rates and performance)
//  4. Majority: RolloutPercentage=75 (confidence in native engine)
//  5. Complete: RolloutPercentage=100 (full migration)
//
// Security Considerations:
//   - Rule IDs are hashed using SHA-256 for deterministic distribution
//   - No external dependencies or network calls
//   - No PII or sensitive data in logs (rule IDs only)
//   - Fail-safe: errors default to legacy engine (graceful degradation)
type SigmaRolloutConfig struct {
	// Enabled is the master switch for native SIGMA engine
	// If false, ALL rules use legacy engine regardless of other settings
	// SECURITY: Allows immediate rollback in case of critical issues
	// Default: false (legacy engine only)
	Enabled bool

	// RolloutPercentage controls what percentage of rules use native engine (0-100)
	// Uses deterministic hash-based routing to ensure stable rule assignment
	// PRODUCTION: Increment gradually (5% → 10% → 25% → 50% → 75% → 100%)
	// Default: 0 (no rules use native engine)
	// Valid range: 0-100 (inclusive)
	RolloutPercentage int

	// EnabledRuleIDs is an explicit whitelist of rule IDs to use native engine
	// Takes precedence over RolloutPercentage (but not over Enabled flag)
	// Use case: Force specific high-priority rules to use native engine
	// PRODUCTION: Useful for targeted testing of specific SIGMA rules
	// Example: ["rule-001", "rule-002", "rule-critical"]
	EnabledRuleIDs []string

	// DisabledRuleIDs is an explicit blocklist of rule IDs to NEVER use native engine
	// Takes precedence over both RolloutPercentage AND EnabledRuleIDs
	// Use case: Prevent problematic rules from using native engine
	// PRODUCTION: Emergency mitigation for rules with evaluation issues
	// Example: ["rule-broken", "rule-slow", "rule-false-positive"]
	DisabledRuleIDs []string

	// logger provides structured logging for rollout decisions
	// OBSERVABILITY: Logs decision rationale for audit and debugging
	logger *zap.SugaredLogger

	// enabledMap and disabledMap are pre-computed lookup maps for O(1) access
	// PERFORMANCE: Avoids O(n) slice iteration on every evaluation
	enabledMap  map[string]bool
	disabledMap map[string]bool

	// mu protects concurrent read access to config fields
	// CONCURRENCY: Allows safe access from multiple worker goroutines
	mu sync.RWMutex
}

// NewSigmaRolloutConfig creates a new feature flag configuration for SIGMA rollout
//
// PARAMETERS:
//   - enabled: Master switch for native SIGMA engine (false = all legacy)
//   - rolloutPercentage: Percentage of rules to use native engine (0-100)
//   - enabledRuleIDs: Explicit whitelist of rule IDs for native engine
//   - disabledRuleIDs: Explicit blocklist of rule IDs for legacy engine
//   - logger: Structured logger for audit trail (nil = no logging)
//
// RETURNS:
//   - Configured SigmaRolloutConfig instance
//   - Error if validation fails (invalid percentage, etc.)
//
// VALIDATION:
//   - RolloutPercentage must be 0-100 (inclusive)
//   - Duplicate rule IDs are silently deduplicated
//   - Empty slices are allowed (no whitelist/blocklist)
//
// THREAD-SAFETY:
//   - Safe to call from multiple goroutines
//   - Returned config is immutable (no setters)
//
// EXAMPLE:
//
//	config, err := NewSigmaRolloutConfig(true, 25, []string{"high-priority"}, []string{"broken"}, logger)
//	if err != nil {
//	    return err
//	}
func NewSigmaRolloutConfig(enabled bool, rolloutPercentage int, enabledRuleIDs, disabledRuleIDs []string, logger *zap.SugaredLogger) (*SigmaRolloutConfig, error) {
	// VALIDATION: Rollout percentage must be 0-100
	if rolloutPercentage < 0 || rolloutPercentage > 100 {
		return nil, fmt.Errorf("rollout percentage must be 0-100, got %d", rolloutPercentage)
	}

	// PERFORMANCE: Pre-compute lookup maps for O(1) access
	enabledMap := make(map[string]bool, len(enabledRuleIDs))
	for _, ruleID := range enabledRuleIDs {
		if ruleID != "" { // Skip empty strings
			enabledMap[ruleID] = true
		}
	}

	disabledMap := make(map[string]bool, len(disabledRuleIDs))
	for _, ruleID := range disabledRuleIDs {
		if ruleID != "" { // Skip empty strings
			disabledMap[ruleID] = true
		}
	}

	config := &SigmaRolloutConfig{
		Enabled:           enabled,
		RolloutPercentage: rolloutPercentage,
		EnabledRuleIDs:    enabledRuleIDs,
		DisabledRuleIDs:   disabledRuleIDs,
		logger:            logger,
		enabledMap:        enabledMap,
		disabledMap:       disabledMap,
	}

	// OBSERVABILITY: Log rollout configuration at startup
	if logger != nil {
		logger.Infow("SIGMA rollout configuration initialized",
			"enabled", enabled,
			"rollout_percentage", rolloutPercentage,
			"whitelist_count", len(enabledMap),
			"blocklist_count", len(disabledMap),
		)
	}

	return config, nil
}

// ShouldUseSigmaEngine determines if a rule should use the native SIGMA engine
//
// DECISION LOGIC (in precedence order):
//  1. If Enabled=false → return false (master switch off)
//  2. If ruleID in DisabledRuleIDs → return false (blocklist)
//  3. If ruleID in EnabledRuleIDs → return true (whitelist)
//  4. Otherwise → hash-based percentage routing (deterministic canary)
//
// PARAMETERS:
//   - ruleID: The unique identifier of the rule to evaluate
//
// RETURNS:
//   - true if rule should use native SIGMA engine
//   - false if rule should use legacy engine
//
// DETERMINISM:
//   - Same ruleID always returns same result (stable routing)
//   - Hash-based distribution ensures even spread across rules
//   - No randomness or time-based factors (reproducible behavior)
//
// THREAD-SAFETY:
//   - Safe to call concurrently from multiple goroutines
//   - Uses read lock for concurrent access to config
//
// PERFORMANCE:
//   - O(1) lookup for whitelist/blocklist via map access
//   - O(1) hash computation for percentage routing
//   - No allocations in hot path
//
// OBSERVABILITY:
//   - Logs decision for each rule (with rationale)
//   - Includes hash value for debugging distribution
//
// EXAMPLE:
//
//	if config.ShouldUseSigmaEngine("rule-001") {
//	    // Use native SIGMA engine
//	    result = sigmaEngine.Evaluate(rule, event)
//	} else {
//	    // Use legacy engine
//	    result = legacyEngine.Evaluate(rule, event)
//	}
func (c *SigmaRolloutConfig) ShouldUseSigmaEngine(ruleID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// DECISION 1: Master switch check
	// If native engine is disabled globally, use legacy engine
	if !c.Enabled {
		if c.logger != nil {
			c.logger.Debugw("SIGMA engine disabled globally",
				"rule_id", ruleID,
				"decision", "legacy",
				"reason", "master_switch_off",
			)
		}
		return false
	}

	// DECISION 2: Blocklist check (highest precedence)
	// If rule is explicitly disabled, use legacy engine
	if c.disabledMap[ruleID] {
		if c.logger != nil {
			c.logger.Debugw("SIGMA engine blocked for rule",
				"rule_id", ruleID,
				"decision", "legacy",
				"reason", "explicit_blocklist",
			)
		}
		return false
	}

	// DECISION 3: Whitelist check (second-highest precedence)
	// If rule is explicitly enabled, use native engine
	if c.enabledMap[ruleID] {
		if c.logger != nil {
			c.logger.Debugw("SIGMA engine whitelisted for rule",
				"rule_id", ruleID,
				"decision", "native",
				"reason", "explicit_whitelist",
			)
		}
		return true
	}

	// DECISION 4: Hash-based percentage routing (canary rollout)
	// Compute deterministic hash of rule ID to decide if it falls in rollout percentage
	hashValue := hashRuleID(ruleID)
	// Map hash to 0-100 range for percentage comparison
	hashPercentage := int(hashValue % 100)
	useSigma := hashPercentage < c.RolloutPercentage

	if c.logger != nil {
		c.logger.Debugw("SIGMA engine decision via hash routing",
			"rule_id", ruleID,
			"decision", map[bool]string{true: "native", false: "legacy"}[useSigma],
			"reason", "hash_based_routing",
			"hash_percentage", hashPercentage,
			"rollout_percentage", c.RolloutPercentage,
		)
	}

	return useSigma
}

// GetStats returns statistics about the current rollout configuration
//
// RETURNS:
//   - map with keys:
//   - "enabled": bool (master switch status)
//   - "rollout_percentage": int (0-100)
//   - "whitelist_count": int (number of explicitly enabled rules)
//   - "blocklist_count": int (number of explicitly disabled rules)
//
// THREAD-SAFETY:
//   - Safe to call concurrently from multiple goroutines
//
// USE CASE:
//   - Health check endpoints
//   - Metrics collection
//   - Admin dashboards
//
// EXAMPLE:
//
//	stats := config.GetStats()
//	fmt.Printf("Rollout: %d%%, Whitelist: %d, Blocklist: %d\n",
//	    stats["rollout_percentage"], stats["whitelist_count"], stats["blocklist_count"])
func (c *SigmaRolloutConfig) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"enabled":            c.Enabled,
		"rollout_percentage": c.RolloutPercentage,
		"whitelist_count":    len(c.enabledMap),
		"blocklist_count":    len(c.disabledMap),
	}
}

// hashRuleID computes a deterministic hash of a rule ID
//
// ALGORITHM:
//   - Uses SHA-256 for cryptographic quality hash (collision resistance)
//   - Converts first 8 bytes to uint64 for numeric comparison
//   - Same input always produces same output (deterministic)
//
// SECURITY:
//   - SHA-256 ensures even distribution across rule IDs
//   - No timing attacks possible (constant-time hash)
//   - No secret key required (not for authentication)
//
// PERFORMANCE:
//   - Fast (SHA-256 is hardware-accelerated on modern CPUs)
//   - No allocations beyond hash computation
//   - O(n) in rule ID length (typically short)
//
// PARAMETERS:
//   - ruleID: The rule identifier to hash
//
// RETURNS:
//   - uint64 hash value (0 to 2^64-1)
//
// EXAMPLE:
//
//	hash := hashRuleID("rule-001")
//	// hash is deterministic: same for "rule-001" every time
//	percentage := int(hash % 100) // Map to 0-99 range
func hashRuleID(ruleID string) uint64 {
	// SECURITY: Use SHA-256 for high-quality hash distribution
	// This ensures even spread of rules across rollout percentage buckets
	hash := sha256.Sum256([]byte(ruleID))

	// Convert first 8 bytes to uint64 for numeric operations
	// Using binary.BigEndian for consistent cross-platform behavior
	return binary.BigEndian.Uint64(hash[:8])
}
