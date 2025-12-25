//go:build ignore

package examples

// TASK 131.5: Example of SIGMA Engine Gradual Rollout Integration
//
// This example demonstrates how to integrate the SigmaRolloutConfig
// feature flags into the rule evaluation engine.
//
// PRODUCTION USAGE:
//   1. Load configuration from config.yaml
//   2. Create SigmaRolloutConfig from config values
//   3. Use ShouldUseSigmaEngine() to route rule evaluations
//   4. Track metrics for monitoring rollout health
//
// SECURITY: This example shows production-ready patterns for:
//   - Safe feature flag initialization
//   - Thread-safe concurrent access
//   - Comprehensive error handling
//   - Observability through metrics
//
// NOTE: This is example code only - not compiled as part of the main binary

import (
	"cerberus/api"
	"cerberus/config"
	"cerberus/core"
	"cerberus/detect"
	"cerberus/metrics"
	"context"
	"log"

	"go.uber.org/zap"
)

// InitializeSigmaRollout creates a SigmaRolloutConfig from application config
//
// PARAMETERS:
//   - cfg: Application configuration loaded from config.yaml
//   - logger: Structured logger for audit trail
//
// RETURNS:
//   - Configured SigmaRolloutConfig instance
//   - Error if validation fails
//
// THREAD-SAFETY:
//   - Safe to call from multiple goroutines
//   - Returned config is immutable
func InitializeSigmaRollout(cfg *config.Config, logger *zap.SugaredLogger) (*api.SigmaRolloutConfig, error) {
	// Extract rollout configuration from engine config
	enabled := cfg.Engine.EnableNativeSigmaEngine
	percentage := cfg.Engine.SigmaRolloutPercentage
	enabledRules := cfg.Engine.SigmaRolloutEnabledRules
	disabledRules := cfg.Engine.SigmaRolloutDisabledRules

	// Create rollout configuration with validation
	rolloutConfig, err := api.NewSigmaRolloutConfig(
		enabled,
		percentage,
		enabledRules,
		disabledRules,
		logger,
	)
	if err != nil {
		return nil, err
	}

	// Log initialization for audit trail
	logger.Infow("SIGMA rollout initialized",
		"enabled", enabled,
		"percentage", percentage,
		"whitelist_count", len(enabledRules),
		"blocklist_count", len(disabledRules),
	)

	return rolloutConfig, nil
}

// EvaluateRuleWithRollout evaluates a rule using the appropriate engine based on rollout config
//
// DECISION FLOW:
//   1. Check if rule should use native SIGMA engine (feature flag)
//   2. Route to appropriate engine (native or legacy)
//   3. Track metrics for monitoring
//   4. Handle errors gracefully
//
// PARAMETERS:
//   - rolloutConfig: Feature flag configuration
//   - sigmaEngine: Native SIGMA detection engine (may be nil if disabled)
//   - rule: Detection rule to evaluate
//   - event: Event to evaluate against rule
//
// RETURNS:
//   - true if rule matched event
//   - false if no match or evaluation error
//
// THREAD-SAFETY:
//   - Safe to call concurrently from multiple goroutines
//   - Uses read-only access to rollout config
//
// OBSERVABILITY:
//   - Tracks engine usage via Prometheus metrics
//   - Logs decision rationale for debugging
func EvaluateRuleWithRollout(
	rolloutConfig *api.SigmaRolloutConfig,
	sigmaEngine *detect.SigmaEngine,
	rule *core.Rule,
	event *core.Event,
) bool {
	// DECISION: Should this rule use native SIGMA engine?
	useNative := rolloutConfig.ShouldUseSigmaEngine(rule.ID)

	if useNative {
		// NATIVE ENGINE PATH
		// Track decision for metrics
		metrics.SigmaRolloutDecisions.WithLabelValues("native", "rollout_decision").Inc()

		// Validate SIGMA engine is available
		if sigmaEngine == nil {
			// Fallback to legacy if native engine not initialized
			log.Printf("WARN: Native engine selected but not initialized for rule %s, falling back to legacy", rule.ID)
			metrics.SigmaEngineErrors.WithLabelValues("engine_unavailable", rule.ID).Inc()
			return evaluateLegacyRule(rule, event)
		}

		// Evaluate with native SIGMA engine
		matched, err := sigmaEngine.Evaluate(rule, event)
		if err != nil {
			// Log error and fallback to legacy engine
			log.Printf("ERROR: SIGMA engine evaluation failed for rule %s: %v", rule.ID, err)
			metrics.SigmaEngineErrors.WithLabelValues("evaluation_error", rule.ID).Inc()
			// Graceful degradation: use legacy engine
			return evaluateLegacyRule(rule, event)
		}

		// Track successful native engine evaluation
		metrics.SigmaEngineEvaluations.WithLabelValues("native", rule.ID).Inc()
		return matched
	}

	// LEGACY ENGINE PATH
	// Track decision for metrics
	metrics.SigmaRolloutDecisions.WithLabelValues("legacy", "rollout_decision").Inc()
	metrics.SigmaEngineEvaluations.WithLabelValues("legacy", rule.ID).Inc()

	return evaluateLegacyRule(rule, event)
}

// evaluateLegacyRule evaluates a rule using the legacy condition-based engine
//
// BACKWARD COMPATIBILITY: This maintains existing behavior for non-SIGMA rules
//
// PARAMETERS:
//   - rule: Detection rule to evaluate
//   - event: Event to evaluate against rule
//
// RETURNS:
//   - true if rule matched event
//   - false if no match
func evaluateLegacyRule(rule *core.Rule, event *core.Event) bool {
	// Legacy evaluation logic (simplified for example)
	// In production, this would be the full condition evaluation logic
	if len(rule.Conditions) == 0 {
		return false
	}

	// Evaluate first condition (simplified)
	// Real implementation would evaluate all conditions with AND/OR logic
	cond := rule.Conditions[0]
	fieldValue := event.Data[cond.Field]
	if fieldValue == nil {
		return false
	}

	// Simple string equality check (simplified)
	// Real implementation would support all operators
	if cond.Operator == "equals" {
		return fieldValue == cond.Value
	}

	return false
}

// RolloutHealthCheck monitors rollout health and returns status
//
// USE CASE: Health check endpoint for monitoring rollout status
//
// PARAMETERS:
//   - rolloutConfig: Feature flag configuration
//
// RETURNS:
//   - Health status map with rollout metrics
func RolloutHealthCheck(rolloutConfig *api.SigmaRolloutConfig) map[string]interface{} {
	stats := rolloutConfig.GetStats()

	health := map[string]interface{}{
		"status": "healthy",
		"rollout": stats,
	}

	// Check for potential issues
	if enabled, ok := stats["enabled"].(bool); ok && enabled {
		if percentage, ok := stats["rollout_percentage"].(int); ok {
			if percentage > 0 {
				health["message"] = "Native SIGMA engine partially deployed"
			} else {
				health["message"] = "Native SIGMA engine enabled but not rolled out"
			}
		}
	} else {
		health["message"] = "Native SIGMA engine disabled"
	}

	return health
}

// ExampleGradualRollout demonstrates a complete rollout workflow
//
// This example shows:
//   - Configuration loading
//   - Feature flag initialization
//   - Rule evaluation with routing
//   - Health monitoring
//
// PRODUCTION NOTES:
//   - Run this in integration tests before production deployment
//   - Monitor metrics after each rollout percentage increase
//   - Use health check endpoint for automated monitoring
func ExampleGradualRollout() {
	// Step 1: Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Step 2: Initialize logger
	logger, _ := zap.NewProduction()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Step 3: Initialize rollout configuration
	rolloutConfig, err := InitializeSigmaRollout(cfg, sugar)
	if err != nil {
		log.Fatalf("Failed to initialize rollout: %v", err)
	}

	// Step 4: Initialize SIGMA engine (if enabled)
	var sigmaEngine *detect.SigmaEngine
	if cfg.Engine.EnableNativeSigmaEngine {
		sigmaEngine, err = detect.NewSigmaEngine(
			cfg.Engine.SigmaFieldMappingConfig,
			cfg.Engine.SigmaEngineCacheSize,
			cfg.Engine.SigmaEngineCacheTTL,
			cfg.Engine.SigmaEngineCleanupInterval,
			sugar,
		)
		if err != nil {
			log.Fatalf("Failed to initialize SIGMA engine: %v", err)
		}
		// Start background cache cleanup
		ctx := context.Background()
		sigmaEngine.Start(ctx)
		defer sigmaEngine.Stop()
	}

	// Step 5: Example rule evaluation
	rule := &core.Rule{
		ID:      "example-rule-001",
		Name:    "Example Detection Rule",
		Type:    "sigma",
		Enabled: true,
		// ... other rule fields
	}

	event := &core.Event{
		EventID: "evt-12345",
		Data: map[string]interface{}{
			"event_type": "login",
			"username":   "admin",
		},
		// ... other event fields
	}

	// Evaluate rule with rollout routing
	matched := EvaluateRuleWithRollout(rolloutConfig, sigmaEngine, rule, event)
	if matched {
		log.Printf("Rule %s matched event %s", rule.ID, event.EventID)
	}

	// Step 6: Monitor rollout health
	health := RolloutHealthCheck(rolloutConfig)
	log.Printf("Rollout health: %+v", health)

	// Step 7: Output rollout statistics
	stats := rolloutConfig.GetStats()
	log.Printf("Rollout statistics: %+v", stats)
}

// ExampleRolloutPhases demonstrates configuration for each rollout phase
func ExampleRolloutPhases() {
	// Phase 1: Pre-deployment (0% rollout)
	// Purpose: Validate metrics and configuration
	phase1 := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine":  true,
			"sigma_rollout_percentage":    0,
			"sigma_rollout_enabled_rules": []string{},
			"sigma_rollout_disabled_rules": []string{},
		},
	}
	log.Printf("Phase 1 (Pre-deployment): %+v", phase1)

	// Phase 2: Canary (5% rollout)
	// Purpose: Initial production testing with small percentage
	phase2 := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine":  true,
			"sigma_rollout_percentage":    5,
			"sigma_rollout_enabled_rules": []string{"high-confidence-rule"},
			"sigma_rollout_disabled_rules": []string{},
		},
	}
	log.Printf("Phase 2 (Canary): %+v", phase2)

	// Phase 3: Expansion (25% rollout)
	// Purpose: Confidence building with larger percentage
	phase3 := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine":  true,
			"sigma_rollout_percentage":    25,
			"sigma_rollout_enabled_rules": []string{"high-confidence-rule"},
			"sigma_rollout_disabled_rules": []string{"known-slow-rule"},
		},
	}
	log.Printf("Phase 3 (Expansion): %+v", phase3)

	// Phase 4: Majority (75% rollout)
	// Purpose: Prepare for full migration
	phase4 := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine":  true,
			"sigma_rollout_percentage":    75,
			"sigma_rollout_enabled_rules": []string{},
			"sigma_rollout_disabled_rules": []string{"known-slow-rule"},
		},
	}
	log.Printf("Phase 4 (Majority): %+v", phase4)

	// Phase 5: Complete (100% rollout)
	// Purpose: Full migration to native engine
	phase5 := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine":  true,
			"sigma_rollout_percentage":    100,
			"sigma_rollout_enabled_rules": []string{},
			"sigma_rollout_disabled_rules": []string{},
		},
	}
	log.Printf("Phase 5 (Complete): %+v", phase5)

	// Emergency Rollback
	// Purpose: Immediate fallback to legacy engine
	rollback := map[string]interface{}{
		"engine": map[string]interface{}{
			"enable_native_sigma_engine": false, // Master switch off
		},
	}
	log.Printf("Emergency Rollback: %+v", rollback)
}
