package detect

import (
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// TASK #184: Legacy Conditions conversion functions removed
// The following functions were deleted:
// - operatorToSigmaModifier
// - convertConditionsToSigmaYAML
// - autoConvertRulesToSigma
// All rules now use SigmaYAML directly - no legacy Conditions support

// newTestRuleEngineWithSigma creates a RuleEngine with SIGMA support enabled for testing.
// This helper ensures tests using SIGMA YAML rules properly initialize the SIGMA engine.
func newTestRuleEngineWithSigma(rules []core.Rule) *RuleEngine {
	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        5 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
		Logger:                     zap.NewNop().Sugar(),
	}
	return NewRuleEngineWithConfig(rules, []core.CorrelationRule{}, 0, config)
}
