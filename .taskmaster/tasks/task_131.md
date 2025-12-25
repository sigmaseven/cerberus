# Task ID: 131

**Title:** Integrate SIGMA engine into main detection pipeline

**Status:** done

**Dependencies:** 129 ✓, 130 ✓

**Priority:** medium

**Description:** Wire SIGMA engine into existing RuleEngine, update API handlers to accept SIGMA YAML, and add feature flag for gradual rollout

**Details:**

1. Update config/config.go:
   - Add EnableNativeSigmaEngine bool (default: false)
   - Add SigmaFieldMappingConfig string (default: config/sigma_field_mappings.yaml)

2. Update detect/engine.go:
   - Add sigmaEngine *SigmaEngine field to RuleEngine
   - Initialize in NewRuleEngine if EnableNativeSigmaEngine=true
   - Modify evaluateRule to check rule.Type:
     * If type='sigma' and sigma_yaml present: Use sigmaEngine.Evaluate
     * Else: Use legacy condition-based evaluation
   - Add ReloadSigmaEngine method for cache invalidation

3. Update api/handlers.go:
   - POST /api/rules: Accept sigma_yaml in request body
   - Validate rule before storing (calls core.Rule.Validate)
   - Return sigma_yaml in response for SIGMA rules
   - PUT /api/rules/:id: Update sigma_yaml, invalidate cache

4. Update main.go initialization:
   - Load config.EnableNativeSigmaEngine
   - Pass to RuleEngine constructor
   - Log engine mode ("SIGMA native engine: enabled/disabled")

5. Add feature flag middleware (api/feature_flags.go):
   - Check if native engine enabled
   - Gradual rollout by rule ID hash (canary %)
   - Metrics: Track native vs legacy evaluation split

6. Update documentation:
   - README.md: Document sigma_yaml field
   - API docs: Show SIGMA YAML example requests
   - Configuration guide: EnableNativeSigmaEngine flag

7. Rollout strategy (Phase 6.2):
   - Week 1-2: 5% traffic (canary)
   - Week 3-4: 25% traffic
   - Week 5-6: 75% traffic
   - Week 7-8: 100% traffic, deprecate legacy

See Phase 6 in PRD for deployment and rollout strategy.

**Test Strategy:**

1. Integration tests:
   - Create SIGMA rule via API with sigma_yaml
   - Evaluate event against SIGMA rule
   - Verify native engine used (check metrics)
   - Update SIGMA rule, verify cache invalidated

2. Feature flag tests:
   - Flag disabled: Use legacy engine
   - Flag enabled: Use native engine
   - Canary rollout: Verify % split
   - Metrics: Track engine usage

3. Backward compatibility:
   - Legacy rules still work
   - Mixed rule set (SIGMA + legacy)
   - No performance regression

4. API tests:
   - POST with sigma_yaml
   - GET returns sigma_yaml
   - PUT updates sigma_yaml
   - Validation errors returned

5. End-to-end tests:
   - Ingest event → Rule evaluation → Alert generation
   - SIGMA rule matches event
   - Legacy rule matches event
   - Both match same event

6. Performance comparison:
   - Native vs legacy latency (p50, p95, p99)
   - Throughput (events/sec)
   - Memory usage
   - CPU usage

7. Rollout validation:
   - Canary metrics (5% split)
   - Error rate comparison
   - Match accuracy (no false negatives)

## Subtasks

### 131.1. Update config/config.go for SIGMA engine configuration

**Status:** done  
**Dependencies:** None  

Add EnableNativeSigmaEngine boolean flag and SigmaFieldMappingConfig string field to the Config struct to control SIGMA engine behavior

**Details:**

Add two new fields to the Config struct in config/config.go:
- EnableNativeSigmaEngine bool (default: false) - controls whether native SIGMA engine is active
- SigmaFieldMappingConfig string (default: 'config/sigma_field_mappings.yaml') - path to field mapping configuration

Ensure proper YAML/JSON tags for config file parsing. Update config validation to verify field mapping file exists when EnableNativeSigmaEngine=true.

### 131.2. Update detect/engine.go to integrate SIGMA engine

**Status:** done  
**Dependencies:** 131.1  

Modify RuleEngine to support dual evaluation mode with native SIGMA engine and legacy condition-based engine based on rule type

**Details:**

1. Add sigmaEngine *SigmaEngine field to RuleEngine struct
2. Modify NewRuleEngine constructor:
   - Check config.EnableNativeSigmaEngine
   - If true: Initialize sigmaEngine with field mapper from config.SigmaFieldMappingConfig
   - Pass necessary dependencies (logger, metrics)
3. Update evaluateRule method:
   - Check rule.Type field
   - If type='sigma' AND rule.SigmaYAML is present: Call sigmaEngine.Evaluate(event, rule.SigmaYAML)
   - Else: Use existing legacy condition-based evaluation
4. Add ReloadSigmaEngine() error method for cache invalidation when rules change
5. Ensure thread-safety for concurrent evaluations

### 131.3. Update api/handlers.go for SIGMA YAML CRUD operations

**Status:** done  
**Dependencies:** 131.1  

Extend rule API handlers to accept, validate, store, and return sigma_yaml field for SIGMA-type rules

**Details:**

1. Update POST /api/rules handler:
   - Accept sigma_yaml in request body
   - Call core.Rule.Validate() before storing (checks mutual exclusion with query field)
   - Store sigma_yaml in database via storage layer
   - Return full rule including sigma_yaml in response
2. Update PUT /api/rules/:id handler:
   - Accept sigma_yaml updates
   - Validate updated rule with core.Rule.Validate()
   - Call engine.ReloadSigmaEngine() after successful update to invalidate cache
   - Return updated rule with sigma_yaml
3. Update GET handlers to include sigma_yaml in responses for SIGMA rules
4. Add proper error handling for validation failures (400 Bad Request with details)

### 131.4. Update main.go initialization for SIGMA engine

**Status:** done  
**Dependencies:** 131.2  

Load SIGMA engine configuration and initialize RuleEngine with proper logging of engine mode on startup

**Details:**

1. In main.go initialization sequence:
   - Load config.EnableNativeSigmaEngine flag from configuration file
   - Pass EnableNativeSigmaEngine to RuleEngine constructor (detect.NewRuleEngine)
   - Add startup logging:
     * If enabled: log.Info("SIGMA native engine: enabled")
     * If disabled: log.Info("SIGMA native engine: disabled (using legacy engine)")
2. Ensure proper initialization order:
   - Config loading first
   - Storage initialization
   - RuleEngine initialization with config
   - API server startup last
3. Add graceful shutdown for SIGMA engine resources (cache cleanup)

### 131.5. Create api/feature_flags.go for gradual SIGMA rollout

**Status:** done  
**Dependencies:** 131.2, 131.3  

Implement feature flag middleware for gradual rollout of native SIGMA engine using canary deployment strategy with hash-based traffic routing

**Details:**

Create api/feature_flags.go:
1. Implement canary percentage middleware:
   - Hash rule ID to determine routing (consistent hashing)
   - Compare hash % 100 with canary percentage threshold
   - If within threshold: Use native SIGMA engine
   - Else: Use legacy engine (fallback)
2. Add metrics tracking:
   - Counter: native_engine_evaluations_total
   - Counter: legacy_engine_evaluations_total
   - Histogram: evaluation_duration_seconds (labeled by engine type)
3. Configuration:
   - CanaryPercentage int (0-100, default 0)
   - Allow runtime updates via API or config reload
4. Integration with RuleEngine.evaluateRule to respect canary setting

### 131.6. Update documentation for SIGMA integration

**Status:** done  
**Dependencies:** 131.3, 131.4, 131.5  

Document SIGMA YAML field usage, configuration flags, and API examples in README.md and API documentation

**Details:**

1. Update README.md:
   - Add section 'SIGMA Rule Support'
   - Document EnableNativeSigmaEngine configuration flag
   - Document SigmaFieldMappingConfig path configuration
   - Add example SIGMA YAML rule snippet
   - Explain feature flag rollout strategy (canary deployment)
2. Update API documentation (docs/swagger.yaml or similar):
   - Add sigma_yaml field to Rule schema (string, optional)
   - Show example POST /api/rules request with sigma_yaml
   - Show example response with sigma_yaml included
   - Document validation error responses
3. Create configuration guide:
   - Document rollout phases (5% → 25% → 75% → 100%)
   - Explain monitoring metrics for native vs legacy split
   - Provide troubleshooting guide for SIGMA parsing errors
