# Task ID: 183

**Title:** Remove legacy config fields and delete deprecated rule schema files

**Status:** pending

**Dependencies:** 182

**Priority:** low

**Description:** Delete Rules.File and CorrelationRules.File config fields, remove JSON schema files, update config documentation

**Details:**

PHASE 6: CONFIGURATION REMOVAL - Low risk

Files to DELETE entirely:
1. `rules_schema.json` - Legacy rule JSON schema
2. `correlation_rules_schema.json` - Legacy correlation rule schema
3. `tools/rulegen/rules/detection_rules.json` (if exists)
4. `tools/rulegen/rules/correlation_rules.json` (if exists)
5. `tools/rulegen/rules/windows_detection_rules.json` (if exists)

Files to modify:
1. `config/config.go` (lines 149-155) - DELETE Rules.File and CorrelationRules.File
2. `config/config.go` (lines 409-410) - Remove viper defaults for these fields
3. `config/config.go` (lines 563-568) - Remove filepath adjustment logic
4. `config/config.go` (lines 775-796) - Remove file validation logic
5. `config.yaml` - Remove rules.file and correlation_rules.file examples

Before/After for config/config.go:
```go
// BEFORE (lines 149-155)
type Config struct {
    // ...
    Rules struct {
        File string `mapstructure:"file"` // DELETE THIS
    } `mapstructure:"rules"`
    
    CorrelationRules struct {
        File string `mapstructure:"file"` // DELETE THIS
    } `mapstructure:"correlation_rules"`
    // ...
}

// AFTER
type Config struct {
    // ... other fields ...
    // Rules and CorrelationRules sections removed entirely
    // Rules now loaded exclusively from database
}
```

Update documentation:
1. `README.md` - Remove JSON file configuration instructions
2. `docs/operations/configuration.md` - Document database-only rule loading
3. Add migration guide: `docs/operations/migrating-from-json-rules.md`

Remove validation:
- Delete file existence checks for rules.json
- Delete JSON/YAML format validation for rule files
- Keep database validation intact

**Test Strategy:**

1. Run `go build ./...` - must compile without errors
2. Start Cerberus without rules.file in config - should work
3. Start Cerberus with rules.file in config - should be ignored (not error)
4. Verify deleted schema files don't break any imports
5. Check documentation renders correctly
6. Run `git grep 'Rules\.File' .` - should return 0 results in Go files
7. Run `git grep 'rules\.file' config.yaml` - should return 0 results
