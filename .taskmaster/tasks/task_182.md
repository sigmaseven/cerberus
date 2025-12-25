# Task ID: 182

**Title:** Remove file-based rule loading and simplify bootstrap

**Status:** pending

**Dependencies:** 181

**Priority:** medium

**Description:** Delete LoadRules() and LoadCorrelationRules() file loading functions, remove file fallback logic from bootstrap, keep only database loading

**Details:**

PHASE 5: LOADER & BOOTSTRAP REMOVAL - Medium risk

Files to modify:
1. `detect/loader.go` - DELETE LoadRules(), loadRulesFromFile(), compileRegexInRules()
2. `detect/loader.go` - DELETE LoadCorrelationRules(), loadCorrelationRulesFromFile(), compileRegexInCorrelationRules()
3. `detect/loader.go` - KEEP LoadRulesFromDB() (database loading)
4. `bootstrap/detection.go` (lines 62-107) - Remove file fallback from LoadRules()
5. `bootstrap/detection.go` (lines 110-128) - Remove file fallback from LoadCorrelationRules()

Before/After for bootstrap/detection.go:
```go
// BEFORE LoadRules() (lines 62-107)
func LoadRules(cfg *config.Config, ruleStorage storage.RuleStorageInterface, sugar *zap.SugaredLogger) ([]core.Rule, bool, error) {
    rules, err := detect.LoadRulesFromDB(ruleStorage)
    dbWasEmpty := false
    
    if err != nil {
        // File fallback - REMOVE THIS BLOCK
        if cfg.Rules.File != "" {
            sugar.Warnf("Failed to load rules from database (%v), trying file: %s", err, cfg.Rules.File)
            rules, err = detect.LoadRules(cfg.Rules.File, sugar)
            // ... file loading logic ...
        }
    }
    return rules, dbWasEmpty, nil
}

// AFTER LoadRules() (simplified)
func LoadRules(cfg *config.Config, ruleStorage storage.RuleStorageInterface, sugar *zap.SugaredLogger) ([]core.Rule, bool, error) {
    rules, err := detect.LoadRulesFromDB(ruleStorage)
    if err != nil {
        return nil, false, fmt.Errorf("failed to load rules from database: %w", err)
    }
    
    dbWasEmpty := len(rules) == 0
    if dbWasEmpty {
        sugar.Warn("No rules found in database - use SIGMA feeds or API to import rules")
    } else {
        sugar.Infof("Loaded %d rules from database", len(rules))
    }
    
    return rules, dbWasEmpty, nil
}
```

Delete from detect/loader.go (~200 lines):
- loadRulesFromFile()
- loadCorrelationRulesFromFile()
- compileRegexInRules() (only used for legacy Conditions)
- compileRegexInCorrelationRules()
- LoadRules() wrapper
- LoadCorrelationRules() wrapper
- JSON/YAML file parsing logic

**Test Strategy:**

1. Run `go test ./detect/... ./bootstrap/... -v` - all tests must pass
2. Integration test: Start Cerberus with empty database, verify it starts successfully
3. Integration test: Start Cerberus with rules in database, verify they load
4. Negative test: Set Rules.File in config, verify it's ignored (no error, no loading)
5. Verify bootstrap logs show database loading only
6. Check that LoadRulesFromDB still works correctly
7. End-to-end test: Import SIGMA feed, restart Cerberus, verify rules loaded from DB

## Subtasks

### 182.1. Delete file loading functions from detect/loader.go

**Status:** pending  
**Dependencies:** None  

Remove LoadRules(), loadRulesFromFile(), LoadCorrelationRules(), loadCorrelationRulesFromFile(), compileRegexInRules(), and compileRegexInCorrelationRules() functions along with JSON/YAML file parsing logic (~200 lines total)

**Details:**

Delete the following functions from detect/loader.go:
1. LoadRules() - wrapper function for file-based rule loading
2. loadRulesFromFile() - JSON/YAML file parsing for rules
3. compileRegexInRules() - regex compilation for legacy Conditions
4. LoadCorrelationRules() - wrapper function for correlation rule file loading
5. loadCorrelationRulesFromFile() - JSON/YAML file parsing for correlation rules
6. compileRegexInCorrelationRules() - regex compilation for correlation rules

KEEP LoadRulesFromDB() - this is the database loading function that must remain. Remove all file I/O logic, JSON unmarshaling for rule files, and YAML parsing code. This will eliminate approximately 200 lines of deprecated file-based loading logic.

### 182.2. Simplify bootstrap LoadRules() to remove file fallback

**Status:** pending  
**Dependencies:** 182.1  

Refactor bootstrap/detection.go LoadRules() function (lines 62-107) to remove file fallback logic and only use database loading with proper error handling

**Details:**

Modify bootstrap/detection.go LoadRules() function:

REMOVE:
- File fallback block that attempts to load from cfg.Rules.File on database error
- All file loading error handling and warnings
- JSON/YAML file path checking logic

SIMPLIFY TO:
```go
func LoadRules(cfg *config.Config, ruleStorage storage.RuleStorageInterface, sugar *zap.SugaredLogger) ([]core.Rule, bool, error) {
    rules, err := detect.LoadRulesFromDB(ruleStorage)
    if err != nil {
        return nil, false, fmt.Errorf("failed to load rules from database: %w", err)
    }
    
    dbWasEmpty := len(rules) == 0
    if dbWasEmpty {
        sugar.Warn("No rules found in database - use SIGMA feeds or API to import rules")
    } else {
        sugar.Infof("Loaded %d rules from database", len(rules))
    }
    
    return rules, dbWasEmpty, nil
}
```

This reduces lines 62-107 (46 lines) to approximately 15 lines of database-only loading logic.

### 182.3. Simplify bootstrap LoadCorrelationRules() to remove file fallback

**Status:** pending  
**Dependencies:** 182.1  

Refactor bootstrap/detection.go LoadCorrelationRules() function (lines 110-128) to remove file fallback logic and only use database loading with proper error handling

**Details:**

Modify bootstrap/detection.go LoadCorrelationRules() function:

REMOVE:
- File fallback block that attempts to load from cfg.CorrelationRules.File on database error
- All file loading error handling and warnings
- JSON/YAML file path checking logic

SIMPLIFY TO:
```go
func LoadCorrelationRules(cfg *config.Config, correlationRuleStorage storage.CorrelationRuleStorageInterface, sugar *zap.SugaredLogger) ([]core.CorrelationRule, bool, error) {
    rules, err := detect.LoadCorrelationRulesFromDB(correlationRuleStorage)
    if err != nil {
        return nil, false, fmt.Errorf("failed to load correlation rules from database: %w", err)
    }
    
    dbWasEmpty := len(rules) == 0
    if dbWasEmpty {
        sugar.Warn("No correlation rules found in database - use API to import rules")
    } else {
        sugar.Infof("Loaded %d correlation rules from database", len(rules))
    }
    
    return rules, dbWasEmpty, nil
}
```

This reduces lines 110-128 (19 lines) to approximately 15 lines of database-only loading logic.

### 182.4. Integration testing with multiple database and config scenarios

**Status:** pending  
**Dependencies:** 182.2, 182.3  

Execute comprehensive integration tests covering empty database startup, populated database startup, invalid config scenarios, and verify database-only loading works reliably across all cases

**Details:**

Run comprehensive integration tests:

1. **Empty database test**: Start Cerberus with empty database, verify:
   - Application starts successfully without errors
   - Warning logged: "No rules found in database"
   - Warning logged: "No correlation rules found in database"
   - No file loading attempted

2. **Populated database test**: Start Cerberus with rules and correlation rules in database, verify:
   - All rules load successfully from database
   - Info logs show correct count: "Loaded X rules from database"
   - Info logs show correct count: "Loaded X correlation rules from database"
   - Rules are active and can match events

3. **Invalid config test**: Set Rules.File or CorrelationRules.File in config (if fields still exist), verify:
   - Fields are ignored (no file loading attempted)
   - Database loading proceeds normally
   - No errors or warnings about missing files

4. **Startup error handling**: Test database connection failure scenarios, verify:
   - Proper error propagation with context
   - Application fails fast with clear error message
   - No fallback attempts to file loading

Run full test suite: `go test ./detect/... ./bootstrap/... -v -race`
