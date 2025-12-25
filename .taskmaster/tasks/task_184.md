# Task ID: 184

**Title:** Remove Condition struct and deprecated fields from core data model

**Status:** pending

**Dependencies:** 180, 181, 182, 183

**Priority:** high

**Description:** Delete Condition struct, remove Conditions field from Rule and CorrelationRule, remove deprecated Detection and Logsource fields, finalize cleanup

**Details:**

PHASE 7: CORE DATA STRUCTURE REMOVAL - CRITICAL, final cleanup

**PREREQUISITES**: ALL previous phases (175-183) must be complete

Files to modify:
1. `core/rule.go` (lines 236-242) - DELETE Condition struct entirely
2. `core/rule.go` (line 34) - DELETE `Conditions []Condition` from Rule struct
3. `core/rule.go` (line 271) - DELETE `Conditions []Condition` from CorrelationRule struct
4. `core/rule.go` (lines 43-46) - DELETE deprecated Detection and Logsource fields

Before/After for core/rule.go:
```go
// BEFORE
type Rule struct {
    ID          string                 `json:"id"`
    // ...
    Conditions  []Condition            `json:"conditions"` // DELETE
    // ...
    Detection   map[string]interface{} `json:"detection,omitempty"` // DELETE (deprecated)
    Logsource   map[string]interface{} `json:"logsource,omitempty"` // DELETE (deprecated)
    SigmaYAML   string                 `json:"sigma_yaml,omitempty"` // KEEP
    // ...
}

type Condition struct { // DELETE ENTIRE STRUCT
    Field    string         `json:"field"`
    Operator string         `json:"operator"`
    Value    interface{}    `json:"value"`
    Logic    string         `json:"logic"`
    Regex    *regexp.Regexp `json:"-"`
}

// AFTER
type Rule struct {
    ID          string  `json:"id"`
    Type        string  `json:"type"`
    Name        string  `json:"name"`
    // ... other fields ...
    SigmaYAML   string  `json:"sigma_yaml,omitempty"`
    Query       string  `json:"query,omitempty"` // For CQL rules
    // ... no Conditions, Detection, or Logsource ...
}
// Condition struct deleted entirely
```

Cleanup validation:
- Search entire codebase for `core.Condition` references
- Verify no imports break
- Update any remaining documentation
- Update Swagger/OpenAPI specs if present

**Test Strategy:**

1. **PRE-FLIGHT CHECK**: Run `git grep 'Condition' .` and verify only core/rule.go and docs mention it
2. Run `go build ./...` - must compile without errors (CRITICAL)
3. Run `go test ./... -v` - ALL tests must pass (CRITICAL)
4. Run `golangci-lint run ./...` - no linting errors
5. Verify no undefined references: `go vet ./...`
6. Integration test: Full E2E flow - create SIGMA rule via API, process events, generate alerts
7. Load 100 SIGMA rules, process 10,000 events, verify correct alerts generated
8. Check binary size: Should be slightly smaller after removing ~500 lines
9. Verify API responses no longer include conditions field
10. Final verification: `git grep 'type.*Condition' .` should only return references to SIGMA condition parsing, not legacy Condition struct
