# Task ID: 179

**Title:** Update API validation to reject legacy condition-based rules

**Status:** pending

**Dependencies:** 175, 176, 177, 178

**Priority:** high

**Description:** Modify rule creation and update handlers to reject any rule with non-empty Conditions field and require SigmaYAML for all SIGMA rules

**Details:**

PHASE 2: API LAYER REMOVAL - Medium risk, user-facing changes

Files to modify:
1. `api/handlers.go` (lines 199-278) - `createRule()` validation
2. `api/handlers.go` (lines 280-381) - `updateRule()` validation
3. `api/validation.go` - Add SIGMA-only validation rules
4. `api/rules_import_export.go` - Reject imports with conditions

Implementation:
```go
// In api/validation.go
func ValidateRuleForCreation(rule *core.Rule) error {
    // SIGMA rules must have sigma_yaml, cannot have conditions
    if strings.ToUpper(rule.Type) == "SIGMA" {
        if strings.TrimSpace(rule.SigmaYAML) == "" {
            return fmt.Errorf("SIGMA rules must have sigma_yaml field populated")
        }
        if len(rule.Conditions) > 0 {
            return fmt.Errorf("legacy Conditions field is deprecated and not supported - use sigma_yaml instead")
        }
    }
    
    // CQL rules validation (if supported)
    if strings.ToUpper(rule.Type) == "CQL" {
        if strings.TrimSpace(rule.Query) == "" {
            return fmt.Errorf("CQL rules must have query field populated")
        }
    }
    
    return nil
}

// In api/handlers.go createRule()
func (a *API) createRule(c *gin.Context) {
    var rule core.Rule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Validate rule format
    if err := ValidateRuleForCreation(&rule); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // ... rest of creation logic
}
```

API response changes:
- GET /api/v1/rules - Stop returning `conditions` field
- POST /api/rules - Return 400 if `conditions` present
- PUT /api/rules/{id} - Return 400 if `conditions` present
- Add migration guide in API docs

**Test Strategy:**

1. Integration test: POST rule with conditions field -> expect 400 error
2. Integration test: POST valid SIGMA rule -> expect 201 created
3. Integration test: PUT rule adding conditions -> expect 400 error
4. Test import endpoint with legacy JSON -> expect rejection
5. Run `go test ./api/... -v` - all tests must pass
6. Manual test: Use curl to POST legacy rule format, verify rejection
7. Verify error message guides users to SIGMA YAML format
