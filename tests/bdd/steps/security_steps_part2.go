// Package steps - Security Steps Part 2 (SQL Injection & Code Inspection)
package steps

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// iSearchForRulesWithName searches for rules by name field
func (sc *SecurityContext) iSearchForRulesWithName(name string) error {
	return sc.iSearchForRulesWithQuery(fmt.Sprintf("name:%s", name))
}

// iInspectStorageSourceCode inspects storage layer code for SQL injection vulnerabilities
// Requirement: SEC-003 - SQL Injection Prevention (code inspection)
func (sc *SecurityContext) iInspectStorageSourceCode() error {
	// Define storage layer source files to inspect
	storageFiles := []string{
		"storage/sqlite_rules.go",
		"storage/sqlite_alerts.go",
		"storage/sqlite_users.go",
		"storage/sqlite_actions.go",
		"storage/sqlite_correlation_rules.go",
		"storage/clickhouse_events.go",
		"storage/clickhouse_alerts.go",
	}

	sc.inspectedFiles = []string{}
	sc.violations = []string{}

	for _, relPath := range storageFiles {
		// Construct absolute path
		absPath := filepath.Join("..", "..", relPath) // From tests/bdd/steps

		// Check if file exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			// File doesn't exist, skip
			continue
		}

		sc.inspectedFiles = append(sc.inspectedFiles, relPath)
	}

	if len(sc.inspectedFiles) == 0 {
		return fmt.Errorf("no storage files found to inspect")
	}

	return nil
}

// iCreateRuleWithName creates a rule with a potentially malicious name
func (sc *SecurityContext) iCreateRuleWithName(ruleName string) error {
	ruleID := fmt.Sprintf("test-rule-%d", len(sc.testRules)+1)

	rule := map[string]interface{}{
		"id":          ruleID,
		"name":        ruleName, // Potentially malicious name
		"description": "Test rule",
		"severity":    "Low",
		"enabled":     true,
		"type":        "sigma",
	}

	err := sc.createRule(rule)
	if err != nil {
		sc.lastError = err
		return nil // Store error, don't fail yet
	}

	return nil
}

// theSearchShouldSucceed verifies the search request succeeded
// Requirement: SEC-003 - SQL Injection Prevention (verification)
func (sc *SecurityContext) theSearchShouldSucceed() error {
	if sc.lastError != nil {
		return fmt.Errorf("search failed with error: %w", sc.lastError)
	}

	if sc.lastResponse == nil {
		return fmt.Errorf("no response received")
	}

	if sc.lastResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200, got %d", sc.lastResponse.StatusCode)
	}

	return nil
}

// theSearchShouldCompleteInUnder verifies query completes within time limit
// Requirement: SEC-003 - Prevent time-based blind SQL injection
func (sc *SecurityContext) theSearchShouldCompleteInUnder(seconds int) error {
	maxDuration := time.Duration(seconds) * time.Second

	if sc.queryDuration >= maxDuration {
		return fmt.Errorf("query took %v, should complete in under %v (possible time-based injection)",
			sc.queryDuration, maxDuration)
	}

	return nil
}

// noUserDataInResults verifies no sensitive user data leaked via UNION injection
// Requirement: SEC-003 - UNION injection prevention
func (sc *SecurityContext) noUserDataInResults() error {
	for _, result := range sc.searchResults {
		if containsSensitiveFields(result) {
			return fmt.Errorf("UNION injection may have succeeded - sensitive data in results: %+v", result)
		}
	}

	return nil
}

// onlyValidRuleDataReturned verifies only rule data is returned
// Requirement: SEC-003 - SQL Injection Prevention
func (sc *SecurityContext) onlyValidRuleDataReturned() error {
	for _, result := range sc.searchResults {
		// Check for expected rule fields
		if _, hasID := result["id"]; !hasID {
			return fmt.Errorf("result missing 'id' field, not valid rule data: %+v", result)
		}

		// Check for unexpected fields that might indicate data leak
		suspiciousFields := []string{"password", "password_hash", "api_key", "secret"}
		for _, field := range suspiciousFields {
			if _, exists := result[field]; exists {
				return fmt.Errorf("result contains suspicious field '%s': %+v", field, result)
			}
		}
	}

	return nil
}

// noDatabaseErrorExposed verifies no database errors in response
// Requirement: SEC-003 - Error-based SQL injection prevention
func (sc *SecurityContext) noDatabaseErrorExposed() error {
	if sc.lastResponseBody == nil {
		return nil
	}

	bodyStr := string(sc.lastResponseBody)

	// Database error signatures
	dbErrorSignatures := []string{
		"SQL",
		"syntax error",
		"sqlite",
		"clickhouse",
		"column",
		"table",
		"database",
		"constraint",
		"SQLSTATE",
	}

	for _, signature := range dbErrorSignatures {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(signature)) {
			return fmt.Errorf("database error exposed in response: found '%s' in body", signature)
		}
	}

	return nil
}

// theAttackShouldNotExecute verifies injection attack did not execute
// Requirement: SEC-003 - SQL Injection Prevention
func (sc *SecurityContext) theAttackShouldNotExecute() error {
	// Combination check
	if err := sc.theSearchShouldSucceed(); err != nil {
		return err
	}

	if err := sc.noUserDataInResults(); err != nil {
		return err
	}

	if err := sc.noDatabaseErrorExposed(); err != nil {
		return err
	}

	return nil
}

// allQueriesUseParameterizedStatements inspects code for parameterized queries
// Requirement: SEC-003 - Code inspection for parameterized queries
func (sc *SecurityContext) allQueriesUseParameterizedStatements() error {
	violations := []string{}

	for _, relPath := range sc.inspectedFiles {
		absPath := filepath.Join("..", "..", relPath)

		content, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", relPath, err)
		}

		source := string(content)

		// Look for database query methods
		queryPatterns := []string{
			`\.Query\(`,
			`\.QueryRow\(`,
			`\.Exec\(`,
			`\.QueryContext\(`,
			`\.QueryRowContext\(`,
			`\.ExecContext\(`,
		}

		// For each query method found, check if it has ? placeholders
		for _, pattern := range queryPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringIndex(source, -1)

			for _, match := range matches {
				// Extract surrounding context (next 200 characters)
				start := match[0]
				end := start + 200
				if end > len(source) {
					end = len(source)
				}

				queryContext := source[start:end]

				// Check if this query uses parameterization
				// Look for ? placeholder or is a DDL statement (CREATE, DROP, ALTER)
				isDDL := regexp.MustCompile(`(?i)(CREATE|DROP|ALTER|PRAGMA)`).MatchString(queryContext)
				hasPlaceholder := strings.Contains(queryContext, "?") || strings.Contains(queryContext, "$")

				if !hasPlaceholder && !isDDL {
					violation := fmt.Sprintf("%s: Query without parameterization near position %d", relPath, start)
					violations = append(violations, violation)
				}
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("found queries without parameterization:\n%s", strings.Join(violations, "\n"))
	}

	return nil
}

// noStringConcatenationInQueries checks for string concatenation in SQL queries
// Requirement: SEC-003 - No string building for SQL
func (sc *SecurityContext) noStringConcatenationInQueries() error {
	violations := []string{}

	for _, relPath := range sc.inspectedFiles {
		absPath := filepath.Join("..", "..", relPath)

		content, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", relPath, err)
		}

		source := string(content)

		// Dangerous patterns indicating string concatenation in queries
		dangerousPatterns := []struct {
			pattern string
			reason  string
		}{
			{`(SELECT|INSERT|UPDATE|DELETE).*\+.*["` + "`" + `]`, "String concatenation in SQL"},
			{`["` + "`" + `].*\+.*(SELECT|INSERT|UPDATE|DELETE)`, "String concatenation in SQL"},
		}

		for _, dp := range dangerousPatterns {
			re := regexp.MustCompile(`(?i)` + dp.pattern)
			if matches := re.FindAllString(source, -1); len(matches) > 0 {
				for _, match := range matches {
					violation := fmt.Sprintf("%s: %s - %s", relPath, dp.reason, match)
					violations = append(violations, violation)
				}
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("SECURITY VIOLATION - string concatenation in queries:\n%s",
			strings.Join(violations, "\n"))
	}

	return nil
}

// noFmtSprintfInQueries checks fmt.Sprintf is not used for query building
// Requirement: SEC-003 - No sprintf for queries
func (sc *SecurityContext) noFmtSprintfInQueries() error {
	violations := []string{}

	for _, relPath := range sc.inspectedFiles {
		absPath := filepath.Join("..", "..", relPath)

		content, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", relPath, err)
		}

		source := string(content)
		lines := strings.Split(source, "\n")

		for i, line := range lines {
			// Check for fmt.Sprintf used in SQL query building
			if strings.Contains(line, "fmt.Sprintf") {
				// Look at surrounding lines for SQL keywords
				contextStart := i - 2
				if contextStart < 0 {
					contextStart = 0
				}
				contextEnd := i + 3
				if contextEnd > len(lines) {
					contextEnd = len(lines)
				}

				context := strings.Join(lines[contextStart:contextEnd], " ")

				sqlKeywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"}
				for _, keyword := range sqlKeywords {
					if strings.Contains(strings.ToUpper(context), keyword) {
						violation := fmt.Sprintf("%s:%d - fmt.Sprintf used near SQL: %s",
							relPath, i+1, line)
						violations = append(violations, violation)
						break
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("SECURITY VIOLATION - fmt.Sprintf used for query building:\n%s",
			strings.Join(violations, "\n"))
	}

	return nil
}

// theRuleShouldBeInResults verifies a specific rule is in search results
func (sc *SecurityContext) theRuleShouldBeInResults(ruleName string) error {
	for _, result := range sc.searchResults {
		if name, ok := result["name"].(string); ok {
			if name == ruleName {
				return nil // Found
			}
		}
	}

	return fmt.Errorf("rule '%s' not found in search results", ruleName)
}

// theRuleNameShouldBeStoredExactly verifies rule name stored without modification
func (sc *SecurityContext) theRuleNameShouldBeStoredExactly() error {
	// Query for the rule we just created
	if len(sc.testRules) == 0 {
		return fmt.Errorf("no test rules created")
	}

	// Get last created rule
	var lastRule map[string]interface{}
	for _, rule := range sc.testRules {
		lastRule = rule
	}

	ruleName, ok := lastRule["name"].(string)
	if !ok {
		return fmt.Errorf("rule name not found")
	}

	// Search for it
	if err := sc.iSearchForRulesWithName(ruleName); err != nil {
		return err
	}

	// Verify it's in results with exact name
	return sc.theRuleShouldBeInResults(ruleName)
}

// theRulesTableShouldExist verifies rules table wasn't dropped by SQL injection
func (sc *SecurityContext) theRulesTableShouldExist() error {
	// Try to query rules to verify table exists
	rulesURL := fmt.Sprintf("%s/api/v1/rules?limit=1", sc.baseURL)

	req, err := http.NewRequest("GET", rulesURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sc.authToken))

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("query failed - table may have been dropped: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusInternalServerError {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("rules table may have been dropped: status 500 (failed to read body: %w)", readErr)
		}
		return fmt.Errorf("rules table may have been dropped: status 500, body: %s", string(body))
	}

	return nil
}

// authenticationShouldNotBeBypassed verifies auth is still required
func (sc *SecurityContext) authenticationShouldNotBeBypassed() error {
	// Try to access protected endpoint without auth
	rulesURL := fmt.Sprintf("%s/api/v1/rules", sc.baseURL)

	req, err := http.NewRequest("GET", rulesURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	// No Authorization header

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("authentication was bypassed - got 200 without auth token")
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("unexpected status code: expected 401, got %d", resp.StatusCode)
	}

	return nil
}

// ========================================
// Helper Functions
// ========================================

// containsSensitiveFields checks if result contains sensitive user data
func containsSensitiveFields(result map[string]interface{}) bool {
	sensitiveFields := []string{
		"password", "password_hash", "hash", "salt",
		"api_key", "secret", "token", "ssn",
		"credit_card", "email", // email might be PII
	}

	for _, field := range sensitiveFields {
		if _, exists := result[field]; exists {
			return true
		}
	}

	// Check nested fields
	for key, value := range result {
		if strings.Contains(strings.ToLower(key), "password") ||
			strings.Contains(strings.ToLower(key), "secret") {
			return true
		}

		// Recursively check nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			if containsSensitiveFields(nestedMap) {
				return true
			}
		}
	}

	return false
}
