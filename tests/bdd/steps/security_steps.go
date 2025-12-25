// Package steps provides BDD step definitions for Cerberus security testing
package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

const (
	// API base URL for tests
	defaultAPIBaseURL = "http://localhost:8081"

	// Test user credentials
	testAdminUsername = "admin"
	testAdminPassword = "Admin123!Test" // Meets complexity requirements

	// Timeout constants
	healthCheckTimeout   = 10 * time.Second
	requestTimeout       = 5 * time.Second
	slowQueryMaxDuration = 1 * time.Second

	// Limits
	maxResponseBodySize = 10 * 1024 * 1024 // 10 MB
)

// SecurityContext holds state for security test scenarios
// This struct is passed between all Given/When/Then steps to maintain isolation
type SecurityContext struct {
	// API connection
	baseURL    string
	httpClient *http.Client

	// Authentication
	authToken  string
	username   string
	userID     string

	// Request/Response state
	lastRequest       *http.Request
	lastResponse      *http.Response
	lastResponseBody  []byte
	lastError         error

	// Search state
	searchQuery       string
	searchResults     []map[string]interface{}
	queryStartTime    time.Time
	queryDuration     time.Duration

	// Test data
	testRules         map[string]map[string]interface{} // rule ID -> rule data
	testUsers         map[string]map[string]interface{} // username -> user data
	failedLoginCounts map[string]int                    // username -> failed count

	// Code inspection state
	inspectedFiles []string
	violations     []string
}

// NewSecurityContext creates a new security test context with initialized state
func NewSecurityContext() *SecurityContext {
	return &SecurityContext{
		baseURL: defaultAPIBaseURL,
		httpClient: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects in tests
				return http.ErrUseLastResponse
			},
		},
		testRules:         make(map[string]map[string]interface{}),
		testUsers:         make(map[string]map[string]interface{}),
		failedLoginCounts: make(map[string]int),
		inspectedFiles:    []string{},
		violations:        []string{},
	}
}

// RegisterSecuritySteps registers all security-related step definitions
// This is called by the scenario initializer to wire up Gherkin steps to Go functions
func RegisterSecuritySteps(ctx *godog.ScenarioContext, sc *SecurityContext) {
	// Background steps
	ctx.Step(`^the Cerberus API is running$`, sc.theCerberusAPIIsRunning)
	ctx.Step(`^the database is initialized$`, sc.theDatabaseIsInitialized)
	ctx.Step(`^I am authenticated as an admin user$`, sc.iAmAuthenticatedAsAdminUser)

	// Given steps - SQL Injection
	ctx.Step(`^a rule exists with id "([^"]*)"$`, sc.aRuleExistsWithID)
	ctx.Step(`^a rule exists with name "([^"]*)"$`, sc.aRuleExistsWithName)

	// When steps - SQL Injection
	ctx.Step(`^I search for rules with query "([^"]*)"$`, sc.iSearchForRulesWithQuery)
	ctx.Step(`^I search for rules with name "([^"]*)"$`, sc.iSearchForRulesWithName)
	ctx.Step(`^I inspect the storage layer source code$`, sc.iInspectStorageSourceCode)
	ctx.Step(`^I create a rule with name "([^"]*)"$`, sc.iCreateRuleWithName)

	// Then steps - SQL Injection
	ctx.Step(`^the search should succeed$`, sc.theSearchShouldSucceed)
	ctx.Step(`^the search should complete in under (\d+) second$`, sc.theSearchShouldCompleteInUnder)
	ctx.Step(`^no user data should be in the results$`, sc.noUserDataInResults)
	ctx.Step(`^only valid rule data should be returned$`, sc.onlyValidRuleDataReturned)
	ctx.Step(`^no database error should be exposed in the response$`, sc.noDatabaseErrorExposed)
	ctx.Step(`^the attack should not execute$`, sc.theAttackShouldNotExecute)
	ctx.Step(`^all SQL queries should use parameterized statements$`, sc.allQueriesUseParameterizedStatements)
	ctx.Step(`^no string concatenation should be used in queries$`, sc.noStringConcatenationInQueries)
	ctx.Step(`^no fmt\.Sprintf should be used for query building$`, sc.noFmtSprintfInQueries)
	ctx.Step(`^the rule "([^"]*)" should be in the results$`, sc.theRuleShouldBeInResults)
	ctx.Step(`^the rule name should be stored exactly as provided$`, sc.theRuleNameShouldBeStoredExactly)
	ctx.Step(`^the rules table should still exist$`, sc.theRulesTableShouldExist)
	ctx.Step(`^authentication should not be bypassed$`, sc.authenticationShouldNotBeBypassed)

	// Given steps - Authentication
	ctx.Step(`^a user exists with username "([^"]*)" and password "([^"]*)"$`, sc.aUserExistsWithCredentials)
	ctx.Step(`^the user has (\d+) failed login attempts$`, sc.theUserHasFailedLoginAttempts)
	ctx.Step(`^I am logged in as user "([^"]*)"$`, sc.iAmLoggedInAsUser)
	ctx.Step(`^I have an expired JWT token$`, sc.iHaveExpiredJWTToken)

	// When steps - Authentication
	ctx.Step(`^I attempt to login with username "([^"]*)" and password "([^"]*)"$`, sc.iAttemptLoginWithCredentials)
	ctx.Step(`^I attempt to login (\d+) times with username "([^"]*)" and incorrect passwords$`, sc.iAttemptLoginMultipleTimes)
	ctx.Step(`^I attempt to login again with username "([^"]*)" and password "([^"]*)"$`, sc.iAttemptLoginWithCredentials) // Same implementation
	ctx.Step(`^I access a protected endpoint "([^"]*)" with my JWT token$`, sc.iAccessProtectedEndpoint)
	ctx.Step(`^I access a protected endpoint "([^"]*)" with an invalid JWT token$`, sc.iAccessProtectedEndpointWithInvalidToken)
	ctx.Step(`^I access a protected endpoint "([^"]*)" with the expired token$`, sc.iAccessProtectedEndpoint) // Same implementation
	ctx.Step(`^I modify the JWT token payload to claim admin role$`, sc.iModifyJWTTokenPayload)
	ctx.Step(`^I access a protected endpoint "([^"]*)" with the tampered token$`, sc.iAccessProtectedEndpoint) // Same implementation
	ctx.Step(`^I logout$`, sc.iLogout)
	ctx.Step(`^I attempt to use the same JWT token to access "([^"]*)"$`, sc.iAccessProtectedEndpoint) // Same implementation
	ctx.Step(`^I attempt to create a user with password "([^"]*)"$`, sc.iAttemptCreateUserWithPassword)
	ctx.Step(`^I measure login time for (\d+) attempts with invalid users$`, sc.iMeasureLoginTimeInvalidUsers)
	ctx.Step(`^I measure login time for (\d+) attempts with valid users but wrong passwords$`, sc.iMeasureLoginTimeValidUsersWrongPasswords)

	// Then steps - Authentication
	ctx.Step(`^the login should succeed$`, sc.theLoginShouldSucceed)
	ctx.Step(`^the login should fail$`, sc.theLoginShouldFail)
	ctx.Step(`^I should receive a valid JWT token$`, sc.iShouldReceiveValidJWTToken)
	ctx.Step(`^the JWT token should contain the user ID$`, sc.theJWTTokenShouldContainUserID)
	ctx.Step(`^the JWT token should have an expiration time$`, sc.theJWTTokenShouldHaveExpiration)
	ctx.Step(`^I should receive a "([^"]*)" response$`, sc.iShouldReceiveResponse)
	ctx.Step(`^no JWT token should be returned$`, sc.noJWTTokenShouldBeReturned)
	ctx.Step(`^the error message should not reveal that the username exists$`, sc.errorMessageShouldNotRevealUsername)
	ctx.Step(`^the error message should be identical to wrong password error$`, sc.errorMessageShouldBeIdentical)
	ctx.Step(`^all (\d+) login attempts should fail$`, sc.allLoginAttemptsShouldFail)
	ctx.Step(`^the login should fail with "([^"]*)" error$`, sc.theLoginShouldFailWithError)
	ctx.Step(`^the account should be locked for at least (\d+) minutes$`, sc.theAccountShouldBeLockedFor)
	ctx.Step(`^the failed login counter should be reset to (\d+)$`, sc.theFailedLoginCounterShouldBeReset)
	ctx.Step(`^the request should succeed$`, sc.theRequestShouldSucceed)
	ctx.Step(`^the request should fail$`, sc.theRequestShouldFail)
	ctx.Step(`^the error message should indicate the token has expired$`, sc.errorMessageShouldIndicateExpired)
	ctx.Step(`^the creation should (succeed|fail)$`, sc.theCreationShouldResult)
	ctx.Step(`^the error message should indicate "([^"]*)"$`, sc.errorMessageShouldIndicate)
	ctx.Step(`^the average time difference should be less than (\d+) milliseconds$`, sc.averageTimeDifferenceShouldBeLessThan)
}

// ========================================
// Background Steps
// ========================================

// theCerberusAPIIsRunning verifies the API is accessible via health check
// Requirement: Basic test setup - API must be running
func (sc *SecurityContext) theCerberusAPIIsRunning() error {
	healthURL := fmt.Sprintf("%s/health", sc.baseURL)

	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API not running or not accessible at %s: %w", sc.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("API unhealthy: status %d (failed to read body: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("API unhealthy: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// theDatabaseIsInitialized verifies database connectivity
// Requirement: Basic test setup - Database must be initialized
func (sc *SecurityContext) theDatabaseIsInitialized() error {
	// Attempt to query a basic endpoint that requires database access
	rulesURL := fmt.Sprintf("%s/api/v1/rules?limit=1", sc.baseURL)

	req, err := http.NewRequest("GET", rulesURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create database check request: %w", err)
	}

	// May not be authenticated yet, so 401 is acceptable
	// We're just checking database is accessible
	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("database not accessible: %w", err)
	}
	defer resp.Body.Close()

	// Accept 401 (not authenticated) or 200 (authenticated) as proof database is up
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status checking database: %d", resp.StatusCode)
	}

	return nil
}

// iAmAuthenticatedAsAdminUser logs in as admin and stores JWT token
// Requirement: SEC-001 - Authentication
func (sc *SecurityContext) iAmAuthenticatedAsAdminUser() error {
	return sc.loginAs(testAdminUsername, testAdminPassword)
}

// loginAs performs login and stores the JWT token
func (sc *SecurityContext) loginAs(username, password string) error {
	loginURL := fmt.Sprintf("%s/api/v1/auth/login", sc.baseURL)

	loginData := map[string]string{
		"username": username,
		"password": password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("failed to marshal login data: %w", err)
	}

	req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("login failed: status %d (failed to read body: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("login failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var loginResp struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("failed to decode login response: %w", err)
	}

	if loginResp.Token == "" {
		return fmt.Errorf("no token in login response")
	}

	sc.authToken = loginResp.Token
	sc.username = username
	sc.userID = loginResp.UserID

	return nil
}

// ========================================
// SQL Injection Prevention Steps
// ========================================

// aRuleExistsWithID creates a rule with the specified ID for testing
// Requirement: SEC-003 - SQL Injection Prevention (test data setup)
// TASK 176: Updated to use SIGMA YAML format instead of legacy Conditions
func (sc *SecurityContext) aRuleExistsWithID(ruleID string) error {
	ruleName := fmt.Sprintf("Test Rule %s", ruleID)

	// Generate SIGMA YAML that matches the original condition logic (EventID = 4625)
	sigmaYAML := fmt.Sprintf(`title: %s
id: %s
status: experimental
logsource:
  category: authentication
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium`, ruleName, ruleID)

	rule := map[string]interface{}{
		"id":          ruleID,
		"name":        ruleName,
		"description": "Test detection rule for BDD testing",
		"severity":    "medium",
		"enabled":     true,
		"type":        "sigma",
		"sigma_yaml":  sigmaYAML,
	}

	return sc.createRule(rule)
}

// aRuleExistsWithName creates a rule with the specified name
// Requirement: SEC-003 - SQL Injection Prevention (test data setup)
func (sc *SecurityContext) aRuleExistsWithName(ruleName string) error {
	ruleID := strings.ReplaceAll(strings.ToLower(ruleName), " ", "-")

	rule := map[string]interface{}{
		"id":          ruleID,
		"name":        ruleName,
		"description": "Test rule for name-based search",
		"severity":    "Medium",
		"enabled":     true,
		"type":        "sigma",
	}

	return sc.createRule(rule)
}

// createRule helper function to create a rule via API
func (sc *SecurityContext) createRule(rule map[string]interface{}) error {
	createURL := fmt.Sprintf("%s/api/v1/rules", sc.baseURL)

	jsonData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	req, err := http.NewRequest("POST", createURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create rule request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sc.authToken))

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create rule request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("failed to create rule: status %d (failed to read body: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("failed to create rule: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Store rule data for later verification
	if ruleID, ok := rule["id"].(string); ok {
		sc.testRules[ruleID] = rule
	}

	return nil
}

// iSearchForRulesWithQuery performs a search with the given query string
// Requirement: SEC-003 - SQL Injection Prevention (attack vector testing)
func (sc *SecurityContext) iSearchForRulesWithQuery(query string) error {
	sc.queryStartTime = time.Now()
	sc.searchQuery = query

	// URL-encode the query to test parameterization
	searchURL := fmt.Sprintf("%s/api/v1/rules/search?q=%s", sc.baseURL, query)

	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		sc.lastError = err
		return nil // Store error, don't fail step yet
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sc.authToken))

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		sc.lastError = err
		return nil
	}

	sc.lastResponse = resp
	sc.queryDuration = time.Since(sc.queryStartTime)

	// Read response body
	if resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		if err != nil {
			sc.lastError = err
			return nil
		}

		sc.lastResponseBody = bodyBytes

		// Try to parse as JSON
		var results []map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &results); err == nil {
			sc.searchResults = results
		}
	}

	return nil
}

// Continue in next part due to length...
