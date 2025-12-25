// Package steps implements BDD step definitions for RBAC authorization testing
// Requirement: SEC-002 - Authorization
// Source: docs/requirements/security-threat-model.md
// Source: docs/requirements/user-management-authentication-requirements.md
package steps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// AuthorizationContext maintains state for RBAC authorization test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type AuthorizationContext struct {
	baseURL          string
	httpClient       *http.Client
	authTokens       map[string]string // username -> JWT token
	lastResponse     *http.Response
	lastStatusCode   int
	lastError        error
	lastResponseBody []byte
	currentUser      string
	roles            map[string]map[string]bool // role -> permissions map
	users            map[string]map[string]interface{}
	createdRules     map[string]string // rule_id -> rule data
	createdResources map[string]string // resource_id -> resource type
}

// InitializeAuthorizationContext registers all RBAC step definitions
// Requirement: SEC-002 - Complete RBAC test coverage
func InitializeAuthorizationContext(sc *godog.ScenarioContext) {
	ctx := &AuthorizationContext{
		baseURL: "http://localhost:8080",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		authTokens:       make(map[string]string),
		roles:            make(map[string]map[string]bool),
		users:            make(map[string]map[string]interface{}),
		createdRules:     make(map[string]string),
		createdResources: make(map[string]string),
	}

	// Background steps
	sc.Step(`^the following roles exist:$`, ctx.theFollowingRolesExist)
	sc.Step(`^the following users exist:$`, ctx.theFollowingUsersExist)

	// Authentication context steps
	sc.Step(`^I am logged in as "([^"]*)"$`, ctx.iAmLoggedInAs)
	sc.Step(`^my user ID is "([^"]*)"$`, ctx.myUserIDIs)

	// Authorization action steps
	sc.Step(`^I attempt to create a rule via POST "([^"]*)"$`, ctx.iAttemptToCreateARuleViaPOST)
	sc.Step(`^I attempt to delete the rule via DELETE "([^"]*)"$`, ctx.iAttemptToDeleteTheRuleViaDELETE)
	sc.Step(`^I attempt to read the rule via GET "([^"]*)"$`, ctx.iAttemptToReadTheRuleViaGET)
	sc.Step(`^I attempt to create a user via POST "([^"]*)"$`, ctx.iAttemptToCreateAUserViaPOST)
	sc.Step(`^I attempt to update my role to "([^"]*)" via PUT "([^"]*)"$`, ctx.iAttemptToUpdateMyRoleTo)
	sc.Step(`^I attempt to access "([^"]*)" without authentication$`, ctx.iAttemptToAccessWithoutAuthentication)
	sc.Step(`^I attempt to read analyst2's API key via GET "([^"]*)"$`, ctx.iAttemptToReadAnalyst2APIKey)

	// Resource setup steps
	sc.Step(`^a rule exists with id "([^"]*)"$`, ctx.aRuleExistsWithID)
	sc.Step(`^a user "([^"]*)" exists with private API key$`, ctx.aUserExistsWithPrivateAPIKey)

	// Assertion steps
	sc.Step(`^the request should succeed$`, ctx.theRequestShouldSucceed)
	sc.Step(`^the request should fail$`, ctx.theRequestShouldFail)
	sc.Step(`^I should receive a "([^"]*)" response$`, ctx.iShouldReceiveAResponse)
	sc.Step(`^the rule should be created in the database$`, ctx.theRuleShouldBeCreatedInTheDatabase)
	sc.Step(`^the rule should be deleted from the database$`, ctx.theRuleShouldBeDeletedFromTheDatabase)
	sc.Step(`^the rule should still exist in the database$`, ctx.theRuleShouldStillExistInTheDatabase)
	sc.Step(`^the rule details should be returned$`, ctx.theRuleDetailsShouldBeReturned)
	sc.Step(`^the error message should indicate insufficient permissions$`, ctx.theErrorMessageShouldIndicateInsufficientPermissions)
	sc.Step(`^my role should remain "([^"]*)"$`, ctx.myRoleShouldRemain)

	// Cleanup
}

// theFollowingRolesExist parses role definitions from table
// Requirement: SEC-002 - Role-Based Access Control
// Per AFFIRMATIONS.md Line 168: Check ALL errors
func (ac *AuthorizationContext) theFollowingRolesExist(table *godog.Table) error {
	// Per AFFIRMATIONS.md Line 42: Check nil before access
	if table == nil {
		return fmt.Errorf("table cannot be nil")
	}

	if len(table.Rows) < 2 {
		return fmt.Errorf("table must have at least header and one data row")
	}

	// Validate headers
	headers := table.Rows[0].Cells
	if len(headers) < 2 {
		return fmt.Errorf("table must have at least 2 columns")
	}

	if headers[0].Value != "role" || headers[1].Value != "permissions" {
		return fmt.Errorf("expected headers 'role' and 'permissions', got '%s' and '%s'",
			headers[0].Value, headers[1].Value)
	}

	// Parse each role
	for i := 1; i < len(table.Rows); i++ {
		cells := table.Rows[i].Cells
		if len(cells) < 2 {
			return fmt.Errorf("row %d has insufficient columns", i)
		}

		roleName := cells[0].Value
		permissionsStr := cells[1].Value

		// Split permissions by comma
		permissionsSlice := strings.Split(permissionsStr, ", ")

		// Create permissions map
		permissionsMap := make(map[string]bool)
		for _, perm := range permissionsSlice {
			trimmed := strings.TrimSpace(perm)
			if trimmed != "" {
				permissionsMap[trimmed] = true
			}
		}

		// Store in context
		ac.roles[roleName] = permissionsMap
	}

	return nil
}

// theFollowingUsersExist creates test users via API
// Requirement: SEC-002 - User account creation for testing
func (ac *AuthorizationContext) theFollowingUsersExist(table *godog.Table) error {
	if table == nil {
		return fmt.Errorf("table cannot be nil")
	}

	if len(table.Rows) < 2 {
		return fmt.Errorf("table must have at least header and one data row")
	}

	// Validate headers
	headers := table.Rows[0].Cells
	if len(headers) < 3 {
		return fmt.Errorf("table must have at least 3 columns")
	}

	// Parse each user
	for i := 1; i < len(table.Rows); i++ {
		cells := table.Rows[i].Cells
		if len(cells) < 3 {
			return fmt.Errorf("row %d has insufficient columns", i)
		}

		username := cells[0].Value
		role := cells[1].Value
		password := cells[2].Value

		// Create user via API
		createErr := ac.createUserAccount(username, password, role)
		if createErr != nil {
			return fmt.Errorf("failed to create user %s: %w", username, createErr)
		}

		// Store user data
		if ac.users[username] == nil {
			ac.users[username] = make(map[string]interface{})
		}
		ac.users[username]["username"] = username
		ac.users[username]["role"] = role
		ac.users[username]["password"] = password
	}

	return nil
}

// createUserAccount performs HTTP POST to create user
// Requirement: SEC-002 - User creation API
func (ac *AuthorizationContext) createUserAccount(username, password, role string) error {
	url := fmt.Sprintf("%s/api/v1/users", ac.baseURL)

	// Create user data
	userData := map[string]interface{}{
		"username": username,
		"password": password,
		"role":     role,
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(userData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal user data: %w", marshalErr)
	}

	// Create request
	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to execute request: %w", doErr)
	}

	// Defer close with error check
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	// Check status
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("user creation failed with status %d and could not read body: %w",
				resp.StatusCode, readErr)
		}
		return fmt.Errorf("user creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// iAmLoggedInAs authenticates and stores JWT token
// Requirement: SEC-002 - Authentication
func (ac *AuthorizationContext) iAmLoggedInAs(username string) error {
	ac.currentUser = username

	// Get user data
	userData, exists := ac.users[username]
	if !exists {
		return fmt.Errorf("user %s does not exist in test context", username)
	}

	// Extract password
	passwordInterface, hasPassword := userData["password"]
	if !hasPassword {
		return fmt.Errorf("user %s has no password set", username)
	}

	password, ok := passwordInterface.(string)
	if !ok {
		return fmt.Errorf("user %s password is not a string", username)
	}

	// Build login URL
	loginURL := fmt.Sprintf("%s/api/v1/auth/login", ac.baseURL)

	// Create login data
	loginData := map[string]string{
		"username": username,
		"password": password,
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(loginData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal login data: %w", marshalErr)
	}

	// Create POST request
	req, reqErr := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create login request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to execute login request: %w", doErr)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			fmt.Printf("Warning: failed to close login response body: %v\n", closeErr)
		}
	}()

	// Check status
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("login failed with status %d and could not read body: %w",
				resp.StatusCode, readErr)
		}
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read login response: %w", readErr)
	}

	// Unmarshal token
	var loginResponse struct {
		Token string `json:"token"`
	}
	unmarshalErr := json.Unmarshal(body, &loginResponse)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse login response: %w", unmarshalErr)
	}

	if loginResponse.Token == "" {
		return fmt.Errorf("login response did not contain a token")
	}

	// Store token
	ac.authTokens[username] = loginResponse.Token

	return nil
}

// myUserIDIs sets user ID for privilege escalation tests
// Requirement: SEC-002 - User ID tracking
func (ac *AuthorizationContext) myUserIDIs(userID string) error {
	if ac.currentUser == "" {
		return fmt.Errorf("no user is currently logged in")
	}

	// Initialize user map if needed
	if ac.users[ac.currentUser] == nil {
		ac.users[ac.currentUser] = make(map[string]interface{})
	}

	// Set user ID
	ac.users[ac.currentUser]["id"] = userID

	return nil
}

// iAttemptToCreateARuleViaPOST tests write_rules permission
// Requirement: SEC-002 - Authorization testing
func (ac *AuthorizationContext) iAttemptToCreateARuleViaPOST(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create rule data
	ruleData := map[string]interface{}{
		"name":        "test-rule",
		"description": "Test rule for authorization",
		"pattern":     ".*test.*",
		"severity":    "high",
		"enabled":     true,
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(ruleData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal rule data: %w", marshalErr)
	}

	// Create request
	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil // Don't return error - test will check lastError
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToDeleteTheRuleViaDELETE tests delete_rules permission
// Requirement: SEC-002 - Authorization testing
func (ac *AuthorizationContext) iAttemptToDeleteTheRuleViaDELETE(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create request
	req, reqErr := http.NewRequest("DELETE", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToReadTheRuleViaGET tests read_rules permission
// Requirement: SEC-002 - Authorization testing
func (ac *AuthorizationContext) iAttemptToReadTheRuleViaGET(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create request
	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToCreateAUserViaPOST tests manage_users permission
// Requirement: SEC-002 - Authorization testing
func (ac *AuthorizationContext) iAttemptToCreateAUserViaPOST(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create user data
	userData := map[string]interface{}{
		"username": "newuser",
		"password": "NewUserPass123!",
		"role":     "viewer",
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(userData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal user data: %w", marshalErr)
	}

	// Create request
	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToUpdateMyRoleTo tests privilege escalation prevention
// Requirement: SEC-002 - Privilege escalation prevention
func (ac *AuthorizationContext) iAttemptToUpdateMyRoleTo(newRole, endpoint string) error {
	url := ac.baseURL + endpoint

	// Create update data
	updateData := map[string]interface{}{
		"role": newRole,
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(updateData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal update data: %w", marshalErr)
	}

	// Create request
	req, reqErr := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToAccessWithoutAuthentication tests authentication requirement
// Requirement: SEC-002 - Authentication requirement
func (ac *AuthorizationContext) iAttemptToAccessWithoutAuthentication(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create request WITHOUT auth token
	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// iAttemptToReadAnalyst2APIKey tests horizontal access control
// Requirement: SEC-002 - Horizontal access control
func (ac *AuthorizationContext) iAttemptToReadAnalyst2APIKey(endpoint string) error {
	url := ac.baseURL + endpoint

	// Create request
	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	// Add auth token if user is logged in
	if ac.currentUser != "" {
		token, hasToken := ac.authTokens[ac.currentUser]
		if !hasToken {
			return fmt.Errorf("no auth token for user %s", ac.currentUser)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		ac.lastStatusCode = 0
		return nil
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = body

	// Close body
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return fmt.Errorf("failed to close response body: %w", closeErr)
	}

	return nil
}

// aRuleExistsWithID creates a pre-existing test rule
// Requirement: SEC-002 - Test data setup
func (ac *AuthorizationContext) aRuleExistsWithID(ruleID string) error {
	url := fmt.Sprintf("%s/api/v1/rules", ac.baseURL)

	// Create rule data
	ruleData := map[string]interface{}{
		"id":          ruleID,
		"name":        "test-rule-" + ruleID,
		"description": "Test rule for authorization tests",
		"pattern":     ".*test.*",
		"severity":    "medium",
		"enabled":     true,
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(ruleData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal rule data: %w", marshalErr)
	}

	// Create request
	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add admin token if available
	if adminToken, hasAdmin := ac.authTokens["admin1"]; hasAdmin {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminToken))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to execute request: %w", doErr)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	// Check status
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("rule creation failed with status %d and could not read body: %w",
				resp.StatusCode, readErr)
		}
		return fmt.Errorf("rule creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Store rule ID
	ac.createdRules[ruleID] = "created"

	return nil
}

// aUserExistsWithPrivateAPIKey creates user with private data
// Requirement: SEC-002 - Horizontal access control test setup
func (ac *AuthorizationContext) aUserExistsWithPrivateAPIKey(username string) error {
	password := "Analyst2Pass123!"
	role := "analyst"

	// Create user account
	createErr := ac.createUserAccount(username, password, role)
	if createErr != nil {
		return fmt.Errorf("failed to create user: %w", createErr)
	}

	// Store user data with API key
	if ac.users[username] == nil {
		ac.users[username] = make(map[string]interface{})
	}
	ac.users[username]["username"] = username
	ac.users[username]["role"] = role
	ac.users[username]["password"] = password
	ac.users[username]["api_key"] = "secret-api-key-" + username

	return nil
}

// theRequestShouldSucceed asserts last request succeeded
// Requirement: SEC-002 - Test assertions
func (ac *AuthorizationContext) theRequestShouldSucceed() error {
	if ac.lastError != nil {
		return fmt.Errorf("request failed with error: %w", ac.lastError)
	}

	if ac.lastStatusCode >= 400 {
		return fmt.Errorf("request failed with status %d: %s",
			ac.lastStatusCode, string(ac.lastResponseBody))
	}

	return nil
}

// theRequestShouldFail asserts last request failed
// Requirement: SEC-002 - Test assertions
func (ac *AuthorizationContext) theRequestShouldFail() error {
	if ac.lastError == nil && ac.lastStatusCode < 400 {
		return fmt.Errorf("expected request to fail but got status %d", ac.lastStatusCode)
	}

	return nil
}

// iShouldReceiveAResponse asserts specific HTTP status
// Requirement: SEC-002 - Status code validation
func (ac *AuthorizationContext) iShouldReceiveAResponse(expectedStatus string) error {
	// Status code mapping
	statusCodeMap := map[string]int{
		"200 OK":           200,
		"201 Created":      201,
		"204 No Content":   204,
		"400 Bad Request":  400,
		"401 Unauthorized": 401,
		"403 Forbidden":    403,
		"404 Not Found":    404,
	}

	expectedCode, exists := statusCodeMap[expectedStatus]
	if !exists {
		return fmt.Errorf("unknown status code: %s", expectedStatus)
	}

	if ac.lastStatusCode != expectedCode {
		return fmt.Errorf("expected status %s (%d) but got %d: %s",
			expectedStatus, expectedCode, ac.lastStatusCode, string(ac.lastResponseBody))
	}

	return nil
}

// theRuleShouldBeCreatedInTheDatabase verifies rule creation
// Requirement: SEC-002 - Database verification
func (ac *AuthorizationContext) theRuleShouldBeCreatedInTheDatabase() error {
	if ac.lastStatusCode != 201 && ac.lastStatusCode != 200 {
		return fmt.Errorf("rule was not created, status: %d", ac.lastStatusCode)
	}

	// Parse response to get rule ID
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response: %w", unmarshalErr)
	}

	ruleID, hasID := response["id"]
	if !hasID {
		return fmt.Errorf("created rule response does not contain ID")
	}

	ruleIDStr, ok := ruleID.(string)
	if !ok {
		return fmt.Errorf("rule ID is not a string")
	}

	// Verify by querying
	verifyURL := fmt.Sprintf("%s/api/v1/rules/%s", ac.baseURL, ruleIDStr)
	req, reqErr := http.NewRequest("GET", verifyURL, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create verification request: %w", reqErr)
	}

	if ac.currentUser != "" {
		if token, hasToken := ac.authTokens[ac.currentUser]; hasToken {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to verify rule creation: %w", doErr)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			fmt.Printf("Warning: failed to close verification response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("rule does not exist in database, verify returned status %d", resp.StatusCode)
	}

	return nil
}

// theRuleShouldBeDeletedFromTheDatabase verifies rule deletion
// Requirement: SEC-002 - Database verification
func (ac *AuthorizationContext) theRuleShouldBeDeletedFromTheDatabase() error {
	if ac.lastStatusCode != 200 && ac.lastStatusCode != 204 {
		return fmt.Errorf("rule was not deleted, status: %d", ac.lastStatusCode)
	}

	return nil
}

// theRuleShouldStillExistInTheDatabase verifies rule persistence
// Requirement: SEC-002 - Authorization enforcement verification
func (ac *AuthorizationContext) theRuleShouldStillExistInTheDatabase() error {
	if ac.lastStatusCode == 200 || ac.lastStatusCode == 204 {
		return fmt.Errorf("rule was deleted when it should not have been, status: %d", ac.lastStatusCode)
	}

	return nil
}

// theRuleDetailsShouldBeReturned verifies rule read response
// Requirement: SEC-002 - Response validation
func (ac *AuthorizationContext) theRuleDetailsShouldBeReturned() error {
	if ac.lastStatusCode != 200 {
		return fmt.Errorf("expected status 200 but got %d", ac.lastStatusCode)
	}

	// Parse response
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response: %w", unmarshalErr)
	}

	// Verify required fields
	requiredFields := []string{"id", "name", "description", "pattern", "severity", "enabled"}
	for _, field := range requiredFields {
		if _, exists := response[field]; !exists {
			return fmt.Errorf("response missing required field '%s'", field)
		}
	}

	return nil
}

// theErrorMessageShouldIndicateInsufficientPermissions validates permission error
// Requirement: SEC-002 - Error message validation
func (ac *AuthorizationContext) theErrorMessageShouldIndicateInsufficientPermissions() error {
	if ac.lastStatusCode != 403 {
		return fmt.Errorf("expected status 403 Forbidden but got %d", ac.lastStatusCode)
	}

	bodyStr := strings.ToLower(string(ac.lastResponseBody))

	// Check for permission-related keywords
	permissionKeywords := []string{"permission", "forbidden", "not authorized", "insufficient"}
	hasKeyword := false
	for _, keyword := range permissionKeywords {
		if strings.Contains(bodyStr, keyword) {
			hasKeyword = true
			break
		}
	}

	if !hasKeyword {
		return fmt.Errorf("error message does not indicate insufficient permissions: %s",
			string(ac.lastResponseBody))
	}

	return nil
}

// myRoleShouldRemain verifies role unchanged after escalation attempt
// Requirement: SEC-002 - Privilege escalation prevention verification
func (ac *AuthorizationContext) myRoleShouldRemain(expectedRole string) error {
	if ac.currentUser == "" {
		return fmt.Errorf("no current user set")
	}

	// Get current user details from API
	url := fmt.Sprintf("%s/api/v1/users/%s", ac.baseURL, ac.currentUser)

	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	if token, hasToken := ac.authTokens[ac.currentUser]; hasToken {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to get user details: %w", doErr)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to retrieve user details, status: %d", resp.StatusCode)
	}

	// Read and parse response
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response: %w", readErr)
	}

	var userDetails map[string]interface{}
	unmarshalErr := json.Unmarshal(body, &userDetails)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse user details: %w", unmarshalErr)
	}

	// Verify role
	role, hasRole := userDetails["role"]
	if !hasRole {
		return fmt.Errorf("user details do not contain role field")
	}

	roleStr, ok := role.(string)
	if !ok {
		return fmt.Errorf("role is not a string")
	}

	if roleStr != expectedRole {
		return fmt.Errorf("expected role '%s' but got '%s'", expectedRole, roleStr)
	}

	return nil
}
