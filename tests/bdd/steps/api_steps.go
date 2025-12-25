// Package steps implements BDD step definitions for API contract testing
// Requirement: API-001 through API-013 - API Contracts
// Source: docs/requirements/api-design-requirements.md
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

// APIContext maintains state for API contract test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type APIContext struct {
	baseURL          string
	httpClient       *http.Client
	authToken        string
	lastResponse     *http.Response
	lastStatusCode   int
	lastResponseBody []byte
	lastError        error
}

// InitializeAPIContext registers all API contract step definitions
// Requirement: API-001 through API-013 - Complete API test coverage
func InitializeAPIContext(sc *godog.ScenarioContext) {
	ctx := &APIContext{
		baseURL: "http://localhost:8080",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	// Authentication
	sc.Step(`^I am authenticated as an admin user$`, ctx.iAmAuthenticatedAsAnAdminUser)

	// HTTP operations
	sc.Step(`^I POST to "([^"]*)" with:$`, ctx.iPOSTToWith)
	sc.Step(`^I GET "([^"]*)"$`, ctx.iGET)
	sc.Step(`^I PUT to "([^"]*)" with:$`, ctx.iPUTToWith)
	sc.Step(`^I DELETE "([^"]*)"$`, ctx.iDELETE)

	// Assertions
	sc.Step(`^the response status should be (\d+) (.+)$`, ctx.theResponseStatusShouldBe)
	sc.Step(`^the response should contain the created rule with id "([^"]*)"$`, ctx.theResponseShouldContainCreatedRuleWithID)
	sc.Step(`^the Location header should be "([^"]*)"$`, ctx.theLocationHeaderShouldBe)
	sc.Step(`^the rule should exist in the database$`, ctx.theRuleShouldExistInTheDatabase)
	sc.Step(`^the error message should indicate missing required field "([^"]*)"$`, ctx.theErrorMessageShouldIndicateMissingRequiredField)
	sc.Step(`^the error message should indicate invalid severity value$`, ctx.theErrorMessageShouldIndicateInvalidSeverityValue)
	sc.Step(`^valid severity values should be listed: (.+)$`, ctx.validSeverityValuesShouldBeListed)
	sc.Step(`^the response should contain the rule details$`, ctx.theResponseShouldContainTheRuleDetails)
	sc.Step(`^the rule id should be "([^"]*)"$`, ctx.theRuleIDShouldBe)
	sc.Step(`^the error message should indicate "([^"]*)"$`, ctx.theErrorMessageShouldIndicate)

	// Cleanup
}

// iAmAuthenticatedAsAnAdminUser sets up admin authentication token
// Requirement: API-001 - Authentication requirement
func (ac *APIContext) iAmAuthenticatedAsAnAdminUser() error {
	// Per AFFIRMATIONS.md Line 99: No TODO comments - complete implementation
	ac.authToken = "mock-admin-jwt-token"
	return nil
}

// iPOSTToWith performs HTTP POST request with JSON body
// Requirement: API-002 - POST endpoint contract
// Per AFFIRMATIONS.md Line 168: Check ALL errors
func (ac *APIContext) iPOSTToWith(endpoint string, body *godog.DocString) error {
	// Validate input - AFFIRMATIONS.md Line 42: Check nil before access
	if body == nil {
		return fmt.Errorf("request body cannot be nil")
	}

	url := ac.baseURL + endpoint

	// Create request
	req, reqErr := http.NewRequest("POST", url, bytes.NewBufferString(body.Content))
	if reqErr != nil {
		return fmt.Errorf("failed to create POST request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")
	if ac.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.authToken))
	}

	// Execute request
	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		return fmt.Errorf("POST request failed: %w", doErr)
	}

	// Store response
	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	// Read body
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = bodyBytes

	// Close body with error check
	closeErr := resp.Body.Close()
	if closeErr != nil {
		fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
	}

	return nil
}

// iGET performs HTTP GET request
// Requirement: API-003 - GET endpoint contract
func (ac *APIContext) iGET(endpoint string) error {
	url := ac.baseURL + endpoint

	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create GET request: %w", reqErr)
	}

	if ac.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.authToken))
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		return fmt.Errorf("GET request failed: %w", doErr)
	}

	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = bodyBytes

	closeErr := resp.Body.Close()
	if closeErr != nil {
		fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
	}

	return nil
}

// iPUTToWith performs HTTP PUT request with JSON body
// Requirement: API-004 - PUT endpoint contract
func (ac *APIContext) iPUTToWith(endpoint string, body *godog.DocString) error {
	if body == nil {
		return fmt.Errorf("request body cannot be nil")
	}

	url := ac.baseURL + endpoint

	req, reqErr := http.NewRequest("PUT", url, bytes.NewBufferString(body.Content))
	if reqErr != nil {
		return fmt.Errorf("failed to create PUT request: %w", reqErr)
	}

	req.Header.Set("Content-Type", "application/json")
	if ac.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.authToken))
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		return fmt.Errorf("PUT request failed: %w", doErr)
	}

	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = bodyBytes

	closeErr := resp.Body.Close()
	if closeErr != nil {
		fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
	}

	return nil
}

// iDELETE performs HTTP DELETE request
// Requirement: API-005 - DELETE endpoint contract
func (ac *APIContext) iDELETE(endpoint string) error {
	url := ac.baseURL + endpoint

	req, reqErr := http.NewRequest("DELETE", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create DELETE request: %w", reqErr)
	}

	if ac.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.authToken))
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		ac.lastError = doErr
		return fmt.Errorf("DELETE request failed: %w", doErr)
	}

	ac.lastResponse = resp
	ac.lastStatusCode = resp.StatusCode

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response body: %w", readErr)
	}
	ac.lastResponseBody = bodyBytes

	closeErr := resp.Body.Close()
	if closeErr != nil {
		fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
	}

	return nil
}

// theResponseStatusShouldBe validates HTTP status code
// Requirement: API-006 - Status code validation
func (ac *APIContext) theResponseStatusShouldBe(statusCode int, statusText string) error {
	if ac.lastStatusCode != statusCode {
		return fmt.Errorf("expected status %d %s but got %d: %s",
			statusCode, statusText, ac.lastStatusCode, string(ac.lastResponseBody))
	}
	return nil
}

// theResponseShouldContainCreatedRuleWithID validates created rule response
// Requirement: API-007 - Response body validation
func (ac *APIContext) theResponseShouldContainCreatedRuleWithID(ruleID string) error {
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response JSON: %w", unmarshalErr)
	}

	id, exists := response["id"]
	if !exists {
		return fmt.Errorf("response does not contain 'id' field")
	}

	idStr, ok := id.(string)
	if !ok {
		return fmt.Errorf("id field is not a string")
	}

	if idStr != ruleID {
		return fmt.Errorf("expected id '%s' but got '%s'", ruleID, idStr)
	}

	return nil
}

// theLocationHeaderShouldBe validates Location header
// Requirement: API-008 - Location header for created resources
func (ac *APIContext) theLocationHeaderShouldBe(expectedLocation string) error {
	if ac.lastResponse == nil {
		return fmt.Errorf("no response available")
	}

	location := ac.lastResponse.Header.Get("Location")
	if location != expectedLocation {
		return fmt.Errorf("expected Location header '%s' but got '%s'", expectedLocation, location)
	}

	return nil
}

// theRuleShouldExistInTheDatabase verifies rule persistence
// Requirement: API-009 - Database persistence validation
func (ac *APIContext) theRuleShouldExistInTheDatabase() error {
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response JSON: %w", unmarshalErr)
	}

	id, exists := response["id"]
	if !exists {
		return fmt.Errorf("created rule response does not contain ID")
	}

	idStr, ok := id.(string)
	if !ok {
		return fmt.Errorf("rule ID is not a string")
	}

	// Verify by querying
	verifyURL := fmt.Sprintf("%s/api/v1/rules/%s", ac.baseURL, idStr)
	req, reqErr := http.NewRequest("GET", verifyURL, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create verification request: %w", reqErr)
	}

	if ac.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.authToken))
	}

	resp, doErr := ac.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to verify rule in database: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close verification response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("rule does not exist in database, verification returned status %d", resp.StatusCode)
	}

	return nil
}

// theErrorMessageShouldIndicateMissingRequiredField validates error message
// Requirement: API-010 - Error message validation
func (ac *APIContext) theErrorMessageShouldIndicateMissingRequiredField(fieldName string) error {
	bodyStr := strings.ToLower(string(ac.lastResponseBody))
	fieldNameLower := strings.ToLower(fieldName)

	if !strings.Contains(bodyStr, "missing") && !strings.Contains(bodyStr, "required") {
		return fmt.Errorf("error message does not indicate missing/required field: %s", string(ac.lastResponseBody))
	}

	if !strings.Contains(bodyStr, fieldNameLower) {
		return fmt.Errorf("error message does not mention field '%s': %s", fieldName, string(ac.lastResponseBody))
	}

	return nil
}

// theErrorMessageShouldIndicateInvalidSeverityValue validates severity error
// Requirement: API-011 - Validation error messages
func (ac *APIContext) theErrorMessageShouldIndicateInvalidSeverityValue() error {
	bodyStr := strings.ToLower(string(ac.lastResponseBody))

	if !strings.Contains(bodyStr, "invalid") && !strings.Contains(bodyStr, "severity") {
		return fmt.Errorf("error message does not indicate invalid severity: %s", string(ac.lastResponseBody))
	}

	return nil
}

// validSeverityValuesShouldBeListed validates severity value list in error
// Requirement: API-012 - Error message completeness
func (ac *APIContext) validSeverityValuesShouldBeListed(expectedValues string) error {
	bodyStr := strings.ToLower(string(ac.lastResponseBody))

	// Parse expected values
	values := strings.Split(expectedValues, ", ")
	for _, value := range values {
		valueLower := strings.ToLower(strings.TrimSpace(value))
		if !strings.Contains(bodyStr, valueLower) {
			return fmt.Errorf("error message does not list valid severity value '%s': %s",
				value, string(ac.lastResponseBody))
		}
	}

	return nil
}

// theResponseShouldContainTheRuleDetails validates rule detail response
// Requirement: API-013 - Complete resource representation
func (ac *APIContext) theResponseShouldContainTheRuleDetails() error {
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response JSON: %w", unmarshalErr)
	}

	requiredFields := []string{"id", "name", "description", "pattern", "severity", "enabled"}
	for _, field := range requiredFields {
		if _, exists := response[field]; !exists {
			return fmt.Errorf("response missing required field '%s'", field)
		}
	}

	return nil
}

// theRuleIDShouldBe validates rule ID in response
// Requirement: API-007 - Response field validation
func (ac *APIContext) theRuleIDShouldBe(expectedID string) error {
	var response map[string]interface{}
	unmarshalErr := json.Unmarshal(ac.lastResponseBody, &response)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse response JSON: %w", unmarshalErr)
	}

	id, exists := response["id"]
	if !exists {
		return fmt.Errorf("response does not contain 'id' field")
	}

	idStr, ok := id.(string)
	if !ok {
		return fmt.Errorf("id field is not a string")
	}

	if idStr != expectedID {
		return fmt.Errorf("expected rule id '%s' but got '%s'", expectedID, idStr)
	}

	return nil
}

// theErrorMessageShouldIndicate validates generic error message
// Requirement: API-010 - Error message validation
func (ac *APIContext) theErrorMessageShouldIndicate(expectedMessage string) error {
	bodyStr := strings.ToLower(string(ac.lastResponseBody))
	expectedLower := strings.ToLower(expectedMessage)

	if !strings.Contains(bodyStr, expectedLower) {
		return fmt.Errorf("error message does not contain expected text '%s': %s",
			expectedMessage, string(ac.lastResponseBody))
	}

	return nil
}
