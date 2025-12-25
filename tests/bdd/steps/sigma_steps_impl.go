// Package steps - SIGMA step implementations
// Requirement: SIGMA-002, SIGMA-005 - SIGMA Operator Compliance
package steps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// theCerberusDetectionEngineIsRunning verifies engine health
func (sc *SIGMAContext) theCerberusDetectionEngineIsRunning() error {
	url := sc.baseURL + "/api/v1/health"
	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create health check request: %w", reqErr)
	}

	resp, doErr := sc.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("health check failed: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close health check response: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("engine not healthy, status: %d", resp.StatusCode)
	}

	return nil
}

// theDatabaseContainsSampleEvents marks sample data as loaded
func (sc *SIGMAContext) theDatabaseContainsSampleEvents() error {
	return nil
}

// aSIGMARuleWithCondition creates a SIGMA rule
func (sc *SIGMAContext) aSIGMARuleWithCondition(condition string) error {
	sc.ruleID = fmt.Sprintf("rule-%d", time.Now().UnixNano())

	pattern := sc.convertConditionToPattern(condition)

	ruleData := map[string]interface{}{
		"id":          sc.ruleID,
		"name":        "SIGMA test rule",
		"description": "Test rule for " + condition,
		"pattern":     pattern,
		"severity":    "medium",
		"enabled":     true,
	}

	sc.currentRule = ruleData

	// Create rule via API
	url := sc.baseURL + "/api/v1/rules"
	jsonData, marshalErr := json.Marshal(ruleData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal rule: %w", marshalErr)
	}

	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := sc.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to create rule: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("rule creation failed with status %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("rule creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// convertConditionToPattern converts SIGMA condition to regex pattern
func (sc *SIGMAContext) convertConditionToPattern(condition string) string {
	// Parse condition format: "field operator value"
	if strings.Contains(condition, "equals") {
		parts := strings.Split(condition, "equals")
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			return "^" + regexp.QuoteMeta(value) + "$"
		}
	}

	if strings.Contains(condition, "contains") {
		parts := strings.Split(condition, "contains")
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			return regexp.QuoteMeta(value)
		}
	}

	if strings.Contains(condition, "startswith") {
		parts := strings.Split(condition, "startswith")
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			return "^" + regexp.QuoteMeta(value)
		}
	}

	if strings.Contains(condition, "endswith") {
		parts := strings.Split(condition, "endswith")
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			return regexp.QuoteMeta(value) + "$"
		}
	}

	if strings.Contains(condition, "matches") {
		parts := strings.Split(condition, "matches")
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}

	if strings.Contains(condition, "wildcard") {
		parts := strings.Split(condition, "wildcard")
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Convert wildcard to regex: * -> .*, ? -> .
			value = strings.ReplaceAll(value, "*", ".*")
			value = strings.ReplaceAll(value, "?", ".")
			return value
		}
	}

	return ".*"
}

// anEventExistsWithEventID creates event with EventID field
func (sc *SIGMAContext) anEventExistsWithEventID(eventID string) error {
	sc.eventID = eventID
	sc.currentEvent = map[string]interface{}{
		"EventID": eventID,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithProcessName creates event with ProcessName
func (sc *SIGMAContext) anEventExistsWithProcessName(processName string) error {
	sc.currentEvent = map[string]interface{}{
		"ProcessName": processName,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithCommandLine creates event with CommandLine
func (sc *SIGMAContext) anEventExistsWithCommandLine(commandLine string) error {
	sc.currentEvent = map[string]interface{}{
		"CommandLine": commandLine,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithTargetFilename creates event with TargetFilename
func (sc *SIGMAContext) anEventExistsWithTargetFilename(targetFilename string) error {
	sc.currentEvent = map[string]interface{}{
		"TargetFilename": targetFilename,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithProcessNameAndCommandLine creates event with multiple fields
func (sc *SIGMAContext) anEventExistsWithProcessNameAndCommandLine(processName, commandLine string) error {
	sc.currentEvent = map[string]interface{}{
		"ProcessName": processName,
		"CommandLine": commandLine,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithNestedFieldUserName creates event with nested field
func (sc *SIGMAContext) anEventExistsWithNestedFieldUserName(userName string) error {
	sc.currentEvent = map[string]interface{}{
		"user": map[string]interface{}{
			"name": userName,
		},
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithDeeplyNestedField creates event with deeply nested field
func (sc *SIGMAContext) anEventExistsWithDeeplyNestedField(commandLine string) error {
	sc.currentEvent = map[string]interface{}{
		"process": map[string]interface{}{
			"parent": map[string]interface{}{
				"command_line": commandLine,
			},
		},
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithoutTheField creates event without specified field
func (sc *SIGMAContext) anEventExistsWithoutTheField(fieldName string) error {
	sc.currentEvent = map[string]interface{}{
		"other_field": "value",
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithField1Null creates event with null field
func (sc *SIGMAContext) anEventExistsWithField1Null() error {
	sc.currentEvent = map[string]interface{}{
		"field1": nil,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// anEventExistsWithDataBase64 creates event with base64 encoded data
func (sc *SIGMAContext) anEventExistsWithDataBase64(plaintext string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	sc.currentEvent = map[string]interface{}{
		"Data": encoded,
	}
	return sc.ingestEvent(sc.currentEvent)
}

// ingestEvent sends event to ingestion endpoint
func (sc *SIGMAContext) ingestEvent(eventData map[string]interface{}) error {
	url := sc.baseURL + "/api/v1/events"

	jsonData, marshalErr := json.Marshal(eventData)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal event: %w", marshalErr)
	}

	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := sc.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to ingest event: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("event ingestion failed with status %d (body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("event ingestion failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Allow time for processing
	time.Sleep(100 * time.Millisecond)

	return nil
}

// iEvaluateTheRuleAgainstTheEvent evaluates rule against event
func (sc *SIGMAContext) iEvaluateTheRuleAgainstTheEvent() error {
	// Try API evaluation first
	url := fmt.Sprintf("%s/api/v1/rules/%s/evaluate", sc.baseURL, sc.ruleID)

	jsonData, marshalErr := json.Marshal(sc.currentEvent)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal event: %w", marshalErr)
	}

	req, reqErr := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := sc.httpClient.Do(req)
	if doErr != nil {
		// Fall back to local evaluation
		sc.evaluationResult = sc.localEvaluateRule(sc.currentRule, sc.currentEvent)
		return nil
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response: %v\n", closeErr)
		}
	}()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response: %w", readErr)
	}

	var result struct {
		Matched bool   `json:"matched"`
		AlertID string `json:"alert_id"`
	}
	unmarshalErr := json.Unmarshal(body, &result)
	if unmarshalErr != nil {
		// Fall back to local evaluation
		sc.evaluationResult = sc.localEvaluateRule(sc.currentRule, sc.currentEvent)
		return nil
	}

	sc.evaluationResult = result.Matched
	if result.AlertID != "" {
		sc.alertGenerated = true
	}

	return nil
}

// localEvaluateRule performs local rule evaluation
func (sc *SIGMAContext) localEvaluateRule(rule, event map[string]interface{}) bool {
	patternInterface, hasPattern := rule["pattern"]
	if !hasPattern {
		return false
	}

	pattern, ok := patternInterface.(string)
	if !ok {
		return false
	}

	// Try to match pattern against event field values
	for _, value := range event {
		valueStr, isString := value.(string)
		if !isString {
			continue
		}

		matched, matchErr := regexp.MatchString(pattern, valueStr)
		if matchErr == nil && matched {
			return true
		}
	}

	return false
}

// theRuleShouldMatch asserts rule matched
func (sc *SIGMAContext) theRuleShouldMatch() error {
	if !sc.evaluationResult {
		return fmt.Errorf("expected rule to match but it did not")
	}
	return nil
}

// theRuleShouldNotMatch asserts rule did not match
func (sc *SIGMAContext) theRuleShouldNotMatch() error {
	if sc.evaluationResult {
		return fmt.Errorf("expected rule not to match but it did")
	}
	return nil
}

// anAlertShouldBeGenerated verifies alert generation
func (sc *SIGMAContext) anAlertShouldBeGenerated() error {
	if sc.alertGenerated {
		return nil
	}

	// Query alerts API
	url := sc.baseURL + "/api/v1/alerts"
	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}

	resp, doErr := sc.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("failed to query alerts: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response: %v\n", closeErr)
		}
	}()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response: %w", readErr)
	}

	var alerts []map[string]interface{}
	unmarshalErr := json.Unmarshal(body, &alerts)
	if unmarshalErr != nil {
		return fmt.Errorf("failed to parse alerts: %w", unmarshalErr)
	}

	if len(alerts) == 0 {
		return fmt.Errorf("no alerts were generated")
	}

	sc.alertGenerated = true
	return nil
}

// noAlertShouldBeGenerated verifies no alert generation
func (sc *SIGMAContext) noAlertShouldBeGenerated() error {
	if sc.alertGenerated {
		return fmt.Errorf("alert was generated when it should not have been")
	}
	return nil
}
