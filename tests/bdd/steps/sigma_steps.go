// Package steps implements BDD step definitions for SIGMA operator testing
// Requirement: SIGMA-002 - Operator Case Sensitivity
// Requirement: SIGMA-005 - Field Path Resolution
// Source: docs/requirements/sigma-compliance.md
package steps

import (
	"net/http"
	"time"

	"github.com/cucumber/godog"
)

// SIGMAContext maintains state for SIGMA operator test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type SIGMAContext struct {
	baseURL        string
	httpClient     *http.Client
	currentRule    map[string]interface{}
	currentEvent   map[string]interface{}
	evaluationResult bool
	alertGenerated bool
	lastError      error
	ruleID         string
	eventID        string
}

// InitializeSIGMAContext registers all SIGMA operator step definitions
// Requirement: SIGMA-002, SIGMA-005 - Complete SIGMA compliance test coverage
func InitializeSIGMAContext(sc *godog.ScenarioContext) {
	ctx := &SIGMAContext{
		baseURL: "http://localhost:8080",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		currentRule:  make(map[string]interface{}),
		currentEvent: make(map[string]interface{}),
	}

	// Background steps
	sc.Step(`^the Cerberus detection engine is running$`, ctx.theCerberusDetectionEngineIsRunning)
	sc.Step(`^the database contains sample events$`, ctx.theDatabaseContainsSampleEvents)

	// Rule definition steps
	sc.Step(`^a SIGMA rule with condition "([^"]*)"$`, ctx.aSIGMARuleWithCondition)

	// Event creation steps - simple
	sc.Step(`^an event exists with EventID "([^"]*)"$`, ctx.anEventExistsWithEventID)
	sc.Step(`^an event exists with ProcessName "([^"]*)"$`, ctx.anEventExistsWithProcessName)
	sc.Step(`^an event exists with CommandLine "([^"]*)"$`, ctx.anEventExistsWithCommandLine)
	sc.Step(`^an event exists with TargetFilename "([^"]*)"$`, ctx.anEventExistsWithTargetFilename)

	// Event creation steps - compound
	sc.Step(`^an event exists with ProcessName "([^"]*)" and CommandLine "([^"]*)"$`, ctx.anEventExistsWithProcessNameAndCommandLine)

	// Event creation steps - nested/special
	sc.Step(`^an event exists with nested field user\.name = "([^"]*)"$`, ctx.anEventExistsWithNestedFieldUserName)
	sc.Step(`^an event exists with deeply nested field process\.parent\.command_line = "([^"]*)"$`, ctx.anEventExistsWithDeeplyNestedField)
	sc.Step(`^an event exists without the field "([^"]*)"$`, ctx.anEventExistsWithoutTheField)
	sc.Step(`^an event exists with field1 = null$`, ctx.anEventExistsWithField1Null)
	sc.Step(`^an event exists with Data = base64\("([^"]*)"\)$`, ctx.anEventExistsWithDataBase64)

	// Evaluation steps
	sc.Step(`^I evaluate the rule against the event$`, ctx.iEvaluateTheRuleAgainstTheEvent)

	// Assertion steps
	sc.Step(`^the rule should match$`, ctx.theRuleShouldMatch)
	sc.Step(`^the rule should not match$`, ctx.theRuleShouldNotMatch)
	sc.Step(`^an alert should be generated$`, ctx.anAlertShouldBeGenerated)
	sc.Step(`^no alert should be generated$`, ctx.noAlertShouldBeGenerated)

	// Cleanup
}
