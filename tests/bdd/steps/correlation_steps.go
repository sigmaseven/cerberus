// Package steps implements BDD step definitions for correlation rule testing
// Requirement: FR-CORR-001 - Count-Based Correlation
// Requirement: FR-CORR-002 - Value Count Correlation
// Requirement: FR-CORR-003 - Sequence Correlation
// Source: docs/requirements/correlation-rule-requirements.md
package steps

import (
	"net/http"
	"time"

	"github.com/cucumber/godog"
)

// CorrelationContext maintains state for correlation rule test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type CorrelationContext struct {
	baseURL             string
	httpClient          *http.Client
	currentRule         map[string]interface{}
	sentEvents          []map[string]interface{}
	correlationAlert    map[string]interface{}
	alertGenerated      bool
	lastError           error
	ruleID              string
	stateCleanupStats   map[string]interface{}
	correlationBuckets  map[string][]map[string]interface{}
}

// InitializeCorrelationContext registers all correlation step definitions
// Requirement: FR-CORR-001, FR-CORR-002, FR-CORR-003 - Complete correlation coverage
func InitializeCorrelationContext(sc *godog.ScenarioContext) {
	ctx := &CorrelationContext{
		baseURL: "http://localhost:8080",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		currentRule:        make(map[string]interface{}),
		sentEvents:         make([]map[string]interface{}, 0),
		correlationBuckets: make(map[string][]map[string]interface{}),
	}

	// Background steps
	sc.Step(`^correlation state is initialized$`, ctx.correlationStateIsInitialized)

	// Rule definition steps
	sc.Step(`^a count-based correlation rule:$`, ctx.aCountBasedCorrelationRule)
	sc.Step(`^a count-based correlation rule with threshold > (\d+) and window (\d+)m$`, ctx.aCountBasedCorrelationRuleWithThresholdAndWindow)
	sc.Step(`^a value count correlation rule:$`, ctx.aValueCountCorrelationRule)
	sc.Step(`^a value count correlation rule with count_field "([^"]*)" and threshold > (\d+)$`, ctx.aValueCountCorrelationRuleWithCountField)
	sc.Step(`^an ordered sequence correlation rule:$`, ctx.anOrderedSequenceCorrelationRule)
	sc.Step(`^an ordered sequence correlation rule \[A, B, C\]$`, ctx.anOrderedSequenceCorrelationRuleABC)
	sc.Step(`^an unordered sequence correlation rule:$`, ctx.anUnorderedSequenceCorrelationRule)
	sc.Step(`^a sequence correlation rule with max_span = (\d+) minutes$`, ctx.aSequenceCorrelationRuleWithMaxSpan)
	sc.Step(`^a rare event correlation rule:$`, ctx.aRareEventCorrelationRule)
	sc.Step(`^a rare event correlation rule with threshold <= (\d+)$`, ctx.aRareEventCorrelationRuleWithThreshold)
	sc.Step(`^a correlation rule with max events per window = (\d+)$`, ctx.aCorrelationRuleWithMaxEventsPerWindow)
	sc.Step(`^a correlation rule with window = (\d+) minutes$`, ctx.aCorrelationRuleWithWindow)
	sc.Step(`^a correlation rule with group_by \["([^"]*)", "([^"]*)"\]$`, ctx.aCorrelationRuleWithGroupByMultipleFields)
	sc.Step(`^a count-based correlation rule$`, ctx.aCountBasedCorrelationRuleSimple)

	// Sequence modifiers
	sc.Step(`^the sequence window is (\d+) (hour|minutes?)$`, ctx.theSequenceWindowIs)
	sc.Step(`^the sequence is ordered$`, ctx.theSequenceIsOrdered)

	// Event sending steps
	sc.Step(`^I send (\d+) failed SSH login events from IP "([^"]*)" within (\d+) minutes$`, ctx.iSendFailedSSHLoginEventsFromIPWithinMinutes)
	sc.Step(`^I send (\d+) matching events within (\d+) minutes$`, ctx.iSendMatchingEventsWithinMinutes)
	sc.Step(`^I send (\d+) events with the following timestamps:$`, ctx.iSendEventsWithTimestamps)
	sc.Step(`^I send (\d+) successful auth events for user "([^"]*)" to (\d+) distinct hosts within (\d+) minutes$`, ctx.iSendSuccessfulAuthEventsForUserToDistinctHosts)
	sc.Step(`^I send (\d+) events with only (\d+) distinct usernames$`, ctx.iSendEventsWithDistinctUsernames)
	sc.Step(`^I send events in order: sqli → rce → exfil within (\d+) hour$`, ctx.iSendEventsInOrderSQLiRCEExfil)
	sc.Step(`^I send events in order: B → A → C$`, ctx.iSendEventsInOrderBAC)
	sc.Step(`^I send events in order: network → powershell within (\d+) minutes$`, ctx.iSendEventsInOrderNetworkPowershell)
	sc.Step(`^event A occurs at time T$`, ctx.eventAOccursAtTimeT)
	sc.Step(`^event B occurs at time T\+(\d+) minutes$`, ctx.eventBOccursAtTimeTPlus)
	sc.Step(`^a process "([^"]*)" is executed (\d+) times in (\d+) hours$`, ctx.aProcessIsExecutedTimesInHours)
	sc.Step(`^I send (\d+) matching events$`, ctx.iSendMatchingEvents)
	sc.Step(`^I send events from IP "([^"]*)" with username "([^"]*)"$`, ctx.iSendEventsFromIPWithUsername)
	sc.Step(`^all events have the same source_ip$`, ctx.allEventsHaveTheSameSourceIP)

	// State management steps
	sc.Step(`^correlation state contains events from (\d+) minutes ago$`, ctx.correlationStateContainsEventsFromMinutesAgo)
	sc.Step(`^the state cleanup runs$`, ctx.theStateCleanupRuns)
	sc.Step(`^a correlation threshold is exceeded$`, ctx.aCorrelationThresholdIsExceeded)

	// Assertion steps
	sc.Step(`^a correlation alert should be generated$`, ctx.aCorrelationAlertShouldBeGenerated)
	sc.Step(`^no correlation alert should be generated$`, ctx.noCorrelationAlertShouldBeGenerated)
	sc.Step(`^the alert should contain all (\d+) correlated events$`, ctx.theAlertShouldContainAllCorrelatedEvents)
	sc.Step(`^the alert correlation_type should be "([^"]*)"$`, ctx.theAlertCorrelationTypeShouldBe)
	sc.Step(`^the alert group_key should be "([^"]*)"$`, ctx.theAlertGroupKeyShouldBe)
	sc.Step(`^the correlation state should preserve the (\d+) events$`, ctx.theCorrelationStateShouldPreserveEvents)
	sc.Step(`^only (\d+) events should be counted \(events outside (\d+)m window excluded\)$`, ctx.onlyEventsShouldBeCounted)
	sc.Step(`^the alert should list all (\d+) distinct hostnames$`, ctx.theAlertShouldListDistinctHostnames)
	sc.Step(`^the distinct count should be (\d+)$`, ctx.theDistinctCountShouldBe)
	sc.Step(`^a sequence correlation alert should be generated$`, ctx.aSequenceCorrelationAlertShouldBeGenerated)
	sc.Step(`^no sequence correlation alert should be generated$`, ctx.noSequenceCorrelationAlertShouldBeGenerated)
	sc.Step(`^no sequence alert should be generated$`, ctx.noSequenceAlertShouldBeGenerated)
	sc.Step(`^the max_span violation should be logged$`, ctx.theMaxSpanViolationShouldBeLogged)
	sc.Step(`^a rare event alert should be generated on the (\d+)(?:nd|rd|th) occurrence$`, ctx.aRareEventAlertShouldBeGeneratedOnOccurrence)
	sc.Step(`^no rare event alert should be generated after the (\d+)(?:nd|rd|th) occurrence$`, ctx.noRareEventAlertShouldBeGeneratedAfterOccurrence)
	sc.Step(`^the oldest event should be evicted$`, ctx.theOldestEventShouldBeEvicted)
	sc.Step(`^the correlation state should contain exactly (\d+) events$`, ctx.theCorrelationStateShouldContainExactlyEvents)
	sc.Step(`^an eviction warning should be logged$`, ctx.anEvictionWarningShouldBeLogged)
	sc.Step(`^expired events should be removed from memory$`, ctx.expiredEventsShouldBeRemovedFromMemory)
	sc.Step(`^cleanup statistics should be logged$`, ctx.cleanupStatisticsShouldBeLogged)
	sc.Step(`^two separate correlation state buckets should exist$`, ctx.twoSeparateCorrelationStateBucketsShouldExist)
	sc.Step(`^each bucket should track events independently$`, ctx.eachBucketShouldTrackEventsIndependently)
	sc.Step(`^the generated alert should include:$`, ctx.theGeneratedAlertShouldInclude)

	// Cleanup
}
