package detect

import (
	"fmt"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/search"

	"go.uber.org/zap"
)

// CQLCorrelationEngine handles correlation and aggregation for CQL rules
type CQLCorrelationEngine struct {
	rules         map[string]*core.CQLRule     // rule ID -> rule
	state         map[string]*correlationState // state key -> correlation state
	stateMu       sync.RWMutex
	evaluator     *search.Evaluator
	logger        *zap.SugaredLogger
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
}

// correlationState tracks aggregation state for a rule
type correlationState struct {
	RuleID       string
	GroupKey     string // Computed from group_by fields
	Events       []*eventData
	FirstSeen    time.Time
	LastSeen     time.Time
	Aggregations map[string]interface{} // Cached aggregation results
	mu           sync.RWMutex
}

// eventData stores event information for correlation
type eventData struct {
	Event     *core.Event
	Timestamp time.Time
	Fields    map[string]interface{} // Extracted field values for aggregation
}

// NewCQLCorrelationEngine creates a new correlation engine
func NewCQLCorrelationEngine(rules []*core.CQLRule, logger *zap.SugaredLogger) *CQLCorrelationEngine {
	engine := &CQLCorrelationEngine{
		rules:     make(map[string]*core.CQLRule),
		state:     make(map[string]*correlationState),
		evaluator: search.NewEvaluator(),
		logger:    logger,
		stopCh:    make(chan struct{}),
	}

	// Index rules by ID
	for _, rule := range rules {
		if rule.Correlation != nil {
			engine.rules[rule.ID] = rule
		}
	}

	// Start cleanup goroutine
	engine.cleanupTicker = time.NewTicker(60 * time.Second)
	go engine.cleanupExpiredState()

	return engine
}

// ProcessEvent processes an event through all correlated CQL rules
func (e *CQLCorrelationEngine) ProcessEvent(event *core.Event) []*core.Alert {
	alerts := []*core.Alert{}

	for _, rule := range e.rules {
		if !rule.Enabled || rule.Correlation == nil {
			continue
		}

		// First check if event matches the base query
		matched, matchedFields, err := e.evaluator.Evaluate(rule.Query, event)
		if err != nil {
			e.logger.Errorw("CQL evaluation error", "rule", rule.ID, "error", err)
			continue
		}

		if !matched {
			continue
		}

		// Event matched base query, now handle correlation
		alert := e.processCorrelation(rule, event, matchedFields)
		if alert != nil {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// processCorrelation handles correlation logic for a matched event
func (e *CQLCorrelationEngine) processCorrelation(rule *core.CQLRule, event *core.Event, matchedFields map[string]interface{}) *core.Alert {
	// Compute group key from group_by fields
	groupKey := e.computeGroupKey(rule, event)
	stateKey := fmt.Sprintf("%s:%s", rule.ID, groupKey)

	e.stateMu.Lock()
	state, exists := e.state[stateKey]
	if !exists {
		state = &correlationState{
			RuleID:       rule.ID,
			GroupKey:     groupKey,
			Events:       []*eventData{},
			FirstSeen:    time.Now(),
			Aggregations: make(map[string]interface{}),
		}
		e.state[stateKey] = state
	}
	e.stateMu.Unlock()

	state.mu.Lock()
	defer state.mu.Unlock()

	// Add event to state
	evtData := &eventData{
		Event:     event,
		Timestamp: time.Now(),
		Fields:    matchedFields,
	}
	state.Events = append(state.Events, evtData)
	state.LastSeen = time.Now()

	// Clean up expired events based on timeframe
	e.cleanupExpiredEvents(state, rule.Correlation.Timeframe)

	// Evaluate aggregation and check threshold
	aggregationValue := e.evaluateAggregation(state, rule.Correlation)
	thresholdMet := e.checkThreshold(aggregationValue, rule.Correlation.Threshold, rule.Correlation.Operator)

	if thresholdMet {
		// Create alert
		// TASK 137: Handle error from createCorrelationAlert
		alert, err := e.createCorrelationAlert(rule, state, aggregationValue, matchedFields)
		if err != nil {
			e.logger.Errorf("Failed to create correlation alert: %v", err)
			return nil
		}

		// Reset state after alert
		state.Events = []*eventData{}
		state.FirstSeen = time.Now()
		state.Aggregations = make(map[string]interface{})

		return alert
	}

	return nil
}

// computeGroupKey creates a unique key from group_by fields
func (e *CQLCorrelationEngine) computeGroupKey(rule *core.CQLRule, event *core.Event) string {
	if len(rule.Correlation.GroupBy) == 0 {
		return "global"
	}

	key := ""
	for _, field := range rule.Correlation.GroupBy {
		value := e.evaluator.GetFieldValue(field, event)
		if value != nil {
			key += fmt.Sprintf("%s=%v;", field, value)
		}
	}
	return key
}

// cleanupExpiredEvents removes events outside the timeframe window
func (e *CQLCorrelationEngine) cleanupExpiredEvents(state *correlationState, timeframe int) {
	now := time.Now()
	cutoff := now.Add(-time.Duration(timeframe) * time.Second)

	validEvents := []*eventData{}
	for _, evt := range state.Events {
		if evt.Timestamp.After(cutoff) {
			validEvents = append(validEvents, evt)
		}
	}
	state.Events = validEvents
}

// evaluateAggregation computes the aggregation value
func (e *CQLCorrelationEngine) evaluateAggregation(state *correlationState, config *core.CorrelationConfig) interface{} {
	if len(state.Events) == 0 {
		return 0
	}

	switch config.Aggregation {
	case "count":
		return len(state.Events)

	case "sum":
		return e.aggregateSum(state, config.Field)

	case "avg":
		sum := e.aggregateSum(state, config.Field)
		if count := len(state.Events); count > 0 {
			if sumFloat, ok := sum.(float64); ok {
				return sumFloat / float64(count)
			}
		}
		return 0.0

	case "min":
		return e.aggregateMin(state, config.Field)

	case "max":
		return e.aggregateMax(state, config.Field)

	case "distinct":
		return e.aggregateDistinct(state, config.Field)

	default:
		e.logger.Warnw("Unknown aggregation type", "type", config.Aggregation)
		return 0
	}
}

// aggregateSum calculates sum of a field
func (e *CQLCorrelationEngine) aggregateSum(state *correlationState, field string) interface{} {
	var sum float64
	for _, evt := range state.Events {
		value := e.evaluator.GetFieldValue(field, evt.Event)
		if value != nil {
			if floatVal := e.evaluator.ToFloat64(value); floatVal > 0 {
				sum += floatVal
			}
		}
	}
	return sum
}

// aggregateMin calculates minimum value
func (e *CQLCorrelationEngine) aggregateMin(state *correlationState, field string) interface{} {
	var min float64
	first := true

	for _, evt := range state.Events {
		value := e.evaluator.GetFieldValue(field, evt.Event)
		if value != nil {
			floatVal := e.evaluator.ToFloat64(value)
			if first || floatVal < min {
				min = floatVal
				first = false
			}
		}
	}
	return min
}

// aggregateMax calculates maximum value
func (e *CQLCorrelationEngine) aggregateMax(state *correlationState, field string) interface{} {
	var max float64
	for _, evt := range state.Events {
		value := e.evaluator.GetFieldValue(field, evt.Event)
		if value != nil {
			if floatVal := e.evaluator.ToFloat64(value); floatVal > max {
				max = floatVal
			}
		}
	}
	return max
}

// aggregateDistinct counts distinct values
func (e *CQLCorrelationEngine) aggregateDistinct(state *correlationState, field string) interface{} {
	distinct := make(map[string]bool)
	for _, evt := range state.Events {
		value := e.evaluator.GetFieldValue(field, evt.Event)
		if value != nil {
			distinct[fmt.Sprintf("%v", value)] = true
		}
	}
	return len(distinct)
}

// checkThreshold checks if aggregation value meets threshold
func (e *CQLCorrelationEngine) checkThreshold(value interface{}, threshold interface{}, operator string) bool {
	// Convert to float64 for comparison
	var valueFloat float64
	switch v := value.(type) {
	case int:
		valueFloat = float64(v)
	case float64:
		valueFloat = v
	default:
		return false
	}

	var thresholdFloat float64
	switch t := threshold.(type) {
	case int:
		thresholdFloat = float64(t)
	case float64:
		thresholdFloat = t
	case int64:
		thresholdFloat = float64(t)
	default:
		return false
	}

	switch operator {
	case ">":
		return valueFloat > thresholdFloat
	case "<":
		return valueFloat < thresholdFloat
	case ">=":
		return valueFloat >= thresholdFloat
	case "<=":
		return valueFloat <= thresholdFloat
	case "==", "=":
		return valueFloat == thresholdFloat
	case "!=":
		return valueFloat != thresholdFloat
	default:
		return false
	}
}

// createCorrelationAlert creates an alert from correlation match
func (e *CQLCorrelationEngine) createCorrelationAlert(rule *core.CQLRule, state *correlationState, aggregationValue interface{}, matchedFields map[string]interface{}) (*core.Alert, error) {
	// Get the most recent event for alert details
	var lastEvent *core.Event
	var eventID string
	if len(state.Events) > 0 {
		lastEvent = state.Events[len(state.Events)-1].Event
		eventID = lastEvent.EventID
	}

	// Build metadata for the correlation alert
	metadata := &core.AlertMetadata{
		RuleName:        rule.Name,
		RuleDescription: rule.Description,
		RuleType:        "cql-correlation",
		MitreTechniques: rule.MITRE,
		Category:        "correlation",
		ConfidenceScore: 80, // Correlation rules have higher confidence
	}

	// Create alert using the NewAlertWithMetadata helper
	alert, err := core.NewAlertWithMetadata(rule.ID, eventID, rule.Severity, lastEvent, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create correlation alert for rule %s: %w", rule.ID, err)
	}

	// Build event IDs list from all correlated events
	eventIDs := make([]string, 0, len(state.Events))
	for _, evt := range state.Events {
		eventIDs = append(eventIDs, evt.Event.EventID)
	}
	alert.EventIDs = eventIDs

	e.logger.Infof("CQL correlation alert created: rule=%s, aggregation=%s %s %v (threshold: %v), events=%d, timeframe=%ds",
		rule.Name,
		rule.Correlation.Aggregation,
		rule.Correlation.Operator,
		aggregationValue,
		rule.Correlation.Threshold,
		len(state.Events),
		rule.Correlation.Timeframe,
	)

	return alert, nil
}

// cleanupExpiredState removes old correlation state periodically
func (e *CQLCorrelationEngine) cleanupExpiredState() {
	for {
		select {
		case <-e.cleanupTicker.C:
			e.performCleanup()
		case <-e.stopCh:
			return
		}
	}
}

// performCleanup removes expired correlation state
func (e *CQLCorrelationEngine) performCleanup() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	now := time.Now()
	toDelete := []string{}

	for key, state := range e.state {
		rule, exists := e.rules[state.RuleID]
		if !exists {
			toDelete = append(toDelete, key)
			continue
		}

		// Check if state has expired (2x timeframe)
		timeout := time.Duration(rule.Correlation.Timeframe*2) * time.Second
		if now.Sub(state.LastSeen) > timeout {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(e.state, key)
	}

	if len(toDelete) > 0 {
		e.logger.Infow("Cleaned up expired correlation state", "count", len(toDelete))
	}
}

// Stop stops the correlation engine
func (e *CQLCorrelationEngine) Stop() {
	if e.cleanupTicker != nil {
		e.cleanupTicker.Stop()
	}
	close(e.stopCh)
}

// UpdateRules updates the rule set
func (e *CQLCorrelationEngine) UpdateRules(rules []*core.CQLRule) {
	newRules := make(map[string]*core.CQLRule)
	for _, rule := range rules {
		if rule.Correlation != nil {
			newRules[rule.ID] = rule
		}
	}

	e.stateMu.Lock()
	e.rules = newRules
	e.stateMu.Unlock()
}

// GetState returns current correlation state (for debugging/monitoring)
func (e *CQLCorrelationEngine) GetState() map[string]interface{} {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()

	state := make(map[string]interface{})
	state["rule_count"] = len(e.rules)
	state["active_states"] = len(e.state)

	states := []map[string]interface{}{}
	for key, s := range e.state {
		states = append(states, map[string]interface{}{
			"key":         key,
			"rule_id":     s.RuleID,
			"group_key":   s.GroupKey,
			"event_count": len(s.Events),
			"first_seen":  s.FirstSeen.Format(time.RFC3339),
			"last_seen":   s.LastSeen.Format(time.RFC3339),
		})
	}
	state["states"] = states

	return state
}
