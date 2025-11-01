package detect

import (
	"context"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cerberus/core"
)

// RuleEngine evaluates rules against events
type RuleEngine struct {
	rules            []core.Rule
	correlationRules []core.CorrelationRule
	correlationState map[string][]*core.Event // ruleID -> events in window
	stateMu          sync.RWMutex
	correlationTTL   int               // seconds
	cleanupCancel    context.CancelFunc // for stopping cleanup goroutine
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rules []core.Rule, correlationRules []core.CorrelationRule, correlationTTL int) *RuleEngine {
	re := &RuleEngine{
		rules:            rules,
		correlationRules: correlationRules,
		correlationState: make(map[string][]*core.Event),
		correlationTTL:   correlationTTL,
	}

	// Start periodic cleanup of expired correlation state
	ctx, cancel := context.WithCancel(context.Background())
	re.cleanupCancel = cancel
	re.startStateCleanup(ctx)

	return re
}

// ResetCorrelationState clears the correlation state map
func (re *RuleEngine) ResetCorrelationState() {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()
	re.correlationState = make(map[string][]*core.Event)
}

// Stop cleanup goroutine
func (re *RuleEngine) Stop() {
	if re.cleanupCancel != nil {
		re.cleanupCancel()
	}
}

// startStateCleanup runs periodic cleanup of expired correlation state
func (re *RuleEngine) startStateCleanup(ctx context.Context) {
	// Calculate cleanup interval - run at half the TTL, minimum 30 seconds
	cleanupInterval := time.Duration(re.correlationTTL/2) * time.Second
	if cleanupInterval < 30*time.Second {
		cleanupInterval = 30 * time.Second
	}

	ticker := time.NewTicker(cleanupInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				re.cleanupExpiredState()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupExpiredState removes expired entries from correlation state
func (re *RuleEngine) cleanupExpiredState() {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()

	now := time.Now()
	ttlDuration := time.Duration(re.correlationTTL) * time.Second

	for ruleID, events := range re.correlationState {
		if len(events) == 0 {
			delete(re.correlationState, ruleID)
			continue
		}

		// Check if oldest event is expired
		oldestEvent := events[0]
		if now.Sub(oldestEvent.Timestamp) > ttlDuration {
			// Remove all expired events
			cutoff := now.Add(-ttlDuration)
			validIdx := sort.Search(len(events), func(i int) bool {
				return events[i].Timestamp.After(cutoff)
			})

			if validIdx >= len(events) {
				// All events expired
				delete(re.correlationState, ruleID)
			} else {
				// Keep only valid events
				re.correlationState[ruleID] = events[validIdx:]
			}
		}
	}
}

// Evaluate evaluates all rules against an event and returns matching rules
func (re *RuleEngine) Evaluate(event *core.Event) []core.AlertableRule {
	var matches []core.AlertableRule
	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}
		if re.evaluateRule(rule, event) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// EvaluateCorrelation evaluates correlation rules and returns matching ones
func (re *RuleEngine) EvaluateCorrelation(event *core.Event) []core.AlertableRule {
	var matches []core.AlertableRule
	for _, rule := range re.correlationRules {
		if re.evaluateCorrelationRule(rule, event) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// evaluateCorrelationRule checks if a correlation rule matches based on event sequence
func (re *RuleEngine) evaluateCorrelationRule(rule core.CorrelationRule, event *core.Event) bool {
	re.stateMu.Lock()
	defer re.stateMu.Unlock()

	// Add event to state in sorted order
	events := re.correlationState[rule.ID]
	// Find insertion point to maintain sorted order
	insertIndex := sort.Search(len(events), func(i int) bool {
		if events[i].Timestamp.Equal(event.Timestamp) {
			return events[i].EventID >= event.EventID
		}
		return events[i].Timestamp.After(event.Timestamp)
	})
	// Insert event at the correct position
	events = append(events[:insertIndex], append([]*core.Event{event}, events[insertIndex:]...)...)

	// Clean up expired events from the front before window filtering
	now := event.Timestamp
	for len(events) > 0 && now.Sub(events[0].Timestamp).Seconds() > float64(re.correlationTTL) {
		events = events[1:]
	}

	// Clean up old events outside the window
	windowStart := now.Add(-rule.Window)
	// Find the first event within the window
	startIndex := sort.Search(len(events), func(i int) bool {
		return events[i].Timestamp.After(windowStart) || events[i].Timestamp.Equal(windowStart)
	})
	validEvents := events[startIndex:]

	if len(validEvents) == 0 {
		delete(re.correlationState, rule.ID)
		return false
	}
	re.correlationState[rule.ID] = validEvents

	// Check if sequence matches
	if len(validEvents) < len(rule.Sequence) {
		return false
	}

	// Check the last len(sequence) events match the sequence in order
	start := len(validEvents) - len(rule.Sequence)
	for i, eventType := range rule.Sequence {
		if validEvents[start+i].EventType != eventType {
			return false
		}
	}

	// Also evaluate conditions if any (on the last event or all?)
	// For simplicity, evaluate conditions on the triggering event
	if len(rule.Conditions) > 0 {
		if !re.evaluateRule(core.Rule{Conditions: rule.Conditions}, event) {
			return false
		}
	}

	// Clear state after successful match
	delete(re.correlationState, rule.ID)

	return true
}

// evaluateRule checks if a rule matches the event
func (re *RuleEngine) evaluateRule(rule core.Rule, event *core.Event) bool {
	if len(rule.Conditions) == 0 {
		return false
	}

	result := re.evaluateCondition(rule.Conditions[0], event)
	for i := 1; i < len(rule.Conditions); i++ {
		cond := rule.Conditions[i]
		condResult := re.evaluateCondition(cond, event)
		if rule.Conditions[i-1].Logic == "OR" {
			result = result || condResult
		} else {
			result = result && condResult
		}
	}
	return result
}

// evaluateCondition evaluates a single condition against the event
func (re *RuleEngine) evaluateCondition(cond core.Condition, event *core.Event) bool {
	fieldValue := re.getFieldValue(cond.Field, event)
	if fieldValue == nil {
		return false
	}

	switch cond.Operator {
	case "equals":
		return reflect.DeepEqual(fieldValue, cond.Value)
	case "not_equals":
		return !reflect.DeepEqual(fieldValue, cond.Value)
	case "contains":
		if str, ok := fieldValue.(string); ok {
			if valStr, ok := cond.Value.(string); ok {
				return strings.Contains(str, valStr)
			}
		}
		return false
	case "starts_with":
		if str, ok := fieldValue.(string); ok {
			if valStr, ok := cond.Value.(string); ok {
				return strings.HasPrefix(str, valStr)
			}
		}
		return false
	case "ends_with":
		if str, ok := fieldValue.(string); ok {
			if valStr, ok := cond.Value.(string); ok {
				return strings.HasSuffix(str, valStr)
			}
		}
		return false
	case "regex":
		if str, ok := fieldValue.(string); ok {
			if cond.Regex != nil {
				return cond.Regex.MatchString(str)
			}
		}
		return false
	case "greater_than":
		return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a > b })
	case "less_than":
		return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a < b })
	case "greater_than_or_equal":
		return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a >= b })
	case "less_than_or_equal":
		return compareNumbers(fieldValue, cond.Value, func(a, b float64) bool { return a <= b })
	}
	return false
}

// compareNumbers compares two values as numbers
func compareNumbers(a, b interface{}, cmp func(float64, float64) bool) bool {
	var fa, fb float64
	var ok bool

	// Try to convert a to float64
	if fa, ok = a.(float64); !ok {
		if str, ok := a.(string); ok {
			if parsed, err := strconv.ParseFloat(str, 64); err == nil {
				fa = parsed
			} else {
				return false
			}
		} else {
			return false
		}
	}

	// Try to convert b to float64
	if fb, ok = b.(float64); !ok {
		if str, ok := b.(string); ok {
			if parsed, err := strconv.ParseFloat(str, 64); err == nil {
				fb = parsed
			} else {
				return false
			}
		} else {
			return false
		}
	}

	return cmp(fa, fb)
}

// getFieldValue extracts field value from event using dot notation (e.g., "fields.key")
func (re *RuleEngine) getFieldValue(field string, event *core.Event) interface{} {
	parts := strings.Split(field, ".")

	// Start with top-level fields merged with event fields
	current := make(map[string]interface{})
	current["event_id"] = event.EventID
	current["timestamp"] = event.Timestamp
	current["source_format"] = event.SourceFormat
	current["source_ip"] = event.SourceIP
	current["event_type"] = event.EventType
	current["severity"] = event.Severity
	current["raw_data"] = event.RawData
	for k, v := range event.Fields {
		current[k] = v
	}

	// Navigate through nested maps using dot notation
	for i, part := range parts {
		val := current[part]
		if i < len(parts)-1 {
			// For non-last parts, must be a map to navigate further
			if m, ok := val.(map[string]interface{}); ok {
				current = m
			} else {
				return nil
			}
		} else {
			// For the last part, return whatever value it has
			return val
		}
	}
	return nil // Should not reach here
}
