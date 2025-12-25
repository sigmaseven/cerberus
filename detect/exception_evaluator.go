package detect

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/search"
	"cerberus/storage"
)

// ExceptionEvaluator evaluates exceptions against events
type ExceptionEvaluator struct {
	exceptionStorage storage.ExceptionStorageInterface
}

// NewExceptionEvaluator creates a new exception evaluator
func NewExceptionEvaluator(exceptionStorage storage.ExceptionStorageInterface) *ExceptionEvaluator {
	return &ExceptionEvaluator{
		exceptionStorage: exceptionStorage,
	}
}

// EvaluateExceptions evaluates all applicable exceptions against an event
// Returns the result indicating whether to suppress or modify the alert
func (e *ExceptionEvaluator) EvaluateExceptions(event map[string]interface{}, rule *core.Rule) (*core.ExceptionResult, error) {
	result := core.NewExceptionResult()

	// Get exceptions for this specific rule
	ruleExceptions, err := e.exceptionStorage.GetExceptionsByRuleID(rule.ID)
	if err != nil {
		return result, fmt.Errorf("failed to get rule exceptions: %w", err)
	}

	// Get global exceptions
	globalExceptions, err := e.exceptionStorage.GetGlobalExceptions()
	if err != nil {
		return result, fmt.Errorf("failed to get global exceptions: %w", err)
	}

	// Combine and sort by priority (lower = higher priority)
	allExceptions := append(ruleExceptions, globalExceptions...)

	// Evaluate exceptions in priority order
	for _, exception := range allExceptions {
		// Skip inactive exceptions
		if !exception.IsActive() {
			continue
		}

		// Evaluate the condition
		matches, err := e.evaluateCondition(&exception, event)
		if err != nil {
			// Log error but continue with other exceptions
			continue
		}

		if matches {
			// Track the matched exception
			result.MatchedExceptions = append(result.MatchedExceptions, exception.ID)

			// Update hit tracking (async to avoid blocking)
			go func(exceptionID string) {
				now := time.Now()
				_ = e.exceptionStorage.IncrementHitCount(exceptionID)
				_ = e.exceptionStorage.UpdateLastHit(exceptionID, now)
			}(exception.ID)

			// Apply the exception action
			switch exception.Type {
			case core.ExceptionSuppress:
				result.Action = "suppress"
				result.SuppressReason = fmt.Sprintf("Suppressed by exception: %s", exception.Name)
				// Suppression takes precedence - return immediately
				return result, nil

			case core.ExceptionModifySeverity:
				result.Action = "modify"
				result.NewSeverity = exception.NewSeverity
				// Continue checking for higher priority exceptions
			}
		}
	}

	return result, nil
}

// evaluateCondition evaluates an exception condition against an event
func (e *ExceptionEvaluator) evaluateCondition(exception *core.Exception, event map[string]interface{}) (bool, error) {
	switch exception.ConditionType {
	case core.ConditionTypeSigmaFilter:
		return e.evaluateSigmaFilter(exception.Condition, event)
	case core.ConditionTypeCQL:
		return e.evaluateCQL(exception.Condition, event)
	default:
		return false, fmt.Errorf("unknown condition type: %s", exception.ConditionType)
	}
}

// evaluateSigmaFilter evaluates a SIGMA-style filter against an event
// Format: "field|modifier: value" or "field: value"
func (e *ExceptionEvaluator) evaluateSigmaFilter(filter string, event map[string]interface{}) (bool, error) {
	// Parse filter lines (supports AND logic with multiple lines)
	lines := strings.Split(strings.TrimSpace(filter), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if the line matches
		matches, err := e.evaluateSigmaFilterLine(line, event)
		if err != nil {
			return false, err
		}

		// All conditions must match (AND logic)
		if !matches {
			return false, nil
		}
	}

	return true, nil
}

// evaluateSigmaFilterLine evaluates a single line of a SIGMA filter
func (e *ExceptionEvaluator) evaluateSigmaFilterLine(line string, event map[string]interface{}) (bool, error) {
	// Skip AND/OR keywords
	line = strings.TrimPrefix(line, "AND ")
	line = strings.TrimPrefix(line, "OR ")
	line = strings.TrimSpace(line)

	// Parse the condition: field|modifier: value or field: value
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid filter format: %s", line)
	}

	fieldPart := strings.TrimSpace(parts[0])
	valuePart := strings.TrimSpace(parts[1])

	// Remove quotes from value
	valuePart = strings.Trim(valuePart, "'\"")

	// Parse field and modifier
	var field, modifier string
	if strings.Contains(fieldPart, "|") {
		fieldModParts := strings.SplitN(fieldPart, "|", 2)
		field = strings.TrimSpace(fieldModParts[0])
		modifier = strings.TrimSpace(fieldModParts[1])
	} else {
		field = fieldPart
		modifier = "equals"
	}

	// Get the field value from the event
	eventValue, exists := event[field]
	if !exists {
		return false, nil
	}

	// Convert event value to string for comparison
	eventValueStr := fmt.Sprintf("%v", eventValue)

	// Apply modifier
	return e.applyModifier(eventValueStr, valuePart, modifier)
}

// applyModifier applies a SIGMA modifier to compare values
func (e *ExceptionEvaluator) applyModifier(eventValue, filterValue, modifier string) (bool, error) {
	switch modifier {
	case "equals", "":
		return strings.EqualFold(eventValue, filterValue), nil

	case "contains":
		return strings.Contains(strings.ToLower(eventValue), strings.ToLower(filterValue)), nil

	case "startswith":
		return strings.HasPrefix(strings.ToLower(eventValue), strings.ToLower(filterValue)), nil

	case "endswith":
		return strings.HasSuffix(strings.ToLower(eventValue), strings.ToLower(filterValue)), nil

	case "re", "regex":
		matched, err := regexp.MatchString(filterValue, eventValue)
		if err != nil {
			return false, fmt.Errorf("invalid regex: %w", err)
		}
		return matched, nil

	case "exists":
		return true, nil

	default:
		return false, fmt.Errorf("unsupported modifier: %s", modifier)
	}
}

// evaluateCQL evaluates a CQL query against an event
func (e *ExceptionEvaluator) evaluateCQL(query string, event map[string]interface{}) (bool, error) {
	// Convert map to core.Event structure
	coreEvent := &core.Event{
		Fields: event,
	}

	// Add timestamp if available
	if ts, ok := event["timestamp"]; ok {
		if tsTime, ok := ts.(time.Time); ok {
			coreEvent.Timestamp = tsTime
		}
	}

	// Evaluate the CQL query
	evaluator := &search.Evaluator{}
	matches, _, err := evaluator.Evaluate(query, coreEvent)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate CQL query: %w", err)
	}

	return matches, nil
}
