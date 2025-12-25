package detect

import (
	"fmt"

	"cerberus/core"
)

// EvaluateCountRule evaluates a count-based correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateCountRule(rule core.CountCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// 1. Check if event matches selection criteria
	if !e.MatchesSelection(event, rule.Selection) {
		return nil, false
	}

	// 2. Compute group key from group_by fields
	groupKey := ComputeGroupKey(event, rule.GroupBy)

	// 3. Increment count for this group and store event
	count := e.stateStore.IncrementCount(rule.ID, groupKey, event)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// 4. Check threshold
	if e.EvaluateThreshold(float64(count), rule.Threshold) {
		// 5. Get all events in window
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// 6. Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "count",
			"group_key":        groupKey,
			"count":            count,
			"threshold":        rule.Threshold,
			"window":           rule.Window.String(),
			"group_by":         rule.GroupBy,
		})

		// 7. Reset state for this group
		e.stateStore.Reset()

		return alert, true
	}

	return nil, false
}

// EvaluateValueCountRule evaluates a value count correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateValueCountRule(rule core.ValueCountCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// 1. Check if event matches selection criteria
	if !e.MatchesSelection(event, rule.Selection) {
		return nil, false
	}

	// 2. Compute group key from group_by fields
	groupKey := ComputeGroupKey(event, rule.GroupBy)

	// 3. Extract the value to count
	value := getEventFieldByPath(event, rule.CountField)
	if value == nil {
		return nil, false
	}

	// 4. Add value to set and get distinct count
	distinctCount := e.stateStore.AddValue(rule.ID, groupKey, rule.CountField, value)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// 5. Check threshold
	if e.EvaluateThreshold(float64(distinctCount), rule.Threshold) {
		// 6. Get all events in window
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// 7. Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "value_count",
			"group_key":        groupKey,
			"distinct_count":   distinctCount,
			"count_field":      rule.CountField,
			"threshold":        rule.Threshold,
			"window":           rule.Window.String(),
			"group_by":         rule.GroupBy,
		})

		return alert, true
	}

	return nil, false
}

// EvaluateSequenceRule evaluates an enhanced sequence correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateSequenceRule(rule core.SequenceCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// Find which stage this event matches (if any)
	matchedStage := -1
	for i, stage := range rule.Sequence {
		if e.MatchesSelection(event, stage.Selection) {
			matchedStage = i
			break
		}
	}

	if matchedStage == -1 {
		return nil, false
	}

	// Compute group key from group_by fields
	groupKey := ComputeGroupKey(event, rule.GroupBy)

	// Add event to sequence
	stageName := rule.Sequence[matchedStage].Name
	matchedSequence := e.stateStore.AddToSequence(rule.ID, groupKey, stageName, event)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// Check if sequence is complete
	isComplete := e.checkSequenceComplete(rule, matchedSequence)

	if isComplete {
		// Get all events in sequence
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// Check max_span if specified
		if rule.MaxSpan > 0 && len(correlatedEvents) > 0 {
			firstEvent := correlatedEvents[0]
			lastEvent := correlatedEvents[len(correlatedEvents)-1]
			span := lastEvent.Timestamp.Sub(firstEvent.Timestamp)

			if span > rule.MaxSpan {
				// Sequence took too long
				return nil, false
			}
		}

		// Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "sequence",
			"group_key":        groupKey,
			"matched_sequence": matchedSequence,
			"ordered":          rule.Ordered,
			"sequence_stages":  len(rule.Sequence),
			"window":           rule.Window.String(),
			"max_span":         rule.MaxSpan.String(),
			"group_by":         rule.GroupBy,
		})

		return alert, true
	}

	return nil, false
}

// checkSequenceComplete checks if a matched sequence satisfies the rule requirements
func (e *EnhancedCorrelationEvaluator) checkSequenceComplete(rule core.SequenceCorrelationRule, matchedSequence []string) bool {
	// Create map of required stages
	requiredStages := make(map[string]bool)
	for _, stage := range rule.Sequence {
		if stage.Required {
			requiredStages[stage.Name] = true
		}
	}

	// If no required stages, sequence needs at least one match
	if len(requiredStages) == 0 {
		return len(matchedSequence) > 0
	}

	// Check if all required stages are matched
	matchedStages := make(map[string]bool)
	for _, stageName := range matchedSequence {
		matchedStages[stageName] = true
	}

	for requiredStage := range requiredStages {
		if !matchedStages[requiredStage] {
			return false
		}
	}

	// Check ordering if required
	if rule.Ordered {
		return e.checkSequenceOrdered(rule, matchedSequence)
	}

	return true
}

// checkSequenceOrdered checks if matched stages follow the correct order
func (e *EnhancedCorrelationEvaluator) checkSequenceOrdered(rule core.SequenceCorrelationRule, matchedSequence []string) bool {
	// Build stage index map
	stageIndex := make(map[string]int)
	for i, stage := range rule.Sequence {
		stageIndex[stage.Name] = i
	}

	// Check if matched sequence follows rule order
	lastIndex := -1
	for _, stageName := range matchedSequence {
		currentIndex := stageIndex[stageName]
		if currentIndex < lastIndex {
			return false
		}
		lastIndex = currentIndex
	}

	return true
}

// EvaluateRareRule evaluates a rare event correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateRareRule(rule core.RareCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// 1. Check if event matches selection criteria
	if !e.MatchesSelection(event, rule.Selection) {
		return nil, false
	}

	// 2. Extract the field value to track
	value := getEventFieldByPath(event, rule.CountField)
	if value == nil {
		return nil, false
	}

	// 3. Use value as group key for rare detection
	groupKey := fmt.Sprintf("%v", value)

	// 4. Increment count for this value
	count := e.stateStore.IncrementCount(rule.ID, groupKey, event)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// 5. Check threshold (rare events have LOW count)
	if e.EvaluateThreshold(float64(count), rule.Threshold) {
		// Get all events with this rare value
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "rare",
			"rare_value":       value,
			"count_field":      rule.CountField,
			"count":            count,
			"threshold":        rule.Threshold,
			"window":           rule.Window.String(),
		})

		return alert, true
	}

	return nil, false
}

// EvaluateStatisticalRule evaluates a statistical anomaly correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateStatisticalRule(rule core.StatisticalCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// 1. Check if event matches selection criteria
	if !e.MatchesSelection(event, rule.Selection) {
		return nil, false
	}

	// 2. Extract metric value
	metricValue, err := e.ExtractNumericValue(event, rule.MetricField)
	if err != nil {
		return nil, false
	}

	// 3. Compute group key from group_by fields
	groupKey := ComputeGroupKey(event, rule.GroupBy)

	// 4. Add metric to statistics
	e.stateStore.AddMetric(rule.ID, groupKey, metricValue)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// 5. Get current statistics
	stats := e.stateStore.GetStatistics(rule.ID, groupKey)

	// 6. Check if we have enough data for statistical analysis
	minDataPoints := 10 // Minimum data points for meaningful statistics
	if stats.Count < minDataPoints {
		return nil, false
	}

	// 7. Evaluate statistical threshold
	if e.EvaluateStatisticalThreshold(metricValue, stats, rule.Threshold) {
		// Get all events in window
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "statistical",
			"group_key":        groupKey,
			"metric_field":     rule.MetricField,
			"metric_value":     metricValue,
			"baseline_mean":    stats.Mean,
			"baseline_stddev":  stats.StdDev,
			"deviation":        (metricValue - stats.Mean) / stats.StdDev,
			"threshold":        rule.Threshold,
			"window":           rule.Window.String(),
			"baseline_window":  rule.BaselineWindow.String(),
			"group_by":         rule.GroupBy,
		})

		return alert, true
	}

	return nil, false
}

// EvaluateCrossEntityRule evaluates a cross-entity correlation rule
func (e *EnhancedCorrelationEvaluator) EvaluateCrossEntityRule(rule core.CrossEntityCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// 1. Check if event matches selection criteria
	if !e.MatchesSelection(event, rule.Selection) {
		return nil, false
	}

	// 2. Extract tracking field value (e.g., username)
	trackValue := getEventFieldByPath(event, rule.TrackField)
	if trackValue == nil {
		return nil, false
	}

	// 3. Use track value as group key
	groupKey := fmt.Sprintf("%v", trackValue)

	// 4. Extract the field to count distinct values (e.g., dest_host)
	distinctValue := getEventFieldByPath(event, rule.CountDistinct)
	if distinctValue == nil {
		return nil, false
	}

	// 5. Add distinct value and get count
	distinctCount := e.stateStore.AddValue(rule.ID, groupKey, rule.CountDistinct, distinctValue)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// 6. Check threshold
	if e.EvaluateThreshold(float64(distinctCount), rule.Threshold) {
		// Get all events showing cross-entity behavior
		correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

		// Generate alert with context
		alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
			"correlation_type": "cross_entity",
			"track_field":      rule.TrackField,
			"track_value":      trackValue,
			"count_distinct":   rule.CountDistinct,
			"distinct_count":   distinctCount,
			"threshold":        rule.Threshold,
			"window":           rule.Window.String(),
		})

		return alert, true
	}

	return nil, false
}

// EvaluateChainRule evaluates a chain correlation rule (multi-stage attack detection)
func (e *EnhancedCorrelationEvaluator) EvaluateChainRule(rule core.ChainCorrelationRule, event *core.Event) (*core.Alert, bool) {
	// Find which stage this event matches (if any)
	matchedStage := -1
	for i, stage := range rule.Stages {
		if e.MatchesSelection(event, stage.Selection) {
			matchedStage = i
			break
		}
	}

	if matchedStage == -1 {
		return nil, false
	}

	// Compute group key from group_by fields
	groupKey := ComputeGroupKey(event, rule.GroupBy)

	// Add event to chain sequence
	stageName := rule.Stages[matchedStage].Name
	matchedStages := e.stateStore.AddToSequence(rule.ID, groupKey, stageName, event)
	e.stateStore.AddEvent(rule.ID, groupKey, event)

	// Check if minimum required stages are met
	requiredStages := 0
	for _, stage := range rule.Stages {
		if stage.Required {
			requiredStages++
		}
	}

	// Use MinStages if specified, otherwise use required stages count
	minStages := rule.MinStages
	if minStages == 0 {
		minStages = requiredStages
	}

	if len(matchedStages) < minStages {
		return nil, false
	}

	// Check all required stages are present
	matchedStageMap := make(map[string]bool)
	for _, stageName := range matchedStages {
		matchedStageMap[stageName] = true
	}

	for _, stage := range rule.Stages {
		if stage.Required && !matchedStageMap[stage.Name] {
			return nil, false
		}
	}

	// Get all events in chain
	correlatedEvents := e.stateStore.GetEvents(rule.ID, groupKey)

	// Check max duration if specified
	if rule.MaxDuration > 0 && len(correlatedEvents) > 0 {
		firstEvent := correlatedEvents[0]
		lastEvent := correlatedEvents[len(correlatedEvents)-1]
		duration := lastEvent.Timestamp.Sub(firstEvent.Timestamp)

		if duration > rule.MaxDuration {
			// Chain took too long
			return nil, false
		}
	}

	// Generate alert with context
	alert := e.GenerateCorrelationAlert(&rule, event, correlatedEvents, map[string]interface{}{
		"correlation_type": "chain",
		"group_key":        groupKey,
		"matched_stages":   matchedStages,
		"total_stages":     len(rule.Stages),
		"min_stages":       minStages,
		"max_duration":     rule.MaxDuration.String(),
		"chain_duration":   correlatedEvents[len(correlatedEvents)-1].Timestamp.Sub(correlatedEvents[0].Timestamp).String(),
		"group_by":         rule.GroupBy,
	})

	return alert, true
}
