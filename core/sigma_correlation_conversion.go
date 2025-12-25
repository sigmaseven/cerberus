package core

import (
	"fmt"
	"time"
)

// ToCountCorrelationRule converts SigmaCorrelation to CountCorrelationRule.
// Returns error if the correlation type is not event_count or required fields are missing.
func (sc *SigmaCorrelation) ToCountCorrelationRule(base EnhancedCorrelationRule, selection map[string]interface{}, actions []Action) (*CountCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "event_count" && sc.Type != "count" {
		return nil, fmt.Errorf("correlation type must be event_count or count, got: %s", sc.Type)
	}

	// Parse timespan
	window, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timespan: %w", err)
	}

	// Convert condition to threshold
	threshold, err := sc.Condition.ToThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to convert condition: %w", err)
	}

	return &CountCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		GroupBy:                 sc.GroupBy,
		Threshold:               threshold,
		Actions:                 actions,
	}, nil
}

// ToValueCountCorrelationRule converts SigmaCorrelation to ValueCountCorrelationRule.
func (sc *SigmaCorrelation) ToValueCountCorrelationRule(base EnhancedCorrelationRule, selection map[string]interface{}, actions []Action) (*ValueCountCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "value_count" {
		return nil, fmt.Errorf("correlation type must be value_count, got: %s", sc.Type)
	}

	// Parse timespan
	window, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timespan: %w", err)
	}

	// Convert condition to threshold
	threshold, err := sc.Condition.ToThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to convert condition: %w", err)
	}

	return &ValueCountCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		CountField:              sc.DistinctField,
		GroupBy:                 sc.GroupBy,
		Threshold:               threshold,
		Actions:                 actions,
	}, nil
}

// ToSequenceCorrelationRule converts SigmaCorrelation to SequenceCorrelationRule.
func (sc *SigmaCorrelation) ToSequenceCorrelationRule(base EnhancedCorrelationRule, stages []SequenceStage, actions []Action) (*SequenceCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "sequence" {
		return nil, fmt.Errorf("correlation type must be sequence, got: %s", sc.Type)
	}

	// Parse timespan
	window, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timespan: %w", err)
	}

	// Parse max_span if provided
	var maxSpan time.Duration
	if sc.MaxDuration != "" {
		maxSpan, err = sc.ParseDuration(sc.MaxDuration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse max_duration: %w", err)
		}
	}

	return &SequenceCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Sequence:                stages,
		Ordered:                 sc.Ordered,
		GroupBy:                 sc.GroupBy,
		MaxSpan:                 maxSpan,
		Actions:                 actions,
	}, nil
}

// ToRareCorrelationRule converts SigmaCorrelation to RareCorrelationRule.
func (sc *SigmaCorrelation) ToRareCorrelationRule(base EnhancedCorrelationRule, selection map[string]interface{}, actions []Action) (*RareCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "rare" {
		return nil, fmt.Errorf("correlation type must be rare, got: %s", sc.Type)
	}

	// Parse baseline_window as the main window
	window, err := sc.ParseDuration(sc.BaselineWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse baseline_window: %w", err)
	}

	// Convert condition to threshold
	threshold, err := sc.Condition.ToThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to convert condition: %w", err)
	}

	// Use distinct_field as count_field if provided
	countField := sc.DistinctField
	if countField == "" {
		// Default to tracking by a required field
		countField = DefaultRareCountField
	}

	return &RareCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		CountField:              countField,
		Threshold:               threshold,
		Actions:                 actions,
	}, nil
}

// ToStatisticalCorrelationRule converts SigmaCorrelation to StatisticalCorrelationRule.
func (sc *SigmaCorrelation) ToStatisticalCorrelationRule(base EnhancedCorrelationRule, selection map[string]interface{}, metricField string, actions []Action) (*StatisticalCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "statistical" {
		return nil, fmt.Errorf("correlation type must be statistical, got: %s", sc.Type)
	}

	// Parse timespan as detection window
	window, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timespan: %w", err)
	}

	// Parse baseline_window
	baselineWindow, err := sc.ParseDuration(sc.BaselineWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse baseline_window: %w", err)
	}

	// Create threshold with std_dev operator
	threshold := Threshold{
		Operator: ThresholdOpStdDev,
		Value:    sc.StdDevThreshold,
	}

	return &StatisticalCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		BaselineWindow:          baselineWindow,
		Selection:               selection,
		MetricField:             metricField,
		GroupBy:                 sc.GroupBy,
		Threshold:               threshold,
		Actions:                 actions,
	}, nil
}

// ToChainCorrelationRule converts SigmaCorrelation to ChainCorrelationRule.
func (sc *SigmaCorrelation) ToChainCorrelationRule(base EnhancedCorrelationRule, stages []ChainStage, actions []Action) (*ChainCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "chain" {
		return nil, fmt.Errorf("correlation type must be chain, got: %s", sc.Type)
	}

	// Parse max_duration
	maxDuration, err := sc.ParseDuration(sc.MaxDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to parse max_duration: %w", err)
	}

	// Convert SIGMA chain stages to core chain stages
	coreStages := make([]ChainStage, len(sc.Stages))
	for i, stage := range sc.Stages {
		coreStages[i] = ChainStage{
			Name: stage.Name,
			// Selection will be populated from referenced detection rule
			Selection: map[string]interface{}{
				"detection_ref": stage.DetectionRef,
			},
			Required: true, // All stages required by default
		}
	}

	minStages := sc.MinStages
	if minStages == 0 {
		minStages = len(coreStages)
	}

	return &ChainCorrelationRule{
		EnhancedCorrelationRule: base,
		MaxDuration:             maxDuration,
		Stages:                  coreStages,
		GroupBy:                 sc.GroupBy,
		MinStages:               minStages,
		Actions:                 actions,
	}, nil
}

// ToCrossEntityCorrelationRule converts SigmaCorrelation to CrossEntityCorrelationRule.
func (sc *SigmaCorrelation) ToCrossEntityCorrelationRule(base EnhancedCorrelationRule, selection map[string]interface{}, actions []Action) (*CrossEntityCorrelationRule, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate type
	if sc.Type != "cross_entity" {
		return nil, fmt.Errorf("correlation type must be cross_entity, got: %s", sc.Type)
	}

	// Parse timespan
	window, err := sc.ParseDuration(sc.Timespan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timespan: %w", err)
	}

	// Convert condition to threshold
	threshold, err := sc.Condition.ToThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to convert condition: %w", err)
	}

	return &CrossEntityCorrelationRule{
		EnhancedCorrelationRule: base,
		Window:                  window,
		Selection:               selection,
		TrackField:              sc.TrackField,
		CountDistinct:           sc.CountDistinct,
		Threshold:               threshold,
		Actions:                 actions,
	}, nil
}

// ToEnhancedCorrelation converts SigmaCorrelation to the appropriate enhanced correlation rule type.
// This is a convenience method that dispatches to type-specific converters.
//
// Parameters:
//   - base: Base metadata (ID, name, description, etc.)
//   - selection: Event selection criteria
//   - metricField: Field for statistical analysis (only used for statistical type)
//   - actions: Actions to execute when correlation triggers
//
// Returns the appropriate correlation rule type or error if conversion fails.
func (sc *SigmaCorrelation) ToEnhancedCorrelation(
	base EnhancedCorrelationRule,
	selection map[string]interface{},
	metricField string,
	actions []Action,
) (interface{}, error) {
	if sc == nil {
		return nil, fmt.Errorf("correlation is nil")
	}

	// Validate before conversion
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	switch sc.Type {
	case "event_count", "count":
		return sc.ToCountCorrelationRule(base, selection, actions)

	case "value_count":
		return sc.ToValueCountCorrelationRule(base, selection, actions)

	case "sequence":
		// Convert event references to stages
		stages := make([]SequenceStage, len(sc.Events))
		for i, event := range sc.Events {
			stages[i] = SequenceStage{
				Name:      event,
				Selection: selection,
				Required:  true,
			}
		}
		return sc.ToSequenceCorrelationRule(base, stages, actions)

	case "rare":
		return sc.ToRareCorrelationRule(base, selection, actions)

	case "statistical":
		return sc.ToStatisticalCorrelationRule(base, selection, metricField, actions)

	case "chain":
		// Stages already defined in sc.Stages
		return sc.ToChainCorrelationRule(base, nil, actions)

	case "cross_entity":
		return sc.ToCrossEntityCorrelationRule(base, selection, actions)

	case "temporal":
		// Temporal is a special case that maps to SequenceCorrelationRule
		// with time-based constraints. Create a copy to avoid race conditions.
		tempSc := *sc // Copy struct to prevent mutation
		tempSc.Type = "sequence"
		stages := make([]SequenceStage, len(tempSc.Events))
		for i, event := range tempSc.Events {
			stages[i] = SequenceStage{
				Name:      event,
				Selection: selection,
				Required:  true,
			}
		}
		return tempSc.ToSequenceCorrelationRule(base, stages, actions)

	default:
		return nil, fmt.Errorf("unsupported correlation type: %s", sc.Type)
	}
}
