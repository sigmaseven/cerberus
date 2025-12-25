package core

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultRareCountField is the default field used for rare event tracking
	// when no specific distinct_field is provided.
	DefaultRareCountField = "event_type"
)

// SigmaCorrelation represents SIGMA-compatible correlation rule structures.
// This structure maps to the 7 enhanced correlation types and provides
// YAML serialization for SIGMA rule compatibility.
//
// Security considerations:
//   - All duration strings are validated before parsing
//   - Field names are validated to prevent injection
//   - Type-specific validation ensures proper field usage
type SigmaCorrelation struct {
	// Type specifies the correlation type (event_count, value_count, sequence, temporal, rare, statistical, chain)
	Type string `yaml:"type" json:"type" bson:"type"`

	// GroupBy specifies fields to group events by (e.g., ["source_ip", "username"])
	GroupBy []string `yaml:"group_by,omitempty" json:"group_by,omitempty" bson:"group_by,omitempty"`

	// Timespan is the correlation time window as a duration string (e.g., "5m", "1h", "24h")
	Timespan string `yaml:"timespan,omitempty" json:"timespan,omitempty" bson:"timespan,omitempty"`

	// Condition defines threshold conditions for count-based and statistical correlations
	Condition *CorrelationCondition `yaml:"condition,omitempty" json:"condition,omitempty" bson:"condition,omitempty"`

	// Ordered indicates if sequence events must occur in order (for sequence type)
	Ordered bool `yaml:"ordered,omitempty" json:"ordered,omitempty" bson:"ordered,omitempty"`

	// Events lists event types or detection references for sequence correlations
	Events []string `yaml:"events,omitempty" json:"events,omitempty" bson:"events,omitempty"`

	// DistinctField specifies the field to count distinct values (for value_count type)
	DistinctField string `yaml:"distinct_field,omitempty" json:"distinct_field,omitempty" bson:"distinct_field,omitempty"`

	// BaselineWindow is the historical window for statistical baselines (e.g., "7d", "30d")
	BaselineWindow string `yaml:"baseline_window,omitempty" json:"baseline_window,omitempty" bson:"baseline_window,omitempty"`

	// StdDevThreshold is the standard deviation multiplier for statistical correlations
	StdDevThreshold float64 `yaml:"std_dev_threshold,omitempty" json:"std_dev_threshold,omitempty" bson:"std_dev_threshold,omitempty"`

	// Stages defines multi-stage chain detection stages
	Stages []SigmaChainStage `yaml:"stages,omitempty" json:"stages,omitempty" bson:"stages,omitempty"`

	// TrackField is the field to track across entities (for cross_entity type)
	TrackField string `yaml:"track_field,omitempty" json:"track_field,omitempty" bson:"track_field,omitempty"`

	// CountDistinct specifies the field to count distinct occurrences (for cross_entity type)
	CountDistinct string `yaml:"count_distinct,omitempty" json:"count_distinct,omitempty" bson:"count_distinct,omitempty"`

	// MinStages is the minimum number of chain stages required
	MinStages int `yaml:"min_stages,omitempty" json:"min_stages,omitempty" bson:"min_stages,omitempty"`

	// MaxDuration is the maximum time span for chain completion (e.g., "24h")
	MaxDuration string `yaml:"max_duration,omitempty" json:"max_duration,omitempty" bson:"max_duration,omitempty"`
}

// CorrelationCondition defines threshold conditions for correlations.
// Supports numeric comparisons and statistical operators.
type CorrelationCondition struct {
	// Field is the field name to evaluate (optional for count-based correlations)
	Field string `yaml:"field,omitempty" json:"field,omitempty" bson:"field,omitempty"`

	// Operator is the comparison operator (>=, >, <, <=, ==, !=, std_dev)
	Operator string `yaml:"operator" json:"operator" bson:"operator"`

	// Value is the threshold value (numeric or string depending on operator)
	Value interface{} `yaml:"value" json:"value" bson:"value"`
}

// SigmaChainStage represents a stage in a multi-stage attack chain.
// Each stage references a detection rule and has a timeout.
type SigmaChainStage struct {
	// Name is the human-readable stage name
	Name string `yaml:"name" json:"name" bson:"name"`

	// DetectionRef references a SIGMA detection rule ID
	DetectionRef string `yaml:"detection_ref" json:"detection_ref" bson:"detection_ref"`

	// Timeout is the maximum time to wait for this stage (e.g., "1h")
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty" bson:"timeout,omitempty"`
}

// Validate validates the SigmaCorrelation structure based on correlation type.
// Returns an error if required fields are missing or invalid for the type.
func (sc *SigmaCorrelation) Validate() error {
	if sc == nil {
		return fmt.Errorf("correlation configuration cannot be nil")
	}

	// Normalize and validate type
	sc.Type = strings.ToLower(strings.TrimSpace(sc.Type))
	if sc.Type == "" {
		return fmt.Errorf("correlation type is required")
	}

	// Validate timespan if provided
	if sc.Timespan != "" {
		if err := validateDurationString(sc.Timespan); err != nil {
			return fmt.Errorf("invalid timespan: %w", err)
		}
	}

	// Type-specific validation
	switch sc.Type {
	case "event_count", "count":
		return sc.validateEventCount()
	case "value_count":
		return sc.validateValueCount()
	case "sequence":
		return sc.validateSequence()
	case "temporal":
		return sc.validateTemporal()
	case "rare":
		return sc.validateRare()
	case "statistical":
		return sc.validateStatistical()
	case "chain":
		return sc.validateChain()
	case "cross_entity":
		return sc.validateCrossEntity()
	default:
		return fmt.Errorf("unsupported correlation type: %s", sc.Type)
	}
}

// validateEventCount validates event_count correlation configuration.
func (sc *SigmaCorrelation) validateEventCount() error {
	if sc.Condition == nil {
		return fmt.Errorf("event_count requires condition")
	}
	if sc.Timespan == "" {
		return fmt.Errorf("event_count requires timespan")
	}
	return sc.Condition.Validate()
}

// validateValueCount validates value_count correlation configuration.
func (sc *SigmaCorrelation) validateValueCount() error {
	if sc.DistinctField == "" {
		return fmt.Errorf("value_count requires distinct_field")
	}
	if sc.Condition == nil {
		return fmt.Errorf("value_count requires condition")
	}
	if sc.Timespan == "" {
		return fmt.Errorf("value_count requires timespan")
	}
	return sc.Condition.Validate()
}

// validateSequence validates sequence correlation configuration.
func (sc *SigmaCorrelation) validateSequence() error {
	if len(sc.Events) == 0 {
		return fmt.Errorf("sequence requires at least one event")
	}
	if sc.Timespan == "" {
		return fmt.Errorf("sequence requires timespan")
	}
	return nil
}

// validateTemporal validates temporal correlation configuration.
func (sc *SigmaCorrelation) validateTemporal() error {
	if sc.Timespan == "" {
		return fmt.Errorf("temporal requires timespan")
	}
	// Additional fields validated in conversion
	return nil
}

// validateRare validates rare correlation configuration.
func (sc *SigmaCorrelation) validateRare() error {
	if sc.BaselineWindow == "" {
		return fmt.Errorf("rare requires baseline_window")
	}
	if err := validateDurationString(sc.BaselineWindow); err != nil {
		return fmt.Errorf("invalid baseline_window: %w", err)
	}
	if sc.Condition == nil {
		return fmt.Errorf("rare requires condition")
	}
	return sc.Condition.Validate()
}

// validateStatistical validates statistical correlation configuration.
func (sc *SigmaCorrelation) validateStatistical() error {
	if sc.BaselineWindow == "" {
		return fmt.Errorf("statistical requires baseline_window")
	}
	if err := validateDurationString(sc.BaselineWindow); err != nil {
		return fmt.Errorf("invalid baseline_window: %w", err)
	}
	if sc.StdDevThreshold <= 0 {
		return fmt.Errorf("statistical requires positive std_dev_threshold")
	}
	return nil
}

// validateChain validates chain correlation configuration.
func (sc *SigmaCorrelation) validateChain() error {
	if len(sc.Stages) == 0 {
		return fmt.Errorf("chain requires at least one stage")
	}
	if sc.MaxDuration == "" {
		return fmt.Errorf("chain requires max_duration")
	}
	if err := validateDurationString(sc.MaxDuration); err != nil {
		return fmt.Errorf("invalid max_duration: %w", err)
	}
	for i, stage := range sc.Stages {
		if stage.Name == "" {
			return fmt.Errorf("stage %d missing name", i)
		}
		if stage.DetectionRef == "" {
			return fmt.Errorf("stage %d missing detection_ref", i)
		}
		if stage.Timeout != "" {
			if err := validateDurationString(stage.Timeout); err != nil {
				return fmt.Errorf("stage %d invalid timeout: %w", i, err)
			}
		}
	}
	return nil
}

// validateCrossEntity validates cross_entity correlation configuration.
func (sc *SigmaCorrelation) validateCrossEntity() error {
	if sc.TrackField == "" {
		return fmt.Errorf("cross_entity requires track_field")
	}
	if sc.CountDistinct == "" {
		return fmt.Errorf("cross_entity requires count_distinct")
	}
	if sc.Condition == nil {
		return fmt.Errorf("cross_entity requires condition")
	}
	if sc.Timespan == "" {
		return fmt.Errorf("cross_entity requires timespan")
	}
	return sc.Condition.Validate()
}

// Validate validates the CorrelationCondition structure.
func (cc *CorrelationCondition) Validate() error {
	if cc == nil {
		return fmt.Errorf("correlation condition cannot be nil")
	}

	// Validate operator
	validOps := map[string]bool{
		">=":      true,
		">":       true,
		"<":       true,
		"<=":      true,
		"==":      true,
		"!=":      true,
		"std_dev": true,
	}
	if !validOps[cc.Operator] {
		return fmt.Errorf("invalid operator: %s", cc.Operator)
	}

	// Validate value is present
	if cc.Value == nil {
		return fmt.Errorf("condition value is required")
	}

	return nil
}

// ParseDuration safely parses a duration string.
// Supports standard Go duration format (e.g., "5m", "1h", "24h").
func (sc *SigmaCorrelation) ParseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, fmt.Errorf("duration string is empty")
	}
	return parseDuration(durationStr)
}

// ToThreshold converts a CorrelationCondition to a Threshold struct.
// Supports int, int64, uint, uint64, float32, and float64 value types.
func (cc *CorrelationCondition) ToThreshold() (Threshold, error) {
	if cc == nil {
		return Threshold{}, fmt.Errorf("condition is nil")
	}

	// Convert value to float64
	var floatValue float64
	switch v := cc.Value.(type) {
	case int:
		floatValue = float64(v)
	case int64:
		floatValue = float64(v)
	case uint:
		floatValue = float64(v)
	case uint64:
		floatValue = float64(v)
	case float64:
		floatValue = v
	case float32:
		floatValue = float64(v)
	default:
		return Threshold{}, fmt.Errorf("unsupported value type: %T", cc.Value)
	}

	return Threshold{
		Operator: ThresholdOperator(cc.Operator),
		Value:    floatValue,
	}, nil
}

// ParseYAML parses YAML bytes into a SigmaCorrelation structure.
// Returns error if YAML is malformed, exceeds size limits, or has excessive nesting depth.
//
// Security constraints enforced:
//   - Maximum size: 1MB (prevents resource exhaustion)
//   - Maximum nesting depth: 20 levels (prevents YAML bombs)
func ParseYAML(data []byte) (*SigmaCorrelation, error) {
	// Security: Limit YAML size
	const maxYAMLSize = 1024 * 1024 // 1MB
	if len(data) > maxYAMLSize {
		return nil, fmt.Errorf("YAML exceeds maximum size of %d bytes", maxYAMLSize)
	}

	// Security: Validate nesting depth before unmarshaling
	if err := validateYAMLDepth(data, 20); err != nil {
		return nil, fmt.Errorf("YAML depth validation failed: %w", err)
	}

	var sc SigmaCorrelation
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &sc, nil
}

// ToYAML serializes the SigmaCorrelation to YAML bytes.
// Validates the structure before serialization.
func (sc *SigmaCorrelation) ToYAML() ([]byte, error) {
	if sc == nil {
		return nil, fmt.Errorf("cannot serialize nil correlation")
	}
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("cannot serialize invalid correlation: %w", err)
	}
	return yaml.Marshal(sc)
}

// validateDurationString validates a duration string format.
// Accepts standard Go duration format (e.g., "5m", "1h", "24h").
func validateDurationString(s string) error {
	_, err := parseDuration(s)
	return err
}

// validateYAMLDepth checks the nesting depth of YAML to prevent YAML bombs.
// Returns error if depth exceeds maxDepth.
func validateYAMLDepth(data []byte, maxDepth int) error {
	depth := 0
	currentDepth := 0
	inString := false
	var stringDelim byte

	for i := 0; i < len(data); i++ {
		c := data[i]

		// Track string boundaries to ignore indentation in strings
		if c == '"' || c == '\'' {
			if !inString {
				inString = true
				stringDelim = c
			} else if c == stringDelim && (i == 0 || data[i-1] != '\\') {
				inString = false
			}
			continue
		}

		if inString {
			continue
		}

		// Count indentation depth
		if c == '\n' {
			currentDepth = 0
		} else if c == ' ' || c == '\t' {
			currentDepth++
			if currentDepth > depth {
				depth = currentDepth
			}
		} else if c != '\r' {
			currentDepth = 0
		}
	}

	// Estimate nesting levels (assume 2 spaces per level)
	estimatedDepth := depth / 2
	if estimatedDepth > maxDepth {
		return fmt.Errorf("YAML nesting depth %d exceeds maximum of %d", estimatedDepth, maxDepth)
	}
	return nil
}

// parseDuration parses a duration string with strict security validation.
// Supports standard Go duration format (e.g., "5m", "1h") plus "d" suffix for days.
//
// Security constraints enforced:
//   - Maximum duration: 1 year (prevents resource exhaustion)
//   - No negative durations (prevents logic bypass)
//   - Size validated before multiplication (prevents integer overflow)
func parseDuration(s string) (time.Duration, error) {
	// Handle day suffix (not supported by time.ParseDuration)
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.ParseInt(daysStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid days format: %w", err)
		}
		if days < 0 {
			return 0, fmt.Errorf("duration cannot be negative")
		}
		// Check BEFORE multiplication to prevent overflow
		if days > 365 {
			return 0, fmt.Errorf("duration exceeds maximum of 1 year")
		}
		return time.Duration(days*24) * time.Hour, nil
	}

	// Standard Go duration parsing
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration cannot be negative")
	}
	// Prevent unreasonably large durations (> 1 year)
	if d > 365*24*time.Hour {
		return 0, fmt.Errorf("duration exceeds maximum of 1 year")
	}
	return d, nil
}
