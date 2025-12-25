package core

import (
	"time"
)

// CorrelationType defines the type of correlation rule
type CorrelationType string

const (
	// SIGMA-compatible correlation types
	CorrelationTypeCount      CorrelationType = "count"       // Count-based: event count exceeds threshold
	CorrelationTypeValueCount CorrelationType = "value_count" // Distinct value count
	CorrelationTypeSequence   CorrelationType = "sequence"    // Temporal sequence (enhanced)
	CorrelationTypeRare       CorrelationType = "rare"        // Rare event detection

	// Cerberus custom correlation types
	CorrelationTypeStatistical CorrelationType = "statistical"  // Statistical anomaly detection
	CorrelationTypeCrossEntity CorrelationType = "cross_entity" // Cross-entity correlation
	CorrelationTypeChain       CorrelationType = "chain"        // Multi-stage chain detection
)

// ThresholdOperator defines comparison operators for thresholds
type ThresholdOperator string

const (
	ThresholdOpGreater      ThresholdOperator = ">"
	ThresholdOpLess         ThresholdOperator = "<"
	ThresholdOpGreaterEqual ThresholdOperator = ">="
	ThresholdOpLessEqual    ThresholdOperator = "<="
	ThresholdOpEqual        ThresholdOperator = "=="
	ThresholdOpNotEqual     ThresholdOperator = "!="
	ThresholdOpStdDev       ThresholdOperator = "std_dev" // Standard deviation
)

// Threshold defines a threshold condition
type Threshold struct {
	Operator ThresholdOperator `json:"operator" bson:"operator" example:">"`
	Value    float64           `json:"value" bson:"value" example:"5"`
}

// EnhancedCorrelationRule is the base for all correlation rule types
type EnhancedCorrelationRule struct {
	ID          string          `json:"id" bson:"_id" example:"rule_123"`
	Type        CorrelationType `json:"type" bson:"type" example:"count"`
	Name        string          `json:"name" bson:"name" example:"Brute Force Detection"`
	Description string          `json:"description" bson:"description" example:"Detects multiple failed logins"`
	Severity    string          `json:"severity" bson:"severity" example:"High"`
	Enabled     bool            `json:"enabled" bson:"enabled" example:"true"`
	Tags        []string        `json:"tags,omitempty" bson:"tags,omitempty" example:"authentication,brute_force"`
	CreatedAt   time.Time       `json:"created_at" bson:"created_at" swaggertype:"string"`
	UpdatedAt   time.Time       `json:"updated_at" bson:"updated_at" swaggertype:"string"`
}

// CountCorrelationRule detects when event count exceeds threshold
type CountCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration          `json:"window" bson:"window" swaggertype:"string" example:"5m"`
	Selection               map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	GroupBy                 []string               `json:"group_by" bson:"group_by" example:"source_ip,username"`
	Threshold               Threshold              `json:"threshold" bson:"threshold"`
	Actions                 []Action               `json:"actions" bson:"actions"`
}

// ValueCountCorrelationRule detects when distinct values exceed threshold
type ValueCountCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration          `json:"window" bson:"window" swaggertype:"string" example:"10m"`
	Selection               map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	CountField              string                 `json:"count_field" bson:"count_field" example:"username"`
	GroupBy                 []string               `json:"group_by" bson:"group_by" example:"source_ip"`
	Threshold               Threshold              `json:"threshold" bson:"threshold"`
	Actions                 []Action               `json:"actions" bson:"actions"`
}

// SequenceStage represents a stage in a sequence
type SequenceStage struct {
	Name      string                 `json:"name" bson:"name" example:"login"`
	Selection map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	Required  bool                   `json:"required" bson:"required" example:"true"`
}

// SequenceCorrelationRule detects ordered or unordered event sequences
type SequenceCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration   `json:"window" bson:"window" swaggertype:"string" example:"1h"`
	Sequence                []SequenceStage `json:"sequence" bson:"sequence"`
	Ordered                 bool            `json:"ordered" bson:"ordered" example:"true"`
	GroupBy                 []string        `json:"group_by" bson:"group_by" example:"username"`
	MaxSpan                 time.Duration   `json:"max_span,omitempty" bson:"max_span,omitempty" swaggertype:"string" example:"1h"`
	Actions                 []Action        `json:"actions" bson:"actions"`
}

// RareCorrelationRule detects events that occur infrequently
type RareCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration          `json:"window" bson:"window" swaggertype:"string" example:"24h"`
	Selection               map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	CountField              string                 `json:"count_field" bson:"count_field" example:"process_name"`
	Threshold               Threshold              `json:"threshold" bson:"threshold"`
	Actions                 []Action               `json:"actions" bson:"actions"`
}

// StatisticalCorrelationRule detects statistical anomalies
type StatisticalCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration          `json:"window" bson:"window" swaggertype:"string" example:"1h"`
	BaselineWindow          time.Duration          `json:"baseline_window" bson:"baseline_window" swaggertype:"string" example:"7d"`
	Selection               map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	MetricField             string                 `json:"metric_field" bson:"metric_field" example:"bytes_sent"`
	GroupBy                 []string               `json:"group_by" bson:"group_by" example:"source_ip"`
	Threshold               Threshold              `json:"threshold" bson:"threshold"`
	Actions                 []Action               `json:"actions" bson:"actions"`
}

// CrossEntityCorrelationRule correlates events across different entities
type CrossEntityCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	Window                  time.Duration          `json:"window" bson:"window" swaggertype:"string" example:"15m"`
	Selection               map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	TrackField              string                 `json:"track_field" bson:"track_field" example:"username"`
	CountDistinct           string                 `json:"count_distinct" bson:"count_distinct" example:"dest_host"`
	Threshold               Threshold              `json:"threshold" bson:"threshold"`
	Actions                 []Action               `json:"actions" bson:"actions"`
}

// ChainStage represents a stage in a multi-stage attack chain
type ChainStage struct {
	Name      string                 `json:"name" bson:"name" example:"reconnaissance"`
	Selection map[string]interface{} `json:"selection" bson:"selection" swaggertype:"object"`
	Required  bool                   `json:"required" bson:"required" example:"true"`
}

// ChainCorrelationRule detects multi-stage attack chains
type ChainCorrelationRule struct {
	EnhancedCorrelationRule `bson:",inline"`
	MaxDuration             time.Duration `json:"max_duration" bson:"max_duration" swaggertype:"string" example:"24h"`
	Stages                  []ChainStage  `json:"stages" bson:"stages"`
	GroupBy                 []string      `json:"group_by" bson:"group_by" example:"source_ip,dest_ip"`
	MinStages               int           `json:"min_stages" bson:"min_stages" example:"2"`
	Actions                 []Action      `json:"actions" bson:"actions"`
}

// Implement AlertableRule interface for all correlation types

func (r CountCorrelationRule) GetID() string          { return r.ID }
func (r CountCorrelationRule) GetName() string        { return r.Name }
func (r CountCorrelationRule) GetDescription() string { return r.Description }
func (r CountCorrelationRule) GetSeverity() string    { return r.Severity }
func (r CountCorrelationRule) GetActions() []Action   { return r.Actions }

func (r ValueCountCorrelationRule) GetID() string          { return r.ID }
func (r ValueCountCorrelationRule) GetName() string        { return r.Name }
func (r ValueCountCorrelationRule) GetDescription() string { return r.Description }
func (r ValueCountCorrelationRule) GetSeverity() string    { return r.Severity }
func (r ValueCountCorrelationRule) GetActions() []Action   { return r.Actions }

func (r SequenceCorrelationRule) GetID() string          { return r.ID }
func (r SequenceCorrelationRule) GetName() string        { return r.Name }
func (r SequenceCorrelationRule) GetDescription() string { return r.Description }
func (r SequenceCorrelationRule) GetSeverity() string    { return r.Severity }
func (r SequenceCorrelationRule) GetActions() []Action   { return r.Actions }

func (r RareCorrelationRule) GetID() string          { return r.ID }
func (r RareCorrelationRule) GetName() string        { return r.Name }
func (r RareCorrelationRule) GetDescription() string { return r.Description }
func (r RareCorrelationRule) GetSeverity() string    { return r.Severity }
func (r RareCorrelationRule) GetActions() []Action   { return r.Actions }

func (r StatisticalCorrelationRule) GetID() string          { return r.ID }
func (r StatisticalCorrelationRule) GetName() string        { return r.Name }
func (r StatisticalCorrelationRule) GetDescription() string { return r.Description }
func (r StatisticalCorrelationRule) GetSeverity() string    { return r.Severity }
func (r StatisticalCorrelationRule) GetActions() []Action   { return r.Actions }

func (r CrossEntityCorrelationRule) GetID() string          { return r.ID }
func (r CrossEntityCorrelationRule) GetName() string        { return r.Name }
func (r CrossEntityCorrelationRule) GetDescription() string { return r.Description }
func (r CrossEntityCorrelationRule) GetSeverity() string    { return r.Severity }
func (r CrossEntityCorrelationRule) GetActions() []Action   { return r.Actions }

func (r ChainCorrelationRule) GetID() string          { return r.ID }
func (r ChainCorrelationRule) GetName() string        { return r.Name }
func (r ChainCorrelationRule) GetDescription() string { return r.Description }
func (r ChainCorrelationRule) GetSeverity() string    { return r.Severity }
func (r ChainCorrelationRule) GetActions() []Action   { return r.Actions }
