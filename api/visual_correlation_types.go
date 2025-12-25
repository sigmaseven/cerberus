package api

// Visual Correlation Builder Types
// Implements the API contract from VISUAL_BUILDER_BACKEND_INTEGRATION.md

// CorrelationType represents the correlation rule type
type CorrelationType string

const (
	CorrelationTypeCount       CorrelationType = "count"
	CorrelationTypeValueCount  CorrelationType = "value_count"
	CorrelationTypeSequence    CorrelationType = "sequence"
	CorrelationTypeRare        CorrelationType = "rare"
	CorrelationTypeStatistical CorrelationType = "statistical"
	CorrelationTypeCrossEntity CorrelationType = "cross_entity"
	CorrelationTypeChain       CorrelationType = "chain"
)

// TimeUnit represents time duration units
type TimeUnit string

const (
	TimeUnitSeconds TimeUnit = "seconds"
	TimeUnitMinutes TimeUnit = "minutes"
	TimeUnitHours   TimeUnit = "hours"
	TimeUnitDays    TimeUnit = "days"
)

// EntityCorrelationMode represents how entities are correlated across steps
type EntityCorrelationMode string

const (
	EntityModeSameHost          EntityCorrelationMode = "same_host"
	EntityModeSameUser          EntityCorrelationMode = "same_user"
	EntityModeSameSourceIP      EntityCorrelationMode = "same_source_ip"
	EntityModeSameDestinationIP EntityCorrelationMode = "same_destination_ip"
	EntityModeAny               EntityCorrelationMode = "any"
)

// StatisticalAggregation represents aggregation functions for statistical correlations
type StatisticalAggregation string

const (
	AggregationAvg   StatisticalAggregation = "avg"
	AggregationSum   StatisticalAggregation = "sum"
	AggregationMin   StatisticalAggregation = "min"
	AggregationMax   StatisticalAggregation = "max"
	AggregationCount StatisticalAggregation = "count"
)

// CorrelationCreateRequest represents the request to create a visual correlation rule
type CorrelationCreateRequest struct {
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              CorrelationType        `json:"type"`
	Config            map[string]interface{} `json:"config"`
	Severity          string                 `json:"severity"`
	Tags              []string               `json:"tags,omitempty"`
	Enabled           *bool                  `json:"enabled,omitempty"`
	MitreTechniqueIds []string               `json:"mitreTechniqueIds,omitempty"`
}

// CorrelationUpdateRequest represents the request to update a visual correlation rule
type CorrelationUpdateRequest struct {
	Name              *string                `json:"name,omitempty"`
	Description       *string                `json:"description,omitempty"`
	Type              *CorrelationType       `json:"type,omitempty"`
	Config            map[string]interface{} `json:"config,omitempty"`
	Severity          *string                `json:"severity,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	Enabled           *bool                  `json:"enabled,omitempty"`
	MitreTechniqueIds []string               `json:"mitreTechniqueIds,omitempty"`
}

// CqlQuery represents a CQL query with validation metadata
type CqlQuery struct {
	Query           string   `json:"query"`
	ParsedFields    []string `json:"parsedFields,omitempty"`
	IsValid         *bool    `json:"isValid,omitempty"`
	ValidationError string   `json:"validationError,omitempty"`
}

// TimeWindow represents a duration with unit
type TimeWindow struct {
	Value int      `json:"value"`
	Unit  TimeUnit `json:"unit"`
}

// CountCorrelationConfig represents COUNT correlation configuration
type CountCorrelationConfig struct {
	Type         CorrelationType `json:"type"`
	BaseQuery    CqlQuery        `json:"baseQuery"`
	Threshold    int             `json:"threshold"`
	TimeWindow   TimeWindow      `json:"timeWindow"`
	GroupBy      []string        `json:"groupBy"`
	MaxThreshold *int            `json:"maxThreshold,omitempty"`
}

// ValueCountCorrelationConfig represents VALUE_COUNT correlation configuration
type ValueCountCorrelationConfig struct {
	Type              CorrelationType `json:"type"`
	BaseQuery         CqlQuery        `json:"baseQuery"`
	CountField        string          `json:"countField"`
	DistinctThreshold int             `json:"distinctThreshold"`
	TimeWindow        TimeWindow      `json:"timeWindow"`
	GroupBy           []string        `json:"groupBy"`
}

// SequenceStep represents a step in a sequence correlation
type SequenceStep struct {
	Order               int         `json:"order"`
	Name                string      `json:"name"`
	Query               CqlQuery    `json:"query"`
	MaxTimeFromPrevious *TimeWindow `json:"maxTimeFromPrevious,omitempty"`
}

// SequenceCorrelationConfig represents SEQUENCE correlation configuration
type SequenceCorrelationConfig struct {
	Type              CorrelationType       `json:"type"`
	Steps             []SequenceStep        `json:"steps"`
	EntityCorrelation EntityCorrelationMode `json:"entityCorrelation"`
	MaxTotalWindow    TimeWindow            `json:"maxTotalWindow"`
	StrictOrder       bool                  `json:"strictOrder"`
}

// RareCorrelationConfig represents RARE correlation configuration
type RareCorrelationConfig struct {
	Type             CorrelationType `json:"type"`
	BaseQuery        CqlQuery        `json:"baseQuery"`
	RarityField      string          `json:"rarityField"`
	BaselinePeriod   TimeWindow      `json:"baselinePeriod"`
	RarityThreshold  float64         `json:"rarityThreshold"` // 0-100 percentage
	MinBaselineCount int             `json:"minBaselineCount"`
	GroupBy          []string        `json:"groupBy"`
}

// StatisticalCorrelationConfig represents STATISTICAL correlation configuration
type StatisticalCorrelationConfig struct {
	Type            CorrelationType        `json:"type"`
	BaseQuery       CqlQuery               `json:"baseQuery"`
	MetricField     string                 `json:"metricField"`
	Aggregation     StatisticalAggregation `json:"aggregation"`
	BaselinePeriod  TimeWindow             `json:"baselinePeriod"`
	DetectionWindow TimeWindow             `json:"detectionWindow"`
	StdDevThreshold float64                `json:"stdDevThreshold"`
	GroupBy         []string               `json:"groupBy"`
	MinSampleSize   *int                   `json:"minSampleSize,omitempty"`
}

// EntityMapping represents field mapping between source and target entities
type EntityMapping struct {
	SourceField string `json:"sourceField"`
	TargetField string `json:"targetField"`
}

// CrossEntityCorrelationConfig represents CROSS_ENTITY correlation configuration
type CrossEntityCorrelationConfig struct {
	Type           CorrelationType `json:"type"`
	SourceQuery    CqlQuery        `json:"sourceQuery"`
	TargetQuery    CqlQuery        `json:"targetQuery"`
	EntityMappings []EntityMapping `json:"entityMappings"`
	TimeWindow     TimeWindow      `json:"timeWindow"`
	MinSourceCount int             `json:"minSourceCount"`
	MinTargetCount int             `json:"minTargetCount"`
}

// ChainStep represents a step in a chain correlation
type ChainStep struct {
	ID         string      `json:"id"`
	Order      int         `json:"order"`
	RuleID     string      `json:"ruleId"`     // UUID - must reference existing rule
	RuleName   string      `json:"ruleName,omitempty"`
	TimeWindow *TimeWindow `json:"timeWindow,omitempty"` // Time until NEXT step
	IsRequired bool        `json:"isRequired"`
}

// AlertTemplateVariable represents a variable in alert templates
type AlertTemplateVariable struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default,omitempty"`
}

// ConditionalBranch represents conditional branching in chain correlations
type ConditionalBranch struct {
	Condition string   `json:"condition"`
	NextSteps []string `json:"nextSteps"`
}

// ChainCorrelationConfig represents CHAIN correlation configuration
type ChainCorrelationConfig struct {
	Type                 CorrelationType         `json:"type"`
	Steps                []ChainStep             `json:"steps,omitempty"`
	EntityCorrelation    EntityCorrelationMode   `json:"entityCorrelation,omitempty"`
	MaxTotalWindow       *TimeWindow             `json:"maxTotalWindow,omitempty"`
	MinStepsRequired     *int                    `json:"minStepsRequired,omitempty"`
	AlertTemplate        string                  `json:"alertTemplate,omitempty"`
	TemplateVariables    []AlertTemplateVariable `json:"templateVariables,omitempty"`
	ConditionalBranches  []ConditionalBranch     `json:"conditionalBranches,omitempty"`
}

// VisualCorrelationResponse represents the API response format
type VisualCorrelationResponse struct {
	Success bool                   `json:"success"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Details *ValidationErrorDetail `json:"details,omitempty"`
}

// ValidationErrorDetail represents detailed validation error information
type ValidationErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ToNanoseconds converts a TimeWindow to nanoseconds
func (tw TimeWindow) ToNanoseconds() int64 {
	var multiplier int64
	switch tw.Unit {
	case TimeUnitSeconds:
		multiplier = 1e9
	case TimeUnitMinutes:
		multiplier = 60 * 1e9
	case TimeUnitHours:
		multiplier = 3600 * 1e9
	case TimeUnitDays:
		multiplier = 86400 * 1e9
	default:
		multiplier = 1e9 // default to seconds
	}
	return int64(tw.Value) * multiplier
}

// ToDurationString converts a TimeWindow to a duration string (e.g., "5m", "1h")
func (tw TimeWindow) ToDurationString() string {
	switch tw.Unit {
	case TimeUnitSeconds:
		return string(rune(tw.Value)) + "s"
	case TimeUnitMinutes:
		return string(rune(tw.Value)) + "m"
	case TimeUnitHours:
		return string(rune(tw.Value)) + "h"
	case TimeUnitDays:
		return string(rune(tw.Value)) + "d"
	default:
		return string(rune(tw.Value)) + "s"
	}
}
