# Task ID: 165

**Title:** Define SIGMA Correlation YAML Specification in Core

**Status:** done

**Dependencies:** 164 ✓

**Priority:** high

**Description:** Extend core package with SIGMA-compatible correlation rule structures that map to the 7 enhanced correlation types

**Details:**

Implementation: Create core/sigma_correlation.go with:

type SigmaCorrelation struct {
    Type           string            `yaml:"type" json:"type"` // event_count, value_count, sequence, rare, statistical, cross_entity, chain
    GroupBy        []string          `yaml:"group_by" json:"group_by"`
    Timespan       string            `yaml:"timespan" json:"timespan"` // Duration string (e.g., "5m")
    Condition      *CorrelationCond  `yaml:"condition,omitempty" json:"condition,omitempty"`
    Ordered        bool              `yaml:"ordered,omitempty" json:"ordered,omitempty"`
    Events         []string          `yaml:"events,omitempty" json:"events,omitempty"`
    DistinctField  string            `yaml:"distinct_field,omitempty" json:"distinct_field,omitempty"`
    BaselineWindow string            `yaml:"baseline_window,omitempty" json:"baseline_window,omitempty"`
    StdDevThreshold float64          `yaml:"std_dev_threshold,omitempty" json:"std_dev_threshold,omitempty"`
    Stages         []ChainStage      `yaml:"stages,omitempty" json:"stages,omitempty"`
    TrackField     string            `yaml:"track_field,omitempty" json:"track_field,omitempty"`
    CountDistinct  string            `yaml:"count_distinct,omitempty" json:"count_distinct,omitempty"`
    MinStages      int               `yaml:"min_stages,omitempty" json:"min_stages,omitempty"`
    MaxDuration    string            `yaml:"max_duration,omitempty" json:"max_duration,omitempty"`
}

type CorrelationCond struct {
    Field    string      `yaml:"field" json:"field"`
    Operator string      `yaml:"operator" json:"operator"` // >=, >, <, <=, ==, !=, std_dev
    Value    interface{} `yaml:"value" json:"value"`
}

Extend Rule struct:
- Correlation *SigmaCorrelation `yaml:"correlation,omitempty" json:"correlation,omitempty"`

Add validation methods to ensure correlation types map correctly to enhanced correlation rules.

**Test Strategy:**

Create core/sigma_correlation_test.go:
1. Test YAML parsing of all 7 correlation types
2. Verify field mapping to enhanced correlation types
3. Test validation of required fields per type
4. Test conversion helpers (ToEnhancedCorrelation)
5. Test round-trip YAML serialization
6. Test error handling for invalid correlation configs

## Subtasks

### 165.1. Define SigmaCorrelation struct with all 7 correlation types and their specific fields

**Status:** pending  
**Dependencies:** None  

Create core/sigma_correlation.go and define the comprehensive SigmaCorrelation struct that supports all 7 enhanced correlation types (event_count, value_count, sequence, rare, statistical, cross_entity, chain) with proper YAML and JSON tags

**Details:**

Implement the complete SigmaCorrelation struct with all fields: Type, GroupBy, Timespan, Condition, Ordered, Events, DistinctField, BaselineWindow, StdDevThreshold, Stages, TrackField, CountDistinct, MinStages, MaxDuration. Include the CorrelationCond struct for condition specifications and ChainStage struct for chain-type correlations. Ensure all fields have appropriate yaml and json tags for serialization. Add comprehensive documentation comments explaining each field's purpose and which correlation types use them.

### 165.2. Extend core.Rule struct with Correlation field

**Status:** pending  
**Dependencies:** 165.1  

Modify the existing core.Rule struct in core/rule.go to include the new Correlation field that references the SigmaCorrelation struct

**Details:**

Add the Correlation field to core.Rule struct with signature: `Correlation *SigmaCorrelation yaml:"correlation,omitempty" json:"correlation,omitempty"`. Use pointer type to allow nil values for non-correlation rules. Ensure the field integrates properly with existing Rule validation and serialization logic. Update any related Rule constructor or factory functions to handle the new field. Verify backward compatibility with existing rule definitions.

### 165.3. Implement validation methods that map correlation types to enhanced correlation rules

**Status:** pending  
**Dependencies:** 165.1, 165.2  

Create validation functions in core/sigma_correlation.go that verify correlation rule integrity and ensure proper mapping to the 7 enhanced correlation types defined in core/correlation.go

**Details:**

Implement Validate() method on SigmaCorrelation that checks: 1) Type field matches one of the 7 valid correlation types, 2) Required fields are present for each correlation type (e.g., event_count requires Condition, sequence requires Events and Ordered, statistical requires BaselineWindow and StdDevThreshold), 3) GroupBy and Timespan are properly formatted, 4) Condition operators are valid (>=, >, <, <=, ==, !=, std_dev), 5) Duration strings are parseable. Create helper function ValidateCorrelationType() that maps each SIGMA type to its corresponding enhanced correlation rule structure and validates type-specific constraints.

### 165.4. Add conversion helpers (ToEnhancedCorrelation) with comprehensive error handling

**Status:** pending  
**Dependencies:** 165.1, 165.2, 165.3  

Implement conversion functions that transform SigmaCorrelation structs into their corresponding enhanced correlation rule types from core/correlation.go with robust error handling

**Details:**

Create ToEnhancedCorrelation() method on SigmaCorrelation that returns the appropriate enhanced correlation type (EventCountCorrelation, ValueCountCorrelation, SequenceCorrelation, RareEventCorrelation, StatisticalCorrelation, CrossEntityCorrelation, or ChainCorrelation) based on the Type field. Implement type-specific conversion logic for each of the 7 correlation types, parsing duration strings into time.Duration, converting condition operators, and mapping all relevant fields. Add comprehensive error handling for invalid conversions, missing required fields, parsing failures, and type mismatches. Include helper functions like parseDuration(), parseCondition(), and parseChainStages(). Ensure the conversion is lossless where possible and document any limitations.
