package core

import (
	"fmt"
	"time"
)

// CQLRule represents a detection rule defined using CQL query syntax
type CQLRule struct {
	ID             string             `json:"id" bson:"_id,omitempty"`
	Name           string             `json:"name" bson:"name"`
	Description    string             `json:"description" bson:"description"`
	Query          string             `json:"query" bson:"query"`                                 // CQL query string
	Correlation    *CorrelationConfig `json:"correlation,omitempty" bson:"correlation,omitempty"` // Optional correlation
	Severity       string             `json:"severity" bson:"severity"`                           // low, medium, high, critical
	Enabled        bool               `json:"enabled" bson:"enabled"`
	Tags           []string           `json:"tags,omitempty" bson:"tags,omitempty"`
	MITRE          []string           `json:"mitre,omitempty" bson:"mitre,omitempty"`     // MITRE ATT&CK technique IDs
	Actions        []string           `json:"actions,omitempty" bson:"actions,omitempty"` // Action IDs to trigger
	Metadata       map[string]string  `json:"metadata,omitempty" bson:"metadata,omitempty"`
	CreatedAt      time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at" bson:"updated_at"`
	Author         string             `json:"author,omitempty" bson:"author,omitempty"`
	References     []string           `json:"references,omitempty" bson:"references,omitempty"`
	FalsePositives string             `json:"false_positives,omitempty" bson:"false_positives,omitempty"`
}

// CorrelationConfig defines correlation settings for CQL rules
type CorrelationConfig struct {
	Timeframe   int         `json:"timeframe" bson:"timeframe"`                   // Time window in seconds
	GroupBy     []string    `json:"group_by,omitempty" bson:"group_by,omitempty"` // Fields to group by
	Aggregation string      `json:"aggregation" bson:"aggregation"`               // count, sum, avg, min, max, distinct
	Field       string      `json:"field,omitempty" bson:"field,omitempty"`       // Field for aggregation (if needed)
	Threshold   interface{} `json:"threshold" bson:"threshold"`                   // Threshold value
	Operator    string      `json:"operator" bson:"operator"`                     // >, <, >=, <=, ==, !=
}

// CorrelationConfig is now defined in core/rule.go
// This file will be deprecated as CQL rules are now unified with SIGMA rules in core.Rule

// CQLRuleMatch represents a match result for a CQL rule
type CQLRuleMatch struct {
	Rule          *CQLRule
	Event         *Event
	Timestamp     time.Time
	MatchedFields map[string]interface{} // Fields that matched the query
}

// Validate validates the CQL rule
func (r *CQLRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Query == "" {
		return fmt.Errorf("rule query is required")
	}
	if r.Severity != "low" && r.Severity != "medium" && r.Severity != "high" && r.Severity != "critical" {
		return fmt.Errorf("invalid severity: %s", r.Severity)
	}
	return nil
}

// GetID returns the CQL rule ID
func (r *CQLRule) GetID() string {
	return r.ID
}

// GetName returns the CQL rule name
func (r *CQLRule) GetName() string {
	return r.Name
}

// GetDescription returns the CQL rule description
func (r *CQLRule) GetDescription() string {
	return r.Description
}

// GetSeverity returns the CQL rule severity
func (r *CQLRule) GetSeverity() string {
	return r.Severity
}

// GetActions returns the CQL rule actions as Action objects
func (r *CQLRule) GetActions() []Action {
	// CQLRule stores action IDs as strings, not Action objects
	// Return empty slice as CQL rules are handled differently
	return nil
}

// ToAlert converts a CQL rule match to an alert
// Returns error if the event is nil or if alert creation fails
func (m *CQLRuleMatch) ToAlert() (*Alert, error) {
	// Security: Check for nil event to prevent nil pointer dereference
	if m.Event == nil {
		return nil, fmt.Errorf("failed to convert CQL match to alert: event is nil")
	}

	alert, err := NewAlert(m.Rule.ID, m.Event.EventID, m.Rule.Severity, m.Event)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CQL match to alert: %w", err)
	}
	alert.RuleName = m.Rule.Name
	alert.RuleDescription = m.Rule.Description
	alert.RuleType = "cql"
	alert.MitreTechniques = m.Rule.MITRE
	return alert, nil
}
