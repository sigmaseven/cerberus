package core

import (
	"regexp"
	"time"
)

// AlertableRule interface for rules that can generate alerts
type AlertableRule interface {
	GetID() string
	GetSeverity() string
	GetActions() []Action
}

// Rule represents a detection rule
type Rule struct {
	ID          string      `json:"id" bson:"_id" example:"failed_login"`
	Name        string      `json:"name" bson:"name" example:"Failed User Login"`
	Description string      `json:"description" bson:"description" example:"Detects multiple failed login attempts"`
	Severity    string      `json:"severity" bson:"severity" example:"Warning"`
	Version     int         `json:"version" bson:"version" example:"1"`
	Conditions  []Condition `json:"conditions" bson:"conditions"`
	Actions     []Action    `json:"actions" bson:"actions"`
	Enabled     bool        `json:"enabled" bson:"enabled" example:"true"`
}

// GetID returns the rule ID
func (r Rule) GetID() string {
	return r.ID
}

// GetSeverity returns the rule severity
func (r Rule) GetSeverity() string {
	return r.Severity
}

// GetActions returns the rule actions
func (r Rule) GetActions() []Action {
	return r.Actions
}

// Condition represents a match condition
type Condition struct {
	Field    string         `json:"field" bson:"field" example:"fields.status"`
	Operator string         `json:"operator" bson:"operator" example:"equals"` // equals, not_equals, contains, starts_with, ends_with, regex, greater_than, less_than, greater_than_or_equal, less_than_or_equal
	Value    interface{}    `json:"value" bson:"value" swaggertype:"string" example:"failure"`
	Logic    string         `json:"logic" bson:"logic" example:"AND"` // AND, OR (for combining conditions)
	Regex    *regexp.Regexp `json:"-"`                                // Compiled regex for regex operator
}

// Action represents an action to take on match (for Phase 3, but include)
type Action struct {
	ID     string                 `json:"id" bson:"_id" example:"action-123"`
	Type   string                 `json:"type" bson:"type" example:"webhook"` // webhook, jira, etc.
	Config map[string]interface{} `json:"config" bson:"config" swaggertype:"object"`
}

// Rules is a collection of rules
type Rules struct {
	Rules []Rule `json:"rules" bson:"rules"`
}

// CorrelationRules is a collection of correlation rules
type CorrelationRules struct {
	Rules []CorrelationRule `json:"rules" bson:"rules"`
}

// CorrelationRule for multi-event rules
type CorrelationRule struct {
	ID          string        `json:"id" bson:"_id" example:"correlation_rule_1"`
	Name        string        `json:"name" bson:"name" example:"Brute Force Detection"`
	Description string        `json:"description" bson:"description" example:"Detects multiple failed logins"`
	Severity    string        `json:"severity" bson:"severity" example:"High"`
	Version     int           `json:"version" bson:"version" example:"1"`
	Window      time.Duration `json:"window" bson:"window" swaggertype:"integer" example:"300000000000"` // time window for correlation in nanoseconds
	Conditions  []Condition   `json:"conditions" bson:"conditions"`
	Sequence    []string      `json:"sequence" bson:"sequence" example:"user_login,user_login,user_login"` // sequence of event types
	Actions     []Action      `json:"actions" bson:"actions"`
}

// GetID returns the correlation rule ID
func (cr CorrelationRule) GetID() string {
	return cr.ID
}

// GetSeverity returns the correlation rule severity
func (cr CorrelationRule) GetSeverity() string {
	return cr.Severity
}

// GetActions returns the correlation rule actions
func (cr CorrelationRule) GetActions() []Action {
	return cr.Actions
}
