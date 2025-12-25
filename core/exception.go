package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// ExceptionType defines the type of exception
type ExceptionType string

const (
	ExceptionSuppress       ExceptionType = "suppress"
	ExceptionModifySeverity ExceptionType = "modify_severity"
)

// ConditionType defines the type of condition used in the exception
type ConditionType string

const (
	ConditionTypeSigmaFilter ConditionType = "sigma_filter"
	ConditionTypeCQL         ConditionType = "cql"
)

// Exception represents a rule exception that can suppress or modify alerts
type Exception struct {
	ID          string `json:"id" bson:"_id"`
	Name        string `json:"name" bson:"name"`
	Description string `json:"description" bson:"description"`
	RuleID      string `json:"rule_id" bson:"rule_id"` // Empty for global exceptions

	// Exception behavior
	Type ExceptionType `json:"type" bson:"type"`

	// Condition can be SIGMA filter or CQL query
	ConditionType ConditionType `json:"condition_type" bson:"condition_type"`
	Condition     string        `json:"condition" bson:"condition"` // The actual filter/query

	// Action details
	NewSeverity string `json:"new_severity,omitempty" bson:"new_severity,omitempty"` // For modify_severity

	// Control
	Enabled   bool       `json:"enabled" bson:"enabled"`
	Priority  int        `json:"priority" bson:"priority"` // Lower = higher priority
	ExpiresAt *time.Time `json:"expires_at,omitempty" bson:"expires_at,omitempty"`

	// Tracking
	HitCount int64      `json:"hit_count" bson:"hit_count"`
	LastHit  *time.Time `json:"last_hit,omitempty" bson:"last_hit,omitempty"`

	// Metadata
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	CreatedBy string    `json:"created_by" bson:"created_by"`

	// Documentation
	Justification string   `json:"justification" bson:"justification"`
	Tags          []string `json:"tags" bson:"tags"`
}

// ExceptionFilters defines filters for querying exceptions
type ExceptionFilters struct {
	RuleID    string
	Type      ExceptionType
	Enabled   *bool
	Expired   *bool
	Search    string
	Page      int
	Limit     int
	SortBy    string
	SortOrder string
}

// ExceptionResult represents the result of evaluating exceptions against an event
type ExceptionResult struct {
	Action            string   // "suppress", "modify", "none"
	NewSeverity       string   // New severity if action is "modify"
	MatchedExceptions []string // IDs of matched exceptions
	SuppressReason    string   // Human-readable reason for suppression
}

// IsExpired checks if the exception has expired
func (e *Exception) IsExpired() bool {
	if e.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*e.ExpiresAt)
}

// IsActive checks if the exception is currently active
func (e *Exception) IsActive() bool {
	return e.Enabled && !e.IsExpired()
}

// Validate performs basic validation on the exception
func (e *Exception) Validate() error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	if e.Type != ExceptionSuppress && e.Type != ExceptionModifySeverity {
		return fmt.Errorf("invalid exception type")
	}
	if e.ConditionType != ConditionTypeSigmaFilter && e.ConditionType != ConditionTypeCQL {
		return fmt.Errorf("invalid condition type")
	}
	if e.Condition == "" {
		return fmt.Errorf("condition is required")
	}
	if e.Type == ExceptionModifySeverity && e.NewSeverity == "" {
		return fmt.Errorf("new_severity is required for modify_severity exceptions")
	}
	if e.Type == ExceptionModifySeverity {
		// Validate severity value
		validSeverities := []string{"critical", "high", "medium", "low", "info"}
		valid := false
		for _, s := range validSeverities {
			if e.NewSeverity == s {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid severity value")
		}
	}
	return nil
}

// ToJSON converts the exception to JSON
func (e *Exception) ToJSON() (string, error) {
	bytes, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// NewException creates a new exception with default values
func NewException(name, ruleID string, exceptionType ExceptionType, conditionType ConditionType, condition string) *Exception {
	now := time.Now()
	return &Exception{
		Name:          name,
		RuleID:        ruleID,
		Type:          exceptionType,
		ConditionType: conditionType,
		Condition:     condition,
		Enabled:       true,
		Priority:      100,
		HitCount:      0,
		CreatedAt:     now,
		UpdatedAt:     now,
		Tags:          []string{},
	}
}

// NewExceptionResult creates a new exception result with default "none" action
func NewExceptionResult() *ExceptionResult {
	return &ExceptionResult{
		Action:            "none",
		MatchedExceptions: []string{},
	}
}
