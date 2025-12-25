package core

import (
	"time"
)

// AlertFilters defines all available filtering options for alerts
type AlertFilters struct {
	// Pagination
	Page  int `json:"page"`
	Limit int `json:"limit"`

	// Basic filters
	Search     string   `json:"search"`      // Text search across title, description, rule name
	Severities []string `json:"severities"`  // critical, high, medium, low
	Statuses   []string `json:"statuses"`    // pending, acknowledged, investigating, resolved, escalated, closed
	RuleIDs    []string `json:"rule_ids"`    // Filter by rule IDs
	AssignedTo []string `json:"assigned_to"` // Filter by assignee username
	Tags       []string `json:"tags"`        // Filter by tags

	// TASK 110: Disposition filters for analyst workflow
	Dispositions   []string `json:"dispositions"`    // Filter by disposition values: true_positive, false_positive, benign, undetermined
	HasDisposition *bool    `json:"has_disposition"` // Filter by disposition status: true = any disposition set, false = undetermined only

	// MITRE ATT&CK filters
	MitreTactics    []string `json:"mitre_tactics"`    // execution, persistence, etc.
	MitreTechniques []string `json:"mitre_techniques"` // T1059, T1566, etc.

	// Date range filters
	CreatedAfter  *time.Time `json:"created_after"`
	CreatedBefore *time.Time `json:"created_before"`
	UpdatedAfter  *time.Time `json:"updated_after"`
	UpdatedBefore *time.Time `json:"updated_before"`

	// Sorting
	SortBy    string `json:"sort_by"`    // created_at, updated_at, severity, status
	SortOrder string `json:"sort_order"` // asc, desc
}

// NewAlertFilters creates a new AlertFilters with default values
func NewAlertFilters() *AlertFilters {
	return &AlertFilters{
		Page:      1,
		Limit:     100,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}
