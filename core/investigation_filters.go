package core

import (
	"time"
)

// InvestigationFilters defines all available filtering options for investigations
type InvestigationFilters struct {
	// Pagination
	Page  int `json:"page"`
	Limit int `json:"limit"`

	// Basic filters
	Search      string                  `json:"search"`       // Text search across title, description
	Priorities  []InvestigationPriority `json:"priorities"`   // critical, high, medium, low
	Statuses    []InvestigationStatus   `json:"statuses"`     // open, investigating, resolved, closed
	AssigneeIDs []string                `json:"assignee_ids"` // Filter by assignee user IDs
	CreatedBy   []string                `json:"created_by"`   // Filter by creator user IDs
	Tags        []string                `json:"tags"`         // Filter by tags

	// MITRE ATT&CK filters
	MitreTactics    []string `json:"mitre_tactics"`    // execution, persistence, etc.
	MitreTechniques []string `json:"mitre_techniques"` // T1059, T1566, etc.

	// Date range filters
	CreatedAfter  *time.Time `json:"created_after"`
	CreatedBefore *time.Time `json:"created_before"`
	UpdatedAfter  *time.Time `json:"updated_after"`
	UpdatedBefore *time.Time `json:"updated_before"`
	ClosedAfter   *time.Time `json:"closed_after"`
	ClosedBefore  *time.Time `json:"closed_before"`

	// Sorting
	SortBy    string `json:"sort_by"`    // created_at, updated_at, priority, status, title
	SortOrder string `json:"sort_order"` // asc, desc
}

// NewInvestigationFilters creates a new InvestigationFilters with default values
func NewInvestigationFilters() *InvestigationFilters {
	return &InvestigationFilters{
		Page:      1,
		Limit:     100,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}
