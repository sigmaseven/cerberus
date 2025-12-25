package core

import (
	"strings"
	"time"
)

// RuleFilters defines all available filtering options for rules
type RuleFilters struct {
	// Pagination
	Page  int `json:"page"`
	Limit int `json:"limit"`

	// Basic filters
	Search     string   `json:"search"`      // Text search across name, description, tags
	Severities []string `json:"severities"`  // critical, high, medium, low
	Enabled    *bool    `json:"enabled"`     // true, false, or nil for all
	Types      []string `json:"types"`       // sigma, cql
	FeedIDs    []string `json:"feed_ids"`    // Filter by feed source
	Authors    []string `json:"authors"`     // Filter by author name
	Tags       []string `json:"tags"`        // Filter by tags (attack.*, detection.*, etc.)
	LogSources []string `json:"log_sources"` // windows, linux, macos, cloud, network

	// MITRE ATT&CK filters
	MitreTactics    []string `json:"mitre_tactics"`    // execution, persistence, etc.
	MitreTechniques []string `json:"mitre_techniques"` // T1059, T1566, etc.

	// Date range filters
	CreatedAfter  *time.Time `json:"created_after"`
	CreatedBefore *time.Time `json:"created_before"`
	UpdatedAfter  *time.Time `json:"updated_after"`
	UpdatedBefore *time.Time `json:"updated_before"`

	// Sorting
	SortBy    string `json:"sort_by"`    // name, severity, created_at, updated_at
	SortOrder string `json:"sort_order"` // asc, desc
}

// NewRuleFilters creates a new RuleFilters with default values
func NewRuleFilters() *RuleFilters {
	return &RuleFilters{
		Page:      1,
		Limit:     100,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}

// RuleFilterMetadata contains available filter options
type RuleFilterMetadata struct {
	Severities      []string   `json:"severities"`
	Types           []string   `json:"types"`
	MitreTactics    []string   `json:"mitre_tactics"`
	MitreTechniques []string   `json:"mitre_techniques"`
	LogSources      []string   `json:"log_sources"`
	Feeds           []FeedInfo `json:"feeds"`
	Authors         []string   `json:"authors"`
	Tags            []string   `json:"tags"`
	TotalRules      int        `json:"total_rules"`
}

// FeedInfo provides feed information for filtering
type FeedInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MatchesFilters checks if a rule matches the provided filters
func (r *Rule) MatchesFilters(filters *RuleFilters) bool {
	// Search filter
	if filters.Search != "" {
		searchLower := strings.ToLower(filters.Search)
		if !strings.Contains(strings.ToLower(r.Name), searchLower) &&
			!strings.Contains(strings.ToLower(r.Description), searchLower) &&
			!containsAny(r.Tags, searchLower) {
			return false
		}
	}

	// Severity filter
	if len(filters.Severities) > 0 && !contains(filters.Severities, strings.ToLower(r.Severity)) {
		return false
	}

	// Enabled filter
	if filters.Enabled != nil && r.Enabled != *filters.Enabled {
		return false
	}

	// Type filter
	if len(filters.Types) > 0 && !contains(filters.Types, strings.ToLower(r.Type)) {
		return false
	}

	// Feed ID filter
	if len(filters.FeedIDs) > 0 {
		if feedID, ok := r.Metadata["feed_id"].(string); ok {
			if !contains(filters.FeedIDs, feedID) {
				return false
			}
		}
	}

	// Author filter
	if len(filters.Authors) > 0 && !contains(filters.Authors, r.Author) {
		return false
	}

	// Tags filter (any tag matches)
	if len(filters.Tags) > 0 {
		matched := false
		for _, filterTag := range filters.Tags {
			for _, ruleTag := range r.Tags {
				if strings.Contains(strings.ToLower(ruleTag), strings.ToLower(filterTag)) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// MITRE Tactics filter (any tactic matches)
	if len(filters.MitreTactics) > 0 {
		matched := false
		for _, tactic := range filters.MitreTactics {
			for _, ruleTactic := range r.MitreTactics {
				if strings.EqualFold(ruleTactic, tactic) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// MITRE Techniques filter (any technique matches)
	if len(filters.MitreTechniques) > 0 {
		matched := false
		for _, technique := range filters.MitreTechniques {
			for _, ruleTechnique := range r.MitreTechniques {
				if strings.EqualFold(ruleTechnique, technique) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Date filters
	if filters.CreatedAfter != nil && r.CreatedAt.Before(*filters.CreatedAfter) {
		return false
	}
	if filters.CreatedBefore != nil && r.CreatedAt.After(*filters.CreatedBefore) {
		return false
	}
	if filters.UpdatedAfter != nil && r.UpdatedAt.Before(*filters.UpdatedAfter) {
		return false
	}
	if filters.UpdatedBefore != nil && r.UpdatedAt.After(*filters.UpdatedBefore) {
		return false
	}

	return true
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func containsAny(slice []string, substr string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), substr) {
			return true
		}
	}
	return false
}
