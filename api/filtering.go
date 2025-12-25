package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"cerberus/core"
)

// ParseAlertFilters extracts alert filtering parameters from HTTP request
func ParseAlertFilters(r *http.Request) *core.AlertFilters {
	filters := core.NewAlertFilters()

	// Pagination
	if page := r.URL.Query().Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filters.Page = p
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			filters.Limit = l
		}
	}

	// Search
	if search := r.URL.Query().Get("q"); search != "" {
		filters.Search = strings.TrimSpace(search)
	}

	// Severities (comma-separated or multiple params)
	// BUGFIX: Normalize severity values to lowercase to match database storage
	if severities := r.URL.Query()["severity"]; len(severities) > 0 {
		normalized := make([]string, 0, len(severities))
		for _, s := range severities {
			normalized = append(normalized, strings.ToLower(strings.TrimSpace(s)))
		}
		filters.Severities = normalized
	}

	// Statuses (comma-separated or multiple params)
	// Normalize status values to lowercase to match database storage
	if statuses := r.URL.Query()["status"]; len(statuses) > 0 {
		normalized := make([]string, 0, len(statuses))
		for _, s := range statuses {
			normalized = append(normalized, strings.ToLower(strings.TrimSpace(s)))
		}
		filters.Statuses = normalized
	}

	// Rule IDs (comma-separated or multiple params)
	if ruleIDs := r.URL.Query()["rule_id"]; len(ruleIDs) > 0 {
		filters.RuleIDs = ruleIDs
	}

	// Assigned to (comma-separated or multiple params)
	if assignedTo := r.URL.Query()["assigned_to"]; len(assignedTo) > 0 {
		filters.AssignedTo = assignedTo
	}

	// Tags (comma-separated or multiple params)
	if tags := r.URL.Query()["tags"]; len(tags) > 0 {
		filters.Tags = tags
	}

	// TASK 110 FIX: Disposition filters with validation
	// Dispositions - filter by specific disposition values with input validation
	const maxDispositions = 10 // Prevent DoS via excessive params
	if dispositions := r.URL.Query()["disposition"]; len(dispositions) > 0 {
		// Limit number of disposition params to prevent memory exhaustion
		if len(dispositions) > maxDispositions {
			dispositions = dispositions[:maxDispositions]
		}

		// Validate and normalize disposition values
		// Map for case-insensitive lookup to canonical values
		validDispositions := map[string]string{
			"true_positive":  string(core.DispositionTruePositive),
			"false_positive": string(core.DispositionFalsePositive),
			"benign":         string(core.DispositionBenign),
			"undetermined":   string(core.DispositionUndetermined),
		}

		validated := make([]string, 0, len(dispositions))
		for _, d := range dispositions {
			normalized := strings.ToLower(strings.TrimSpace(d))
			if canonicalValue, ok := validDispositions[normalized]; ok {
				validated = append(validated, canonicalValue)
			}
			// Invalid values are silently ignored (lenient parsing for API usability)
		}
		filters.Dispositions = validated
	}

	// HasDisposition boolean filter - true = any disposition set, false = undetermined only
	if hasDisposition := r.URL.Query().Get("has_disposition"); hasDisposition != "" {
		switch strings.ToLower(hasDisposition) {
		case "true", "1", "yes":
			hasDispo := true
			filters.HasDisposition = &hasDispo
		case "false", "0", "no":
			hasDispo := false
			filters.HasDisposition = &hasDispo
		}
	}

	// TASK 110 FIX: Detect and resolve conflicting filter semantics
	// has_disposition=true with disposition=undetermined is contradictory
	// has_disposition=false with disposition=[anything except undetermined] is contradictory
	if filters.HasDisposition != nil && len(filters.Dispositions) > 0 {
		if *filters.HasDisposition {
			// has_disposition=true: remove 'undetermined' from dispositions (it would never match)
			filtered := make([]string, 0, len(filters.Dispositions))
			for _, d := range filters.Dispositions {
				if d != string(core.DispositionUndetermined) {
					filtered = append(filtered, d)
				}
			}
			filters.Dispositions = filtered
		} else {
			// has_disposition=false: only 'undetermined' makes sense, clear other dispositions
			// This effectively ignores disposition filter when has_disposition=false
			filters.Dispositions = nil
		}
	}

	// MITRE Tactics
	if tactics := r.URL.Query()["mitre_tactic"]; len(tactics) > 0 {
		filters.MitreTactics = tactics
	}

	// MITRE Techniques
	if techniques := r.URL.Query()["mitre_technique"]; len(techniques) > 0 {
		filters.MitreTechniques = techniques
	}

	// Date filters
	if createdAfter := r.URL.Query().Get("created_after"); createdAfter != "" {
		if t, err := time.Parse(time.RFC3339, createdAfter); err == nil {
			filters.CreatedAfter = &t
		}
	}
	if createdBefore := r.URL.Query().Get("created_before"); createdBefore != "" {
		if t, err := time.Parse(time.RFC3339, createdBefore); err == nil {
			filters.CreatedBefore = &t
		}
	}
	if updatedAfter := r.URL.Query().Get("updated_after"); updatedAfter != "" {
		if t, err := time.Parse(time.RFC3339, updatedAfter); err == nil {
			filters.UpdatedAfter = &t
		}
	}
	if updatedBefore := r.URL.Query().Get("updated_before"); updatedBefore != "" {
		if t, err := time.Parse(time.RFC3339, updatedBefore); err == nil {
			filters.UpdatedBefore = &t
		}
	}

	// Sorting
	if sortBy := r.URL.Query().Get("sort"); sortBy != "" {
		// Handle desc prefix (e.g., "-created_at")
		if strings.HasPrefix(sortBy, "-") {
			filters.SortBy = sortBy[1:]
			filters.SortOrder = "desc"
		} else {
			filters.SortBy = sortBy
			filters.SortOrder = "asc"
		}
	}
	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder != "" {
		if sortOrder == "asc" || sortOrder == "desc" {
			filters.SortOrder = sortOrder
		}
	}

	return filters
}

// ParseInvestigationFilters extracts investigation filtering parameters from HTTP request
func ParseInvestigationFilters(r *http.Request) *core.InvestigationFilters {
	filters := core.NewInvestigationFilters()

	// Pagination
	if page := r.URL.Query().Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filters.Page = p
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			filters.Limit = l
		}
	}

	// Search
	if search := r.URL.Query().Get("q"); search != "" {
		filters.Search = strings.TrimSpace(search)
	}

	// Priorities (comma-separated or multiple params)
	if priorities := r.URL.Query()["priority"]; len(priorities) > 0 {
		for _, p := range priorities {
			switch strings.ToLower(p) {
			case "critical":
				filters.Priorities = append(filters.Priorities, core.InvestigationPriorityCritical)
			case "high":
				filters.Priorities = append(filters.Priorities, core.InvestigationPriorityHigh)
			case "medium":
				filters.Priorities = append(filters.Priorities, core.InvestigationPriorityMedium)
			case "low":
				filters.Priorities = append(filters.Priorities, core.InvestigationPriorityLow)
			}
		}
	}

	// Statuses (comma-separated or multiple params)
	if statuses := r.URL.Query()["status"]; len(statuses) > 0 {
		for _, s := range statuses {
			switch strings.ToLower(s) {
			case "open":
				filters.Statuses = append(filters.Statuses, core.InvestigationStatusOpen)
			case "investigating", "in_progress":
				filters.Statuses = append(filters.Statuses, core.InvestigationStatusInProgress)
			case "resolved":
				filters.Statuses = append(filters.Statuses, core.InvestigationStatusResolved)
			case "closed":
				filters.Statuses = append(filters.Statuses, core.InvestigationStatusClosed)
			}
		}
	}

	// Assignee IDs
	if assigneeIDs := r.URL.Query()["assignee_id"]; len(assigneeIDs) > 0 {
		filters.AssigneeIDs = assigneeIDs
	}

	// Created by
	if createdBy := r.URL.Query()["created_by"]; len(createdBy) > 0 {
		filters.CreatedBy = createdBy
	}

	// Tags
	if tags := r.URL.Query()["tags"]; len(tags) > 0 {
		filters.Tags = tags
	}

	// MITRE Tactics
	if tactics := r.URL.Query()["mitre_tactic"]; len(tactics) > 0 {
		filters.MitreTactics = tactics
	}

	// MITRE Techniques
	if techniques := r.URL.Query()["mitre_technique"]; len(techniques) > 0 {
		filters.MitreTechniques = techniques
	}

	// Date filters
	if createdAfter := r.URL.Query().Get("created_after"); createdAfter != "" {
		if t, err := time.Parse(time.RFC3339, createdAfter); err == nil {
			filters.CreatedAfter = &t
		}
	}
	if createdBefore := r.URL.Query().Get("created_before"); createdBefore != "" {
		if t, err := time.Parse(time.RFC3339, createdBefore); err == nil {
			filters.CreatedBefore = &t
		}
	}
	if updatedAfter := r.URL.Query().Get("updated_after"); updatedAfter != "" {
		if t, err := time.Parse(time.RFC3339, updatedAfter); err == nil {
			filters.UpdatedAfter = &t
		}
	}
	if updatedBefore := r.URL.Query().Get("updated_before"); updatedBefore != "" {
		if t, err := time.Parse(time.RFC3339, updatedBefore); err == nil {
			filters.UpdatedBefore = &t
		}
	}
	if closedAfter := r.URL.Query().Get("closed_after"); closedAfter != "" {
		if t, err := time.Parse(time.RFC3339, closedAfter); err == nil {
			filters.ClosedAfter = &t
		}
	}
	if closedBefore := r.URL.Query().Get("closed_before"); closedBefore != "" {
		if t, err := time.Parse(time.RFC3339, closedBefore); err == nil {
			filters.ClosedBefore = &t
		}
	}

	// Sorting
	if sortBy := r.URL.Query().Get("sort"); sortBy != "" {
		if strings.HasPrefix(sortBy, "-") {
			filters.SortBy = sortBy[1:]
			filters.SortOrder = "desc"
		} else {
			filters.SortBy = sortBy
			filters.SortOrder = "asc"
		}
	}
	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder != "" {
		if sortOrder == "asc" || sortOrder == "desc" {
			filters.SortOrder = sortOrder
		}
	}

	return filters
}
