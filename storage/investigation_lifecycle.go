package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/core"
)

// ValidateStateTransition validates investigation state transitions
// TASK 28.1: Enforce valid state transitions
func (sis *SQLiteInvestigationStorage) ValidateStateTransition(from, to core.InvestigationStatus) error {
	// Define valid transitions
	validTransitions := map[core.InvestigationStatus][]core.InvestigationStatus{
		core.InvestigationStatusOpen: {
			core.InvestigationStatusInProgress,
		},
		core.InvestigationStatusInProgress: {
			core.InvestigationStatusAwaitingReview,
			core.InvestigationStatusResolved,
			core.InvestigationStatusFalsePositive,
		},
		core.InvestigationStatusAwaitingReview: {
			core.InvestigationStatusResolved,
			core.InvestigationStatusInProgress, // Can go back to in_progress
		},
		core.InvestigationStatusResolved: {
			core.InvestigationStatusClosed,
		},
		core.InvestigationStatusFalsePositive: {
			core.InvestigationStatusClosed,
		},
		// Closed cannot transition to any other state (reopening requires explicit action)
	}

	// Check if transition is valid
	allowedStates, exists := validTransitions[from]
	if !exists {
		return fmt.Errorf("invalid source status: %s", from)
	}

	for _, allowed := range allowedStates {
		if to == allowed {
			return nil // Valid transition
		}
	}

	// Explicitly reject transitions from closed
	if from == core.InvestigationStatusClosed {
		return fmt.Errorf("invalid state transition: cannot transition from closed to %s without reopening (closed investigations cannot be modified)", to)
	}

	return fmt.Errorf("invalid state transition: cannot transition from %s to %s", from, to)
}

// LogStateTransition logs a state transition to the audit table
// TASK 28.1: Audit logging for state changes
func (sis *SQLiteInvestigationStorage) LogStateTransition(ctx context.Context, investigationID string, from, to core.InvestigationStatus, changedBy, reason string) error {
	query := `
		INSERT INTO investigation_state_transitions (investigation_id, from_status, to_status, changed_by, changed_at, reason)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := sis.db.DB.ExecContext(ctx, query,
		investigationID,
		string(from),
		string(to),
		changedBy,
		time.Now().UTC().Format(time.RFC3339),
		reason,
	)

	if err != nil {
		return fmt.Errorf("failed to log state transition: %w", err)
	}

	return nil
}

// AssociateAlert associates an alert with an investigation
// TASK 28.2: Alert association via junction table
func (sis *SQLiteInvestigationStorage) AssociateAlert(ctx context.Context, investigationID, alertID, userID string) error {
	query := `
		INSERT OR IGNORE INTO investigation_alerts (investigation_id, alert_id, associated_at, associated_by)
		VALUES (?, ?, ?, ?)
	`

	_, err := sis.db.DB.ExecContext(ctx, query,
		investigationID,
		alertID,
		time.Now().UTC().Format(time.RFC3339),
		userID,
	)

	if err != nil {
		return fmt.Errorf("failed to associate alert: %w", err)
	}

	return nil
}

// DissociateAlert removes an alert from an investigation
// TASK 28.2: Remove alert association
func (sis *SQLiteInvestigationStorage) DissociateAlert(ctx context.Context, investigationID, alertID string) error {
	query := `
		DELETE FROM investigation_alerts
		WHERE investigation_id = ? AND alert_id = ?
	`

	result, err := sis.db.DB.ExecContext(ctx, query, investigationID, alertID)
	if err != nil {
		return fmt.Errorf("failed to dissociate alert: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert %s not associated with investigation %s", alertID, investigationID)
	}

	return nil
}

// GetAlertsForInvestigation retrieves all alerts associated with an investigation
// TASK 28.2: Query alerts via junction table
func (sis *SQLiteInvestigationStorage) GetAlertsForInvestigation(ctx context.Context, investigationID string) ([]*core.Alert, error) {
	query := `
		SELECT a.alert_id, a.rule_id, a.event_id, a.timestamp, a.severity, a.status, a.jira_ticket_id,
		       a.rule_name, a.rule_type, a.mitre_techniques, a.fingerprint, a.duplicate_count,
		       a.last_seen, a.event_ids, a.threat_intel, a.assigned_to, a.event
		FROM alerts a
		INNER JOIN investigation_alerts ia ON a.alert_id = ia.alert_id
		WHERE ia.investigation_id = ?
		ORDER BY a.timestamp DESC
	`

	rows, err := sis.db.DB.QueryContext(ctx, query, investigationID)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*core.Alert
	for rows.Next() {
		var alert core.Alert
		var eventIDsJSON sql.NullString
		var threatIntelJSON sql.NullString
		var eventJSON sql.NullString
		var lastSeen sql.NullTime

		err := rows.Scan(
			&alert.AlertID,
			&alert.RuleID,
			&alert.EventID,
			&alert.Timestamp,
			&alert.Severity,
			&alert.Status,
			&alert.JiraTicketID,
			&alert.RuleName,
			&alert.RuleType,
			&alert.MitreTechniques,
			&alert.Fingerprint,
			&alert.DuplicateCount,
			&lastSeen,
			&eventIDsJSON,
			&threatIntelJSON,
			&alert.AssignedTo,
			&eventJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		if lastSeen.Valid {
			alert.LastSeen = lastSeen.Time
		}
		if eventIDsJSON.Valid {
			json.Unmarshal([]byte(eventIDsJSON.String), &alert.EventIDs)
		}
		if threatIntelJSON.Valid {
			json.Unmarshal([]byte(threatIntelJSON.String), &alert.ThreatIntel)
		}
		if eventJSON.Valid {
			var event core.Event
			if err := json.Unmarshal([]byte(eventJSON.String), &event); err == nil {
				alert.Event = &event
			}
		}

		alerts = append(alerts, &alert)
	}

	return alerts, nil
}

// GetInvestigationsForAlert retrieves all investigations associated with an alert
// TASK 28.2: Query investigations via junction table
func (sis *SQLiteInvestigationStorage) GetInvestigationsForAlert(ctx context.Context, alertID string) ([]*core.Investigation, error) {
	query := `
		SELECT i.investigation_id, i.title, i.description, i.priority, i.status,
		       i.assignee_id, i.created_by, i.created_at, i.updated_at, i.closed_at,
		       i.alert_ids, i.event_ids, i.mitre_tactics, i.mitre_techniques,
		       i.artifacts, i.notes, i.verdict, i.resolution_category, i.summary,
		       i.affected_assets, i.ml_feedback, i.tags
		FROM investigations i
		INNER JOIN investigation_alerts ia ON i.investigation_id = ia.investigation_id
		WHERE ia.alert_id = ?
		ORDER BY i.created_at DESC
	`

	rows, err := sis.db.DB.QueryContext(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to query investigations: %w", err)
	}
	defer rows.Close()

	var investigations []*core.Investigation
	for rows.Next() {
		inv, err := sis.scanInvestigation(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan investigation: %w", err)
		}
		investigations = append(investigations, inv)
	}

	return investigations, nil
}

// TimelineEntry represents an entry in the investigation timeline
// TASK 28.3: Timeline entry structure
type TimelineEntry struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // alert, state_change, note, artifact_added
	Timestamp   time.Time              `json:"timestamp"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GenerateTimeline generates a chronological timeline of investigation events
// TASK 28.3: Timeline generation with pagination
func (sis *SQLiteInvestigationStorage) GenerateTimeline(ctx context.Context, investigationID string, limit, offset int) ([]TimelineEntry, int64, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Max limit
	}

	var entries []TimelineEntry

	// Get associated alerts
	alerts, err := sis.GetAlertsForInvestigation(ctx, investigationID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get alerts: %w", err)
	}

	for _, alert := range alerts {
		entries = append(entries, TimelineEntry{
			ID:          fmt.Sprintf("alert-%s", alert.AlertID),
			Type:        "alert",
			Timestamp:   alert.Timestamp,
			Title:       fmt.Sprintf("Alert: %s", alert.RuleName),
			Description: fmt.Sprintf("Alert %s triggered by rule %s", alert.AlertID, alert.RuleID),
			Metadata: map[string]interface{}{
				"alert_id": alert.AlertID,
				"rule_id":  alert.RuleID,
				"severity": alert.Severity,
			},
		})
	}

	// Get state transitions
	transitionQuery := `
		SELECT from_status, to_status, changed_by, changed_at, reason
		FROM investigation_state_transitions
		WHERE investigation_id = ?
		ORDER BY changed_at DESC
	`

	rows, err := sis.db.DB.QueryContext(ctx, transitionQuery, investigationID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query state transitions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var fromStatus, toStatus string
		var changedBy sql.NullString
		var changedAtStr string
		var reason sql.NullString

		if err := rows.Scan(&fromStatus, &toStatus, &changedBy, &changedAtStr, &reason); err != nil {
			continue
		}

		changedAt, _ := time.Parse(time.RFC3339, changedAtStr)

		entries = append(entries, TimelineEntry{
			ID:          fmt.Sprintf("transition-%d", changedAt.Unix()),
			Type:        "state_change",
			Timestamp:   changedAt,
			Title:       fmt.Sprintf("Status changed: %s → %s", fromStatus, toStatus),
			Description: reason.String,
			UserID:      changedBy.String,
			Metadata: map[string]interface{}{
				"from_status": fromStatus,
				"to_status":   toStatus,
			},
		})
	}

	// Get investigation notes
	inv, err := sis.GetInvestigation(investigationID)
	if err == nil && inv != nil {
		for _, note := range inv.Notes {
			entries = append(entries, TimelineEntry{
				ID:          note.ID,
				Type:        "note",
				Timestamp:   note.CreatedAt,
				Title:       "Note added",
				Description: note.Content,
				UserID:      note.AnalystID,
			})
		}
	}

	// Sort by timestamp descending
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].Timestamp.Before(entries[j].Timestamp) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	total := int64(len(entries))

	// Apply pagination
	if offset > 0 && offset < len(entries) {
		entries = entries[offset:]
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, total, nil
}

// InvestigationDetailedStatistics contains detailed statistics for an investigation
// TASK 28.4: Investigation statistics structure
type InvestigationDetailedStatistics struct {
	TotalAlerts          int            `json:"total_alerts"`
	SeverityDistribution map[string]int `json:"severity_distribution"` // high:5, medium:3, low:2
	MitreTechniques      []string       `json:"mitre_techniques"`      // Unique list
	MitreTactics         []string       `json:"mitre_tactics"`         // Unique list
	FirstAlertTimestamp  time.Time      `json:"first_alert_timestamp"`
	LastAlertTimestamp   time.Time      `json:"last_alert_timestamp"`
	TimeRangeHours       float64        `json:"time_range_hours"`
}

// CalculateStatistics calculates detailed statistics for an investigation
// TASK 28.4: Compute alert counts, severity distribution, MITRE aggregation, time range
func (sis *SQLiteInvestigationStorage) CalculateStatistics(ctx context.Context, investigationID string) (*InvestigationDetailedStatistics, error) {
	stats := &InvestigationDetailedStatistics{
		SeverityDistribution: make(map[string]int),
		MitreTechniques:      make([]string, 0),
		MitreTactics:         make([]string, 0),
	}

	// Get associated alerts
	alerts, err := sis.GetAlertsForInvestigation(ctx, investigationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts: %w", err)
	}

	stats.TotalAlerts = len(alerts)

	mitreTechMap := make(map[string]bool)
	mitreTacticMap := make(map[string]bool)

	var firstTimestamp, lastTimestamp time.Time

	for i, alert := range alerts {
		// Count severity distribution
		stats.SeverityDistribution[alert.Severity]++

		// Extract MITRE techniques
		for _, tech := range alert.MitreTechniques {
			if !mitreTechMap[tech] {
				mitreTechMap[tech] = true
				stats.MitreTechniques = append(stats.MitreTechniques, tech)
			}
		}

		// Track timestamps
		if i == 0 || alert.Timestamp.Before(firstTimestamp) {
			firstTimestamp = alert.Timestamp
		}
		if i == 0 || alert.Timestamp.After(lastTimestamp) {
			lastTimestamp = alert.Timestamp
		}
	}

	// Also get MITRE tactics from investigation
	inv, err := sis.GetInvestigation(investigationID)
	if err == nil && inv != nil {
		for _, tactic := range inv.MitreTactics {
			if !mitreTacticMap[tactic] {
				mitreTacticMap[tactic] = true
				stats.MitreTactics = append(stats.MitreTactics, tactic)
			}
		}
	}

	stats.FirstAlertTimestamp = firstTimestamp
	stats.LastAlertTimestamp = lastTimestamp

	if !firstTimestamp.IsZero() && !lastTimestamp.IsZero() {
		stats.TimeRangeHours = lastTimestamp.Sub(firstTimestamp).Hours()
	}

	return stats, nil
}

// ValidateClosureRequirements validates that an investigation meets closure requirements
// TASK 28.5: Enforce verdict and resolution notes before closure
func (sis *SQLiteInvestigationStorage) ValidateClosureRequirements(investigation *core.Investigation) error {
	// Check verdict
	if investigation.Verdict == "" {
		return fmt.Errorf("closure requires verdict (true_positive, false_positive, or inconclusive)")
	}

	if !investigation.Verdict.IsValid() {
		return fmt.Errorf("invalid verdict: %s (must be true_positive, false_positive, or inconclusive)", investigation.Verdict)
	}

	// Check resolution notes (minimum 10 characters)
	if len(strings.TrimSpace(investigation.Summary)) < 10 {
		return fmt.Errorf("closure requires resolution notes (minimum 10 characters)")
	}

	return nil
}

// scanInvestigation is a helper to scan investigation rows (duplicated from sqlite_investigations.go)
func (sis *SQLiteInvestigationStorage) scanInvestigation(rows *sql.Rows) (*core.Investigation, error) {
	var inv core.Investigation
	var alertIDsJSON sql.NullString
	var eventIDsJSON sql.NullString
	var mitreTacticsJSON sql.NullString
	var mitreTechniquesJSON sql.NullString
	var artifactsJSON sql.NullString
	var notesJSON sql.NullString
	var affectedAssetsJSON sql.NullString
	var mlFeedbackJSON sql.NullString
	var tagsJSON sql.NullString
	var closedAt sql.NullTime
	var createdAtStr, updatedAtStr string

	err := rows.Scan(
		&inv.InvestigationID,
		&inv.Title,
		&inv.Description,
		&inv.Priority,
		&inv.Status,
		&inv.AssigneeID,
		&inv.CreatedBy,
		&createdAtStr,
		&updatedAtStr,
		&closedAt,
		&alertIDsJSON,
		&eventIDsJSON,
		&mitreTacticsJSON,
		&mitreTechniquesJSON,
		&artifactsJSON,
		&notesJSON,
		&inv.Verdict,
		&inv.ResolutionCategory,
		&inv.Summary,
		&affectedAssetsJSON,
		&mlFeedbackJSON,
		&tagsJSON,
	)
	if err != nil {
		return nil, err
	}

	inv.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	inv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)
	if closedAt.Valid {
		inv.ClosedAt = &closedAt.Time
	}

	if alertIDsJSON.Valid {
		json.Unmarshal([]byte(alertIDsJSON.String), &inv.AlertIDs)
	}
	if eventIDsJSON.Valid {
		json.Unmarshal([]byte(eventIDsJSON.String), &inv.EventIDs)
	}
	if mitreTacticsJSON.Valid {
		json.Unmarshal([]byte(mitreTacticsJSON.String), &inv.MitreTactics)
	}
	if mitreTechniquesJSON.Valid {
		json.Unmarshal([]byte(mitreTechniquesJSON.String), &inv.MitreTechniques)
	}
	if artifactsJSON.Valid {
		json.Unmarshal([]byte(artifactsJSON.String), &inv.Artifacts)
	}
	if notesJSON.Valid {
		json.Unmarshal([]byte(notesJSON.String), &inv.Notes)
	}
	if affectedAssetsJSON.Valid {
		json.Unmarshal([]byte(affectedAssetsJSON.String), &inv.AffectedAssets)
	}
	if mlFeedbackJSON.Valid {
		json.Unmarshal([]byte(mlFeedbackJSON.String), &inv.MLFeedback)
	}
	if tagsJSON.Valid {
		json.Unmarshal([]byte(tagsJSON.String), &inv.Tags)
	}

	return &inv, nil
}
