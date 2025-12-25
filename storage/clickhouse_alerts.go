package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/util/goroutine"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

// ClickHouseAlertStorage handles alert persistence in ClickHouse
type ClickHouseAlertStorage struct {
	clickhouse          *ClickHouse
	batchSize           int
	batchFlushInterval  time.Duration
	alertCh             <-chan *core.Alert
	dedupCache          *lru.Cache[string, bool]
	enableDeduplication bool
	logger              *zap.SugaredLogger
	wg                  sync.WaitGroup
	// TASK 144: Context for graceful shutdown of worker goroutines
	ctx    context.Context
	cancel context.CancelFunc
	// TASK 138: Removed unused mu and pendingBatch fields (batching handled differently)
}

// NewClickHouseAlertStorage creates a new ClickHouse alert storage handler
// TASK 144: Accepts parent context for graceful shutdown propagation
// BLOCKING-2 FIX: Accepts parent context parameter for proper context propagation
func NewClickHouseAlertStorage(parentCtx context.Context, clickhouse *ClickHouse, cfg *config.Config, alertCh <-chan *core.Alert, logger *zap.SugaredLogger) (*ClickHouseAlertStorage, error) {
	lruCache, err := lru.New[string, bool](1000)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert dedup cache: %w", err)
	}

	batchSize := cfg.ClickHouse.BatchSize / 10 // Alerts are less frequent than events
	if batchSize < 100 {
		batchSize = 100
	}

	// TASK 144: Create cancellable context for worker lifecycle management
	// BLOCKING-2 FIX: Derive worker context from parent context for proper cancellation propagation
	ctx, cancel := context.WithCancel(parentCtx)

	return &ClickHouseAlertStorage{
		clickhouse:          clickhouse,
		batchSize:           batchSize,
		batchFlushInterval:  5 * time.Second,
		alertCh:             alertCh,
		dedupCache:          lruCache,
		enableDeduplication: true,
		logger:              logger,
		ctx:                 ctx,
		cancel:              cancel,
	}, nil
}

// Start starts alert storage workers
func (cas *ClickHouseAlertStorage) Start(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		cas.wg.Add(1)
		go cas.worker()
	}
}

// worker processes alerts from the channel
// TASK 144: Uses parent context for graceful shutdown support
// TASK 147: Added panic recovery to prevent worker crashes from affecting entire system
func (cas *ClickHouseAlertStorage) worker() {
	defer cas.wg.Done()
	defer goroutine.Recover("clickhouse-alert-worker", cas.logger)
	batch := make([]*core.Alert, 0, cas.batchSize)

	flushTicker := time.NewTicker(cas.batchFlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case alert, ok := <-cas.alertCh:
			if !ok {
				// Channel closed, flush remaining batch with timeout
				if len(batch) > 0 {
					cas.logger.Infof("[CLICKHOUSE] Alert channel closed, flushing %d alerts", len(batch))
					// TASK 144: Use timeout context for final flush, not parent context which may be cancelled
					// BLOCKING-1 FIX: Log flush errors instead of swallowing them
					flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := cas.insertBatch(flushCtx, batch); err != nil {
						cas.logger.Errorw("CRITICAL: Failed to flush alerts during channel close - data may be lost",
							"error", err,
							"alert_count", len(batch))
					}
					cancel()
				}
				return
			}

			batch = append(batch, alert)
			if len(batch) >= cas.batchSize {
				cas.logger.Infof("[CLICKHOUSE] Alert batch full, inserting %d alerts", len(batch))
				// TASK 144: Use worker context for batch inserts to respect cancellation
				_ = cas.insertBatch(cas.ctx, batch)
				batch = batch[:0]
				flushTicker.Reset(cas.batchFlushInterval)
			}

		case <-flushTicker.C:
			if len(batch) > 0 {
				cas.logger.Infof("[CLICKHOUSE] Alert flush interval reached, inserting %d alerts", len(batch))
				// TASK 144: Use worker context for periodic flushes
				_ = cas.insertBatch(cas.ctx, batch)
				batch = batch[:0]
			}

		case <-cas.ctx.Done():
			// TASK 144: Graceful shutdown requested - flush remaining batch and exit
			if len(batch) > 0 {
				cas.logger.Infof("[CLICKHOUSE] Shutdown requested, flushing %d alerts", len(batch))
				// Use timeout context for final flush, not cancelled parent context
				// BLOCKING-1 FIX: Log flush errors instead of swallowing them
				flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := cas.insertBatch(flushCtx, batch); err != nil {
					cas.logger.Errorw("CRITICAL: Failed to flush alerts during shutdown - data may be lost",
						"error", err,
						"alert_count", len(batch))
				}
				cancel()
			}
			cas.logger.Info("[CLICKHOUSE] Alert worker shutting down gracefully")
			return
		}
	}
}

// Stop gracefully shuts down all workers
// TASK 144: Triggers context cancellation to signal workers to stop
// BLOCKING-3 FIX: Implements timeout on WaitGroup.Wait() to prevent indefinite blocking
func (cas *ClickHouseAlertStorage) Stop() error {
	// Cancel context to signal workers to stop
	if cas.cancel != nil {
		cas.cancel()
	}

	// BLOCKING-3 FIX: Wait for workers with timeout to prevent indefinite blocking
	// TASK 147: Added panic recovery to timeout helper goroutine
	done := make(chan struct{})
	go func() {
		defer goroutine.Recover("clickhouse-alert-shutdown-helper", cas.logger)
		cas.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		cas.logger.Info("[CLICKHOUSE] All alert workers stopped gracefully")
		return nil
	case <-time.After(30 * time.Second):
		cas.logger.Error("[CLICKHOUSE] CRITICAL: Alert workers did not stop within 30s - possible hung worker")
		return fmt.Errorf("graceful shutdown timeout: alert workers did not stop within 30s")
	}
}

// InsertAlert inserts a single alert
func (cas *ClickHouseAlertStorage) InsertAlert(ctx context.Context, alert *core.Alert) error {
	return cas.InsertAlerts([]*core.Alert{alert}, ctx)
}

// InsertAlerts inserts multiple alerts
func (cas *ClickHouseAlertStorage) InsertAlerts(alerts []*core.Alert, ctx context.Context) error {
	if len(alerts) == 0 {
		return nil
	}

	return cas.insertBatch(ctx, alerts)
}

// insertBatch performs the actual batch insert
func (cas *ClickHouseAlertStorage) insertBatch(ctx context.Context, alerts []*core.Alert) error {
	// SAFETY: Guard against nil ClickHouse connection (can occur in tests)
	if cas.clickhouse == nil || cas.clickhouse.Conn == nil {
		cas.logger.Warn("[CLICKHOUSE] Skipping alert batch insert - ClickHouse connection not available")
		return fmt.Errorf("clickhouse connection not available")
	}

	// TASK 101: Include disposition fields in INSERT statement
	// Default values are used until core.Alert struct is updated (Task 102)
	// Migration 1.6.0: Added rule_type, correlated_alert_ids, correlation_rule_id for correlation tracking
	// Migration 1.7.0: Added category, source, confidence_score, risk_score, occurrence_count, sla_breached for alert info modal
	prepareBatch, err := cas.clickhouse.Conn.PrepareBatch(ctx, `
		INSERT INTO alerts (
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel,
			disposition, disposition_reason, disposition_set_at,
			disposition_set_by, investigation_id,
			rule_type, correlated_alert_ids, correlation_rule_id,
			category, source, confidence_score, risk_score, occurrence_count, sla_breached
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare alert batch: %w", err)
	}

	for i, alert := range alerts {
		// Check context cancellation periodically (every 1000 alerts)
		if i > 0 && i%1000 == 0 {
			select {
			case <-ctx.Done():
				cas.logger.Debugw("Context cancelled during ClickHouse alert batch append",
					"processed_alerts", i,
					"total_alerts", len(alerts))
				return ctx.Err()
			default:
			}
		}

		// Serialize Event to JSON
		eventData := ""
		if alert.Event != nil {
			if data, err := json.Marshal(alert.Event); err == nil {
				eventData = string(data)
			}
		}

		// Serialize ThreatIntel to JSON
		threatIntelData := ""
		if alert.ThreatIntel != nil && len(alert.ThreatIntel) > 0 {
			if data, err := json.Marshal(alert.ThreatIntel); err == nil {
				threatIntelData = string(data)
			}
		}

		// Handle empty arrays
		eventIDs := alert.EventIDs
		if eventIDs == nil {
			eventIDs = []string{}
		}

		// TASK 102: Include disposition fields from alert struct
		// Ensure disposition has a default value if empty
		dispositionStr := string(alert.Disposition)
		if dispositionStr == "" {
			dispositionStr = string(core.DispositionUndetermined)
		}

		// Serialize CorrelatedAlertIDs to JSON array
		correlatedAlertIDsJSON := "[]"
		if alert.CorrelatedAlertIDs != nil && len(alert.CorrelatedAlertIDs) > 0 {
			if data, err := json.Marshal(alert.CorrelatedAlertIDs); err == nil {
				correlatedAlertIDsJSON = string(data)
			}
		}

		// Default rule_type to 'sigma' if empty
		ruleType := alert.RuleType
		if ruleType == "" {
			ruleType = core.RuleTypeSigma
		}

		// Convert SLABreached bool to uint8 for ClickHouse
		var slaBreached uint8
		if alert.SLABreached {
			slaBreached = 1
		}

		// Ensure occurrence_count is at least 1
		occurrenceCount := alert.OccurrenceCount
		if occurrenceCount < 1 {
			occurrenceCount = 1
		}

		err := prepareBatch.Append(
			alert.AlertID,
			alert.RuleID,
			alert.EventID,
			alert.Timestamp,
			alert.Severity,
			string(alert.Status),
			alert.JiraTicketID,
			alert.Fingerprint,
			alert.DuplicateCount,
			alert.LastSeen,
			eventIDs,
			alert.AssignedTo,
			eventData,
			threatIntelData,
			dispositionStr,           // disposition from alert
			alert.DispositionReason,  // disposition_reason from alert
			alert.DispositionSetAt,   // disposition_set_at from alert (nullable)
			alert.DispositionSetBy,   // disposition_set_by from alert
			alert.InvestigationID,    // investigation_id from alert
			ruleType,                 // rule_type (sigma, correlation, cql, ml)
			correlatedAlertIDsJSON,   // correlated_alert_ids (JSON array of contributing alert IDs)
			alert.CorrelationRuleID,  // correlation_rule_id (for contributing alerts)
			alert.Category,           // category (alert classification)
			alert.Source,             // source (system that generated alert)
			alert.ConfidenceScore,    // confidence_score (0-100)
			uint8(alert.RiskScore),   // risk_score (0-100, cast to UInt8)
			uint32(occurrenceCount),  // occurrence_count
			slaBreached,              // sla_breached (0 or 1)
		)
		if err != nil {
			cas.logger.Errorf("Failed to append alert %s: %v", alert.AlertID, err)
		}
	}

	start := time.Now()
	if err := prepareBatch.Send(); err != nil {
		return fmt.Errorf("failed to send alert batch: %w", err)
	}

	cas.logger.Infof("[CLICKHOUSE] Inserted %d alerts in %v", len(alerts), time.Since(start))
	return nil
}

// UpdateAlertStatus updates an alert's status (interface compliance)
// IMPORTANT: ClickHouse has `status` in ORDER BY clause, so we cannot use ALTER TABLE UPDATE.
// Instead, we use an insert + delete pattern to replace the alert with the new status.
// We INSERT first to avoid data loss if there's a failure between operations.
// The DELETE uses the old status value in the WHERE clause to target only the old row.
func (cas *ClickHouseAlertStorage) UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// First, get the existing alert
	existingAlert, err := cas.GetAlertByID(ctx, alertID)
	if err != nil {
		if errors.Is(err, ErrAlertNotFound) {
			return ErrAlertNotFound
		}
		return fmt.Errorf("failed to get alert for status update: %w", err)
	}

	// Store the old status for the DELETE query
	oldStatus := existingAlert.Status

	// Skip if status is unchanged
	if oldStatus == status {
		cas.logger.Debugw("Alert status unchanged, skipping update",
			"alert_id", alertID,
			"status", status)
		return nil
	}

	// Update the status in the alert struct
	existingAlert.Status = status

	// INSERT the new row first (safer - avoids data loss if DELETE works but INSERT fails)
	err = cas.InsertAlert(ctx, existingAlert)
	if err != nil {
		return fmt.Errorf("failed to insert updated alert: %w", err)
	}

	// DELETE the old row using both alert_id AND old status to target the exact row
	// This is safe because ORDER BY includes status, so the old row has the old status value
	deleteQuery := `ALTER TABLE alerts DELETE WHERE alert_id = ? AND status = ?`
	err = cas.clickhouse.Conn.Exec(ctx, deleteQuery, alertID, string(oldStatus))
	if err != nil {
		// Log but don't fail - the new row is already inserted
		// ClickHouse's eventual merge will handle duplicates if using ReplacingMergeTree
		// For MergeTree, we may briefly have duplicates but the old status row will be deleted
		cas.logger.Warnw("Failed to delete old alert record after status update - may have temporary duplicate",
			"alert_id", alertID,
			"old_status", oldStatus,
			"new_status", status,
			"error", err)
	}

	cas.logger.Infof("Updated alert %s status from %s to %s", alertID, oldStatus, status)
	return nil
}

// isValidAlertID validates alertID format to prevent injection attacks (defense-in-depth)
func isValidAlertID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	// Allow UUIDs and alphanumeric with hyphens/underscores
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// UpdateAlertDisposition updates an alert's disposition with validation
// TASK 103: Implements analyst verdict workflow
// TASK 111: Returns the previous disposition for audit logging (atomic read-update)
// TASK 111 FIX: Accepts context for request cancellation support (BLOCKING-5)
// If disposition is 'undetermined', clears reason and timestamp fields
// Returns: previousDisposition (for audit trail), error
func (cas *ClickHouseAlertStorage) UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, userID string) (string, error) {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return "", fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	// Validate disposition value
	if !disposition.IsValid() {
		return "", fmt.Errorf("invalid disposition value: %q, must be one of %v", disposition, core.ValidDispositions())
	}

	// TASK 111 FIX: Add timeout to parent context to respect request cancellation
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Verify alert exists and capture previous disposition
	// TASK 111: This read provides previous value for audit trail
	//
	// TASK 111 FIX: Race Condition Documentation (BLOCKING-1)
	// KNOWN LIMITATION: A race window exists between GetAlertByID and the UPDATE.
	// If a concurrent request modifies the disposition between these calls,
	// the audit log will show the wrong previous_disposition value.
	//
	// WHY THIS EXISTS: ClickHouse is an OLAP database optimized for analytics,
	// not OLTP transactions. It does not support:
	// - Row-level locking
	// - SELECT FOR UPDATE
	// - True ACID transactions
	//
	// MITIGATION STRATEGIES (for future enhancement):
	// 1. Add version column and use conditional UPDATE with WHERE version = ?
	// 2. Add timestamp column for optimistic locking
	// 3. Use a separate audit table with INSERT instead of relying on logs
	// 4. For critical compliance requirements, consider a transactional store
	//
	// RISK ASSESSMENT: This race condition is acceptable for most SIEM use cases
	// because disposition changes are relatively infrequent (not high-throughput),
	// and the PRIMARY audit record is the audit log itself, not the disposition history.
	existingAlert, err := cas.GetAlertByID(ctx, alertID)
	if err != nil {
		// TASK 111 FIX: Propagate ErrAlertNotFound directly for proper sentinel error detection (BLOCKING-2)
		if errors.Is(err, ErrAlertNotFound) {
			return "", ErrAlertNotFound
		}
		return "", fmt.Errorf("failed to verify alert exists: %w", err)
	}

	// TASK 111: Capture previous disposition for audit trail
	previousDisposition := string(existingAlert.Disposition)

	var query string
	var args []interface{}

	if disposition == core.DispositionUndetermined {
		// Clearing disposition - reset all fields
		query = `
			ALTER TABLE alerts
			UPDATE
				disposition = ?,
				disposition_reason = '',
				disposition_set_at = NULL,
				disposition_set_by = ''
			WHERE alert_id = ?
		`
		args = []interface{}{string(disposition), alertID}
	} else {
		// Setting disposition - include all fields
		query = `
			ALTER TABLE alerts
			UPDATE
				disposition = ?,
				disposition_reason = ?,
				disposition_set_at = now64(3, 'UTC'),
				disposition_set_by = ?
			WHERE alert_id = ?
		`
		args = []interface{}{string(disposition), reason, userID, alertID}
	}

	err = cas.clickhouse.Conn.Exec(ctx, query, args...)
	if err != nil {
		return previousDisposition, fmt.Errorf("failed to update alert disposition: %w", err)
	}

	cas.logger.Infow("Updated alert disposition",
		"alert_id", alertID,
		"disposition", disposition,
		"previous_disposition", previousDisposition,
		"user_id", userID)
	return previousDisposition, nil
}

// UpdateAlertInvestigation links or unlinks an alert to/from an investigation
// TASK 103: Pass empty investigationID to unlink
// TASK 106: Uses optimistic locking to prevent race conditions when linking
// Returns ErrAlertAlreadyLinked if attempting to link an already-linked alert
func (cas *ClickHouseAlertStorage) UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Verify alert exists and check current state
	existingAlert, err := cas.GetAlertByID(ctx, alertID)
	if err != nil {
		return fmt.Errorf("failed to verify alert exists: %w", err)
	}
	if existingAlert == nil {
		return ErrAlertNotFound
	}

	// TASK 106: Optimistic locking check - prevent linking if already linked
	// Only applicable when linking (non-empty investigationID)
	if investigationID != "" && existingAlert.InvestigationID != "" {
		return ErrAlertAlreadyLinked
	}

	// Build query based on operation type
	var query string
	if investigationID != "" {
		// Linking: Use optimistic locking condition (only update if currently unlinked)
		// This prevents race conditions where two concurrent requests both try to link
		query = `
			ALTER TABLE alerts
			UPDATE investigation_id = ?
			WHERE alert_id = ? AND investigation_id = ''
		`
	} else {
		// Unlinking: No need for optimistic locking
		query = `
			ALTER TABLE alerts
			UPDATE investigation_id = ?
			WHERE alert_id = ?
		`
	}

	err = cas.clickhouse.Conn.Exec(ctx, query, investigationID, alertID)
	if err != nil {
		return fmt.Errorf("failed to update alert investigation: %w", err)
	}

	if investigationID == "" {
		cas.logger.Infow("Unlinked alert from investigation", "alert_id", alertID)
	} else {
		cas.logger.Infow("Linked alert to investigation",
			"alert_id", alertID,
			"investigation_id", investigationID)
	}
	return nil
}

// UpdateAlertAssignment updates the assigned user for an alert
// TASK 103: Assign or unassign alert to analyst
func (cas *ClickHouseAlertStorage) UpdateAlertAssignment(ctx context.Context, alertID, assignedTo string) error {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Verify alert exists before update
	existingAlert, err := cas.GetAlertByID(ctx, alertID)
	if err != nil {
		return fmt.Errorf("failed to verify alert exists: %w", err)
	}
	if existingAlert == nil {
		return fmt.Errorf("alert %s not found", alertID)
	}

	query := `
		ALTER TABLE alerts
		UPDATE assigned_to = ?
		WHERE alert_id = ?
	`

	err = cas.clickhouse.Conn.Exec(ctx, query, assignedTo, alertID)
	if err != nil {
		return fmt.Errorf("failed to update alert assignment: %w", err)
	}

	if assignedTo == "" {
		cas.logger.Infow("Unassigned alert", "alert_id", alertID)
	} else {
		cas.logger.Infow("Assigned alert", "alert_id", alertID, "assigned_to", assignedTo)
	}
	return nil
}

// UpdateAlertAssignee updates an alert's assignee with nullable support
// TASK 105: Implements nullable assignee update for unassignment support
func (cas *ClickHouseAlertStorage) UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Verify alert exists before update
	existingAlert, err := cas.GetAlertByID(ctx, alertID)
	if err != nil {
		return fmt.Errorf("failed to verify alert exists: %w", err)
	}
	if existingAlert == nil {
		return ErrAlertNotFound // Use sentinel error for proper error handling
	}

	// Determine the assignee value (empty string for unassign)
	assignedTo := ""
	if assigneeID != nil {
		assignedTo = *assigneeID
	}

	query := `
		ALTER TABLE alerts
		UPDATE assigned_to = ?
		WHERE alert_id = ?
	`

	err = cas.clickhouse.Conn.Exec(ctx, query, assignedTo, alertID)
	if err != nil {
		return fmt.Errorf("failed to update alert assignee: %w", err)
	}

	if assignedTo == "" {
		cas.logger.Infow("Unassigned alert", "alert_id", alertID)
	} else {
		cas.logger.Infow("Assigned alert", "alert_id", alertID, "assigned_to", assignedTo)
	}
	return nil
}

// GetAlertByID retrieves a single alert by ID
// TASK 103: Used for disposition updates to verify alert exists
func (cas *ClickHouseAlertStorage) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return nil, fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel,
			disposition, disposition_reason, disposition_set_at,
			disposition_set_by, investigation_id,
			rule_type, correlated_alert_ids, correlation_rule_id,
			category, source, confidence_score, risk_score, occurrence_count, sla_breached
		FROM alerts
		WHERE alert_id = ?
		LIMIT 1
	`

	var alert core.Alert
	var eventData string
	var threatIntelData string
	var statusStr string
	var duplicateCount uint32
	var dispositionStr string
	var correlatedAlertIDsJSON string
	// Note: risk_score is UInt8, occurrence_count is UInt32, sla_breached is UInt8
	var riskScore uint8
	var occurrenceCount uint32
	var slaBreached uint8

	err := cas.clickhouse.Conn.QueryRow(ctx, query, alertID).Scan(
		&alert.AlertID,
		&alert.RuleID,
		&alert.EventID,
		&alert.Timestamp,
		&alert.Severity,
		&statusStr,
		&alert.JiraTicketID,
		&alert.Fingerprint,
		&duplicateCount,
		&alert.LastSeen,
		&alert.EventIDs,
		&alert.AssignedTo,
		&eventData,
		&threatIntelData,
		&dispositionStr,
		&alert.DispositionReason,
		&alert.DispositionSetAt,
		&alert.DispositionSetBy,
		&alert.InvestigationID,
		&alert.RuleType,
		&correlatedAlertIDsJSON,
		&alert.CorrelationRuleID,
		&alert.Category,
		&alert.Source,
		&alert.ConfidenceScore,
		&riskScore,
		&occurrenceCount,
		&slaBreached,
	)
	if err != nil {
		// TASK 111 FIX: Check for no-rows error and return ErrAlertNotFound sentinel (BLOCKING-2)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlertNotFound
		}
		return nil, fmt.Errorf("failed to get alert: %w", err)
	}

	// Convert types
	alert.DuplicateCount = int(duplicateCount)
	alert.Status = core.AlertStatus(statusStr)
	alert.Disposition = core.AlertDisposition(dispositionStr)
	if !alert.Disposition.IsValid() {
		cas.logger.Warnf("Invalid disposition value '%s' for alert %s, defaulting to undetermined", dispositionStr, alert.AlertID)
		alert.Disposition = core.DispositionUndetermined
	}

	// Convert new metadata fields
	alert.RiskScore = int(riskScore)
	alert.OccurrenceCount = int(occurrenceCount)
	alert.SLABreached = slaBreached == 1

	// Deserialize CorrelatedAlertIDs from JSON
	if correlatedAlertIDsJSON != "" && correlatedAlertIDsJSON != "[]" {
		if err := json.Unmarshal([]byte(correlatedAlertIDsJSON), &alert.CorrelatedAlertIDs); err != nil {
			cas.logger.Warnf("Failed to unmarshal correlated_alert_ids for alert %s: %v", alert.AlertID, err)
		}
	}

	// Deserialize Event from JSON
	if eventData != "" {
		var event core.Event
		if err := json.Unmarshal([]byte(eventData), &event); err == nil {
			alert.Event = &event
		}
	}

	// Deserialize ThreatIntel from JSON
	if threatIntelData != "" {
		var threatIntel map[string]interface{}
		if err := json.Unmarshal([]byte(threatIntelData), &threatIntel); err == nil {
			alert.ThreatIntel = threatIntel
		}
	}

	return &alert, nil
}

// GetAlerts retrieves alerts without filtering (interface compatibility)
func (cas *ClickHouseAlertStorage) GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error) {
	alerts, err := cas.GetAlertsFiltered(ctx, limit, offset, "", "")
	if err != nil {
		return nil, err
	}

	// Convert []*Alert to []Alert
	result := make([]core.Alert, len(alerts))
	for i, alert := range alerts {
		if alert != nil {
			result[i] = *alert
		}
	}
	return result, nil
}

// GetAlertsFiltered retrieves alerts with filtering
func (cas *ClickHouseAlertStorage) GetAlertsFiltered(ctx context.Context, limit, offset int, severity, status string) ([]*core.Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// TASK 101: Include disposition fields in SELECT for future use
	// These will be scanned into core.Alert fields after Task 102
	// Updated to include 1.6.0 correlation fields and 1.7.0 overview metadata fields
	query := `
		SELECT
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel,
			disposition, disposition_reason, disposition_set_at,
			disposition_set_by, investigation_id,
			rule_type, correlated_alert_ids, correlation_rule_id,
			category, source, confidence_score, risk_score, occurrence_count, sla_breached
		FROM alerts
		WHERE 1=1
	`
	args := make([]interface{}, 0)

	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := cas.clickhouse.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]*core.Alert, 0)
	for rows.Next() {
		var alert core.Alert
		var eventData string
		var threatIntelData string
		var statusStr string
		var duplicateCount uint32 // ClickHouse UInt32

		// TASK 102: Disposition fields - scan into temp variable for type conversion
		var dispositionStr string

		// 1.6.0: Correlation fields
		var correlatedAlertIDsJSON string

		// 1.7.0: Overview metadata fields
		// Note: risk_score is UInt8, occurrence_count is UInt32, sla_breached is UInt8
		var riskScore uint8
		var occurrenceCount uint32
		var slaBreached uint8

		err := rows.Scan(
			&alert.AlertID,
			&alert.RuleID,
			&alert.EventID,
			&alert.Timestamp,
			&alert.Severity,
			&statusStr,
			&alert.JiraTicketID,
			&alert.Fingerprint,
			&duplicateCount,
			&alert.LastSeen,
			&alert.EventIDs,
			&alert.AssignedTo,
			&eventData,
			&threatIntelData,
			// TASK 102: Disposition fields populated into alert struct
			&dispositionStr,
			&alert.DispositionReason,
			&alert.DispositionSetAt,
			&alert.DispositionSetBy,
			&alert.InvestigationID,
			// 1.6.0: Correlation fields
			&alert.RuleType,
			&correlatedAlertIDsJSON,
			&alert.CorrelationRuleID,
			// 1.7.0: Overview metadata fields
			&alert.Category,
			&alert.Source,
			&alert.ConfidenceScore,
			&riskScore,
			&occurrenceCount,
			&slaBreached,
		)
		if err != nil {
			cas.logger.Errorf("Failed to scan alert: %v", err)
			continue
		}

		// TASK 102: Convert disposition string to typed enum with defensive validation
		alert.Disposition = core.AlertDisposition(dispositionStr)
		if !alert.Disposition.IsValid() {
			// Defensive: invalid DB values default to undetermined
			// Note: Migration 1.3.0 backfills empty values, so this should rarely trigger
			cas.logger.Debugf("Invalid disposition value '%s' for alert %s, defaulting to undetermined", dispositionStr, alert.AlertID)
			alert.Disposition = core.DispositionUndetermined
		}

		// Convert uint32 to int
		alert.DuplicateCount = int(duplicateCount)

		// Convert status string to AlertStatus
		alert.Status = core.AlertStatus(statusStr)

		// 1.6.0: Convert correlated_alert_ids JSON to slice
		if correlatedAlertIDsJSON != "" && correlatedAlertIDsJSON != "[]" {
			if err := json.Unmarshal([]byte(correlatedAlertIDsJSON), &alert.CorrelatedAlertIDs); err != nil {
				cas.logger.Warnf("Failed to unmarshal correlated_alert_ids for alert %s: %v", alert.AlertID, err)
			}
		}

		// 1.7.0: Convert overview metadata types
		alert.RiskScore = int(riskScore)
		alert.OccurrenceCount = int(occurrenceCount)
		alert.SLABreached = slaBreached == 1

		// Deserialize Event from JSON
		if eventData != "" {
			var event core.Event
			if err := json.Unmarshal([]byte(eventData), &event); err == nil {
				alert.Event = &event
			} else {
				cas.logger.Warnf("Failed to unmarshal event data for alert %s: %v. Data: %s", alert.AlertID, err, eventData)
			}
		}

		// Deserialize ThreatIntel from JSON
		if threatIntelData != "" {
			var threatIntel map[string]interface{}
			if err := json.Unmarshal([]byte(threatIntelData), &threatIntel); err == nil {
				alert.ThreatIntel = threatIntel
			}
		}

		alerts = append(alerts, &alert)
	}

	return alerts, nil
}

// GetAlertsWithFilters retrieves alerts with comprehensive filtering including dispositions
// TASK 110: Implements full AlertFilters support with disposition and hasDisposition filtering
func (cas *ClickHouseAlertStorage) GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// TASK 110 FIX: Validate and enforce limit bounds to prevent memory exhaustion
	const (
		defaultLimit = 100
		maxLimit     = 10000
	)
	if filters.Limit <= 0 {
		filters.Limit = defaultLimit
	} else if filters.Limit > maxLimit {
		filters.Limit = maxLimit
	}
	if filters.Page <= 0 {
		filters.Page = 1
	}

	// Build WHERE clause conditions and args
	conditions := []string{"1=1"}
	args := make([]interface{}, 0)

	// Severity filter (multiple values supported)
	// FIX: Use lower() for case-insensitive matching - database may have "High" but filter sends "high"
	if len(filters.Severities) > 0 {
		placeholders := make([]string, len(filters.Severities))
		for i, s := range filters.Severities {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(s)) // Ensure lowercase for consistency
		}
		conditions = append(conditions, fmt.Sprintf("lower(severity) IN (%s)", strings.Join(placeholders, ",")))
	}

	// Status filter (multiple values supported)
	// FIX: Use lower() for case-insensitive matching - database may have "Pending" but filter sends "pending"
	if len(filters.Statuses) > 0 {
		placeholders := make([]string, len(filters.Statuses))
		for i, s := range filters.Statuses {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(s)) // Ensure lowercase for consistency
		}
		conditions = append(conditions, fmt.Sprintf("lower(status) IN (%s)", strings.Join(placeholders, ",")))
	}

	// Rule ID filter (multiple values supported)
	if len(filters.RuleIDs) > 0 {
		placeholders := make([]string, len(filters.RuleIDs))
		for i, r := range filters.RuleIDs {
			placeholders[i] = "?"
			args = append(args, r)
		}
		conditions = append(conditions, fmt.Sprintf("rule_id IN (%s)", strings.Join(placeholders, ",")))
	}

	// Assigned to filter (multiple values supported)
	if len(filters.AssignedTo) > 0 {
		placeholders := make([]string, len(filters.AssignedTo))
		for i, a := range filters.AssignedTo {
			placeholders[i] = "?"
			args = append(args, a)
		}
		conditions = append(conditions, fmt.Sprintf("assigned_to IN (%s)", strings.Join(placeholders, ",")))
	}

	// TASK 110 FIX: Disposition filter with validation - filter out empty/invalid values
	// FIX: Use lower() for case-insensitive matching
	if len(filters.Dispositions) > 0 {
		// Filter and validate disposition values
		validDispositions := make([]string, 0, len(filters.Dispositions))
		for _, d := range filters.Dispositions {
			trimmed := strings.TrimSpace(d)
			// Only include valid, non-empty disposition values
			if trimmed != "" && core.AlertDisposition(trimmed).IsValid() {
				validDispositions = append(validDispositions, strings.ToLower(trimmed))
			}
		}

		// Only add condition if we have valid dispositions after filtering
		if len(validDispositions) > 0 {
			placeholders := make([]string, len(validDispositions))
			for i, d := range validDispositions {
				placeholders[i] = "?"
				args = append(args, d)
			}
			conditions = append(conditions, fmt.Sprintf("lower(disposition) IN (%s)", strings.Join(placeholders, ",")))
		}
	}

	// TASK 110: HasDisposition filter - true = any disposition set, false = undetermined only
	// FIX: Use lower() for case-insensitive matching
	if filters.HasDisposition != nil {
		if *filters.HasDisposition {
			// Has disposition: anything except 'undetermined'
			conditions = append(conditions, "lower(disposition) != ?")
			args = append(args, strings.ToLower(string(core.DispositionUndetermined)))
		} else {
			// No disposition: only 'undetermined'
			conditions = append(conditions, "lower(disposition) = ?")
			args = append(args, strings.ToLower(string(core.DispositionUndetermined)))
		}
	}

	// Date range filters
	if filters.CreatedAfter != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filters.CreatedAfter)
	}
	if filters.CreatedBefore != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filters.CreatedBefore)
	}

	// Search filter (searches rule_id, assigned_to, fingerprint)
	if filters.Search != "" {
		searchPattern := "%" + filters.Search + "%"
		conditions = append(conditions, "(rule_id ILIKE ? OR assigned_to ILIKE ? OR fingerprint ILIKE ?)")
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// TASK 110 FIX: Build sort clause with explicit validation against whitelist
	// SQL injection prevention: only allow whitelisted column names
	sortColumn := "created_at"
	validSortColumns := map[string]bool{
		"created_at": true,
		"severity":   true,
		"status":     true,
		"rule_id":    true,
	}
	if filters.SortBy != "" && validSortColumns[filters.SortBy] {
		sortColumn = filters.SortBy
	}

	// TASK 110 FIX: Explicit sort order validation - prevent SQL injection
	// Only accept exact string matches, default to DESC
	sortOrder := "DESC"
	if strings.ToLower(filters.SortOrder) == "asc" {
		sortOrder = "ASC"
	}
	// Any other value (including injection attempts) defaults to DESC

	// Calculate offset
	offset := (filters.Page - 1) * filters.Limit

	// NOTE: Count and data queries are separate, so total count may be slightly
	// inconsistent with actual results if alerts are modified between queries.
	// This is acceptable for UI pagination in a high-throughput SIEM system.
	// ClickHouse's INSERT performance takes priority over perfect consistency.
	countQuery := fmt.Sprintf("SELECT count() FROM alerts WHERE %s", whereClause)
	var total uint64
	err := cas.clickhouse.Conn.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count filtered alerts: %w", err)
	}

	// Build main query
	// Updated to include 1.6.0 correlation fields and 1.7.0 overview metadata fields
	query := fmt.Sprintf(`
		SELECT
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel,
			disposition, disposition_reason, disposition_set_at,
			disposition_set_by, investigation_id,
			rule_type, correlated_alert_ids, correlation_rule_id,
			category, source, confidence_score, risk_score, occurrence_count, sla_breached
		FROM alerts
		WHERE %s
		ORDER BY %s %s
		LIMIT ? OFFSET ?
	`, whereClause, sortColumn, sortOrder)

	// Add pagination to args
	args = append(args, filters.Limit, offset)

	rows, err := cas.clickhouse.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query filtered alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]*core.Alert, 0)
	for rows.Next() {
		var alert core.Alert
		var eventData string
		var threatIntelData string
		var statusStr string
		var duplicateCount uint32
		var dispositionStr string

		// 1.6.0: Correlation fields
		var correlatedAlertIDsJSON string

		// 1.7.0: Overview metadata fields
		// Note: risk_score is UInt8, occurrence_count is UInt32, sla_breached is UInt8
		var riskScore uint8
		var occurrenceCount uint32
		var slaBreached uint8

		err := rows.Scan(
			&alert.AlertID,
			&alert.RuleID,
			&alert.EventID,
			&alert.Timestamp,
			&alert.Severity,
			&statusStr,
			&alert.JiraTicketID,
			&alert.Fingerprint,
			&duplicateCount,
			&alert.LastSeen,
			&alert.EventIDs,
			&alert.AssignedTo,
			&eventData,
			&threatIntelData,
			&dispositionStr,
			&alert.DispositionReason,
			&alert.DispositionSetAt,
			&alert.DispositionSetBy,
			&alert.InvestigationID,
			// 1.6.0: Correlation fields
			&alert.RuleType,
			&correlatedAlertIDsJSON,
			&alert.CorrelationRuleID,
			// 1.7.0: Overview metadata fields
			&alert.Category,
			&alert.Source,
			&alert.ConfidenceScore,
			&riskScore,
			&occurrenceCount,
			&slaBreached,
		)
		if err != nil {
			cas.logger.Errorf("Failed to scan alert: %v", err)
			continue
		}

		// Convert types
		alert.DuplicateCount = int(duplicateCount)
		alert.Status = core.AlertStatus(statusStr)
		alert.Disposition = core.AlertDisposition(dispositionStr)
		if !alert.Disposition.IsValid() {
			cas.logger.Warnf("Invalid disposition value '%s' for alert %s, defaulting to undetermined", dispositionStr, alert.AlertID)
			alert.Disposition = core.DispositionUndetermined
		}

		// 1.6.0: Convert correlated_alert_ids JSON to slice
		if correlatedAlertIDsJSON != "" && correlatedAlertIDsJSON != "[]" {
			if err := json.Unmarshal([]byte(correlatedAlertIDsJSON), &alert.CorrelatedAlertIDs); err != nil {
				cas.logger.Warnf("Failed to unmarshal correlated_alert_ids for alert %s: %v", alert.AlertID, err)
			}
		}

		// 1.7.0: Convert overview metadata types
		alert.RiskScore = int(riskScore)
		alert.OccurrenceCount = int(occurrenceCount)
		alert.SLABreached = slaBreached == 1

		// Deserialize Event from JSON
		if eventData != "" {
			var event core.Event
			if err := json.Unmarshal([]byte(eventData), &event); err == nil {
				alert.Event = &event
			}
		}

		// Deserialize ThreatIntel from JSON
		if threatIntelData != "" {
			var threatIntel map[string]interface{}
			if err := json.Unmarshal([]byte(threatIntelData), &threatIntel); err == nil {
				alert.ThreatIntel = threatIntel
			}
		}

		alerts = append(alerts, &alert)
	}

	return alerts, int64(total), nil
}

// GetAlertCount returns total alert count without filters
func (cas *ClickHouseAlertStorage) GetAlertCount(ctx context.Context) (int64, error) {
	return cas.GetAlertCountFiltered(ctx, "", "")
}

// GetAlertCountFiltered returns total alert count with optional filters
func (cas *ClickHouseAlertStorage) GetAlertCountFiltered(ctx context.Context, severity, status string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := "SELECT count() FROM alerts WHERE 1=1"
	args := make([]interface{}, 0)

	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	var count uint64
	err := cas.clickhouse.Conn.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count alerts: %w", err)
	}

	return int64(count), nil
}

// GetAlertsByTimeRange retrieves alerts within a time range
func (cas *ClickHouseAlertStorage) GetAlertsByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]*core.Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// TASK 101: Include disposition fields in SELECT for future use
	query := `
		SELECT
			alert_id, rule_id, event_id, created_at, severity, status,
			jira_ticket_id, fingerprint, duplicate_count, last_seen,
			event_ids, assigned_to, event_data, threat_intel,
			disposition, disposition_reason, disposition_set_at,
			disposition_set_by, investigation_id
		FROM alerts
		WHERE created_at >= ? AND created_at <= ?
		ORDER BY created_at DESC
	`

	rows, err := cas.clickhouse.Conn.Query(ctx, query, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts by time range: %w", err)
	}
	defer rows.Close()

	alerts := make([]*core.Alert, 0)
	for rows.Next() {
		var alert core.Alert
		var eventData string
		var threatIntelData string
		var statusStr string
		var duplicateCount uint32 // ClickHouse UInt32

		// TASK 102: Disposition fields - scan into temp variable for type conversion
		var dispositionStr string

		err := rows.Scan(
			&alert.AlertID,
			&alert.RuleID,
			&alert.EventID,
			&alert.Timestamp,
			&alert.Severity,
			&statusStr,
			&alert.JiraTicketID,
			&alert.Fingerprint,
			&duplicateCount,
			&alert.LastSeen,
			&alert.EventIDs,
			&alert.AssignedTo,
			&eventData,
			&threatIntelData,
			// TASK 102: Disposition fields populated into alert struct
			&dispositionStr,
			&alert.DispositionReason,
			&alert.DispositionSetAt,
			&alert.DispositionSetBy,
			&alert.InvestigationID,
		)
		if err != nil {
			cas.logger.Errorf("Failed to scan alert: %v", err)
			continue
		}

		// TASK 102: Convert disposition string to typed enum with defensive validation
		alert.Disposition = core.AlertDisposition(dispositionStr)
		if !alert.Disposition.IsValid() {
			// Defensive: invalid DB values default to undetermined
			// Note: Migration 1.3.0 backfills empty values, so this should rarely trigger
			cas.logger.Debugf("Invalid disposition value '%s' for alert %s, defaulting to undetermined", dispositionStr, alert.AlertID)
			alert.Disposition = core.DispositionUndetermined
		}

		// Convert uint32 to int
		alert.DuplicateCount = int(duplicateCount)

		// Convert status string to AlertStatus
		alert.Status = core.AlertStatus(statusStr)

		// Deserialize Event from JSON
		if eventData != "" {
			var event core.Event
			if err := json.Unmarshal([]byte(eventData), &event); err == nil {
				alert.Event = &event
			} else {
				cas.logger.Warnf("Failed to unmarshal event data for alert %s: %v. Data: %s", alert.AlertID, err, eventData)
			}
		}

		// Deserialize ThreatIntel from JSON
		if threatIntelData != "" {
			var threatIntel map[string]interface{}
			if err := json.Unmarshal([]byte(threatIntelData), &threatIntel); err == nil {
				alert.ThreatIntel = threatIntel
			}
		}

		alerts = append(alerts, &alert)
	}

	return alerts, nil
}

// GetAlertStats returns alert statistics
func (cas *ClickHouseAlertStorage) GetAlertStats(ctx context.Context) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	stats := make(map[string]interface{})

	// Total count
	var total uint64
	err := cas.clickhouse.Conn.QueryRow(ctx, "SELECT count() FROM alerts").Scan(&total)
	if err != nil {
		return nil, err
	}
	stats["total"] = total

	// Count by status
	query := `
		SELECT status, count() as count
		FROM alerts
		GROUP BY status
	`
	rows, err := cas.clickhouse.Conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byStatus := make(map[string]uint64)
	for rows.Next() {
		var status string
		var count uint64
		if err := rows.Scan(&status, &count); err == nil {
			byStatus[status] = count
		}
	}
	stats["by_status"] = byStatus

	// Count by severity
	query = `
		SELECT severity, count() as count
		FROM alerts
		GROUP BY severity
	`
	rows, err = cas.clickhouse.Conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bySeverity := make(map[string]uint64)
	for rows.Next() {
		var severity string
		var count uint64
		if err := rows.Scan(&severity, &count); err == nil {
			bySeverity[severity] = count
		}
	}
	stats["by_severity"] = bySeverity

	return stats, nil
}

// DeleteAlert deletes a single alert by ID
func (cas *ClickHouseAlertStorage) DeleteAlert(ctx context.Context, alertID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use ALTER TABLE DELETE (synchronous mutation)
	query := `ALTER TABLE alerts DELETE WHERE alert_id = ?`

	err := cas.clickhouse.Conn.Exec(ctx, query, alertID)
	if err != nil {
		return fmt.Errorf("failed to delete alert: %w", err)
	}

	cas.logger.Infof("Deleted alert %s", alertID)
	return nil
}

// CleanupOldAlerts uses ClickHouse's efficient partition dropping
func (cas *ClickHouseAlertStorage) CleanupOldAlerts(ctx context.Context, retentionDays int) error {
	// Validate input to prevent data loss
	if retentionDays <= 0 {
		return fmt.Errorf("retentionDays must be positive, got %d", retentionDays)
	}
	if retentionDays > 36500 { // Sanity check: max 100 years
		return fmt.Errorf("retentionDays is unreasonably large: %d (max 36500)", retentionDays)
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Drop old partitions
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	partition := cutoffDate.Format("200601") // YYYYMM format

	// Validate partition format to prevent SQL injection (should be exactly 6 digits)
	if len(partition) != 6 {
		return fmt.Errorf("invalid partition format: expected 6 characters, got %d", len(partition))
	}
	for _, c := range partition {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid partition format: contains non-digit character")
		}
	}

	query := fmt.Sprintf("ALTER TABLE alerts DROP PARTITION '%s'", partition)

	err := cas.clickhouse.Conn.Exec(ctx, query)
	if err != nil {
		// Partition might not exist, log as warning
		cas.logger.Warnf("Failed to drop alerts partition %s: %v (may not exist)", partition, err)
	} else {
		cas.logger.Infof("Dropped alerts partition %s", partition)
	}

	return nil
}

// GetAlert retrieves a single alert by ID
// Delegates to GetAlertByID for actual implementation
func (cas *ClickHouseAlertStorage) GetAlert(ctx context.Context, id string) (*core.Alert, error) {
	return cas.GetAlertByID(ctx, id)
}

// GetAlertCountsByMonth returns alert counts grouped by month
func (cas *ClickHouseAlertStorage) GetAlertCountsByMonth(ctx context.Context) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			toStartOfMonth(created_at) as month,
			count() as count
		FROM alerts
		WHERE created_at >= now() - INTERVAL 12 MONTH
		GROUP BY month
		ORDER BY month DESC
	`

	rows, err := cas.clickhouse.Conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query alert counts by month: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var month time.Time
		var count uint64
		if err := rows.Scan(&month, &count); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"month": month,
			"count": count,
		})
	}

	return results, nil
}

// AcknowledgeAlert marks an alert as acknowledged (stub for interface compliance)
func (cas *ClickHouseAlertStorage) AcknowledgeAlert(ctx context.Context, id string) error {
	return fmt.Errorf("alert lifecycle operations not supported in ClickHouse mode")
}

// DismissAlert marks an alert as dismissed (stub for interface compliance)
func (cas *ClickHouseAlertStorage) DismissAlert(ctx context.Context, id string) error {
	return fmt.Errorf("alert lifecycle operations not supported in ClickHouse mode")
}

// AssignAlert assigns an alert to a user (stub for interface compliance)
func (cas *ClickHouseAlertStorage) AssignAlert(ctx context.Context, id string, assignTo string) error {
	return fmt.Errorf("alert lifecycle operations not supported in ClickHouse mode")
}

// LinkAlertToInvestigation links an alert to an investigation (stub for interface compliance)
func (cas *ClickHouseAlertStorage) LinkAlertToInvestigation(alertID string, investigationID string) error {
	return fmt.Errorf("alert lifecycle operations not supported in ClickHouse mode")
}

// RecordStatusChange records a status change in the alert's history
// This creates an audit trail of all status transitions for the timeline display
func (cas *ClickHouseAlertStorage) RecordStatusChange(ctx context.Context, change *core.StatusChange) error {
	if change == nil {
		return fmt.Errorf("status change cannot be nil")
	}

	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(change.AlertID) {
		return fmt.Errorf("invalid alert_id format: %s", change.AlertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		INSERT INTO alert_status_history (
			alert_id, from_status, to_status, changed_by, changed_at, note
		) VALUES (?, ?, ?, ?, ?, ?)
	`

	err := cas.clickhouse.Conn.Exec(ctx, query,
		change.AlertID,
		string(change.FromStatus),
		string(change.ToStatus),
		change.ChangedBy,
		change.ChangedAt,
		change.Note,
	)
	if err != nil {
		return fmt.Errorf("failed to record status change: %w", err)
	}

	cas.logger.Debugw("Recorded status change",
		"alert_id", change.AlertID,
		"from_status", change.FromStatus,
		"to_status", change.ToStatus,
		"changed_by", change.ChangedBy)

	return nil
}

// GetAlertHistory retrieves the status change history for an alert
// Returns changes in chronological order (oldest first) for timeline display
func (cas *ClickHouseAlertStorage) GetAlertHistory(ctx context.Context, alertID string) ([]*core.StatusChange, error) {
	// Validate alertID format (defense-in-depth)
	if !isValidAlertID(alertID) {
		return nil, fmt.Errorf("invalid alert_id format: %s", alertID)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT alert_id, from_status, to_status, changed_by, changed_at, note
		FROM alert_status_history
		WHERE alert_id = ?
		ORDER BY changed_at ASC
	`

	rows, err := cas.clickhouse.Conn.Query(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to query alert history: %w", err)
	}
	defer rows.Close()

	var history []*core.StatusChange
	for rows.Next() {
		var change core.StatusChange
		var fromStatusStr, toStatusStr string

		err := rows.Scan(
			&change.AlertID,
			&fromStatusStr,
			&toStatusStr,
			&change.ChangedBy,
			&change.ChangedAt,
			&change.Note,
		)
		if err != nil {
			cas.logger.Warnw("Failed to scan status change row", "error", err)
			continue
		}

		change.FromStatus = core.AlertStatus(fromStatusStr)
		change.ToStatus = core.AlertStatus(toStatusStr)
		history = append(history, &change)
	}

	return history, nil
}
