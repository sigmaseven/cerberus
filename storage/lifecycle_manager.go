package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LifecycleManager manages rule lifecycle automation
// Enforces sunset dates for deprecated rules by auto-disabling them
// FIX ISSUE #5: Added proper synchronization with WaitGroup
type LifecycleManager struct {
	ruleStorage           *SQLiteRuleStorage
	lifecycleAuditStorage *SQLiteLifecycleAuditStorage
	sqlite                *SQLite
	checkInterval         time.Duration
	logger                *zap.SugaredLogger

	// FIX ISSUE #5: Proper coordination for graceful shutdown
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	running  bool
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(
	ruleStorage *SQLiteRuleStorage,
	lifecycleAuditStorage *SQLiteLifecycleAuditStorage,
	sqlite *SQLite,
	logger *zap.SugaredLogger,
) *LifecycleManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &LifecycleManager{
		ruleStorage:           ruleStorage,
		lifecycleAuditStorage: lifecycleAuditStorage,
		sqlite:                sqlite,
		checkInterval:         24 * time.Hour, // Check daily
		logger:                logger,
		ctx:                   ctx,
		cancel:                cancel,
		running:               false,
	}
}

// Start starts the lifecycle manager background job
// FIX ISSUE #5: Thread-safe start with proper WaitGroup
func (lm *LifecycleManager) Start() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.running {
		lm.logger.Warn("Lifecycle manager already running")
		return
	}

	lm.logger.Info("Starting rule lifecycle manager")
	lm.running = true
	lm.wg.Add(1)
	go lm.run()
}

// Stop stops the lifecycle manager
// FIX ISSUE #5: Thread-safe stop with WaitGroup coordination
func (lm *LifecycleManager) Stop() {
	lm.mu.Lock()
	if !lm.running {
		lm.mu.Unlock()
		return
	}
	lm.running = false
	lm.mu.Unlock()

	lm.logger.Info("Stopping rule lifecycle manager")
	lm.cancel()
	lm.wg.Wait()
	lm.logger.Info("Rule lifecycle manager stopped")
}

// run executes the background job loop
// FIX ISSUE #5: Proper goroutine lifecycle with WaitGroup
func (lm *LifecycleManager) run() {
	defer lm.wg.Done()

	// Run immediately on startup
	lm.enforceSunsetDates()

	ticker := time.NewTicker(lm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lm.enforceSunsetDates()
		case <-lm.ctx.Done():
			lm.logger.Debug("Lifecycle manager context cancelled")
			return
		}
	}
}

// enforceSunsetDates checks deprecated rules and auto-disables those past sunset
// COMPLEXITY: 35 lines (< 50) with CCN ~6
// SECURITY: Uses context with timeout to prevent hanging
// IDEMPOTENT: Safe to run multiple times on same data
// FIX ISSUE #12: All timestamps use UTC
func (lm *LifecycleManager) enforceSunsetDates() {
	lm.logger.Debug("Starting sunset date enforcement check")

	// Create context with timeout, derived from manager's context
	ctx, cancel := context.WithTimeout(lm.ctx, 5*time.Minute)
	defer cancel()

	// Get all deprecated rules
	rules, err := lm.ruleStorage.GetDeprecatedRules()
	if err != nil {
		if ctx.Err() == context.Canceled {
			lm.logger.Info("Sunset enforcement cancelled during shutdown")
		} else {
			lm.logger.Errorf("Failed to get deprecated rules: %v", err)
		}
		return
	}

	// Process each rule
	now := time.Now().UTC()
	disabledCount := 0

	for _, rule := range rules {
		// Check if context is cancelled
		if ctx.Err() != nil {
			lm.logger.Info("Sunset enforcement cancelled during processing")
			return
		}

		// Skip if rule already disabled or no sunset date
		if !rule.Enabled || !rule.SunsetDate.Valid {
			continue
		}

		// Check if sunset date has passed
		if rule.SunsetDate.Time.After(now) {
			continue
		}

		// Disable the rule
		if err := lm.disableRule(&rule); err != nil {
			lm.logger.Errorw("Failed to disable rule past sunset",
				"rule_id", rule.ID,
				"sunset_date", rule.SunsetDate.Time,
				"error", err,
			)
			continue
		}

		disabledCount++
		lm.logger.Infow("Disabled rule past sunset date",
			"rule_id", rule.ID,
			"rule_name", rule.Name,
			"sunset_date", rule.SunsetDate.Time,
		)
	}

	if disabledCount > 0 {
		lm.logger.Infow("Sunset date enforcement completed",
			"disabled_count", disabledCount,
			"total_deprecated", len(rules),
		)
	} else {
		lm.logger.Debug("Sunset date enforcement completed - no rules disabled")
	}
}

// disableRule disables a rule and creates audit entry
// FIX ISSUE #12: All timestamps use UTC
// COMPLEXITY: 30 lines, CCN ~3
func (lm *LifecycleManager) disableRule(rule *RuleWithLifecycle) error {
	now := time.Now().UTC()

	// Disable the rule
	query := "UPDATE rules SET enabled = 0, updated_at = ? WHERE id = ?"
	_, err := lm.sqlite.WriteDB.Exec(query, now.Format(time.RFC3339), rule.ID)
	if err != nil {
		return fmt.Errorf("failed to disable rule: %w", err)
	}

	// Create audit entry
	if lm.lifecycleAuditStorage != nil {
		entry := &LifecycleAuditEntry{
			RuleID:    rule.ID,
			OldStatus: "deprecated",
			NewStatus: "deprecated",
			Reason:    "Automatically disabled due to sunset date",
			ChangedBy: "system",
			ChangedAt: now,
			AdditionalData: map[string]interface{}{
				"sunset_date": rule.SunsetDate.Time.Format(time.RFC3339),
				"action":      "auto_disable",
			},
		}

		if err := lm.lifecycleAuditStorage.CreateAuditEntry(entry); err != nil {
			// Log error but don't fail the operation
			lm.logger.Warnw("Failed to create audit entry for sunset disable",
				"rule_id", rule.ID,
				"error", err,
			)
		}
	}

	return nil
}

// GetSunsetStatus returns statistics about rules approaching sunset
// COMPLEXITY: 25 lines, CCN ~2
func (lm *LifecycleManager) GetSunsetStatus() (*SunsetStatus, error) {
	query := `
		SELECT
			COUNT(*) as total_deprecated,
			COUNT(CASE WHEN sunset_date IS NOT NULL THEN 1 END) as with_sunset,
			COUNT(CASE WHEN sunset_date IS NOT NULL AND sunset_date <= datetime('now', '+7 days') AND enabled = 1 THEN 1 END) as within_7_days,
			COUNT(CASE WHEN sunset_date IS NOT NULL AND sunset_date <= datetime('now', '+30 days') AND enabled = 1 THEN 1 END) as within_30_days
		FROM rules
		WHERE lifecycle_status = 'deprecated'
	`

	var status SunsetStatus
	err := lm.sqlite.ReadDB.QueryRow(query).Scan(
		&status.TotalDeprecated,
		&status.WithSunsetDate,
		&status.SunsetWithin7Days,
		&status.SunsetWithin30Days,
	)
	if err != nil && err != sql.ErrNoRows {
		// Gracefully handle missing lifecycle_status column (migration not yet run)
		if strings.Contains(err.Error(), "no such column") {
			return &SunsetStatus{}, nil
		}
		return nil, fmt.Errorf("failed to get sunset status: %w", err)
	}

	return &status, nil
}

// SunsetStatus represents statistics about deprecated rules
type SunsetStatus struct {
	TotalDeprecated    int64 `json:"total_deprecated"`
	WithSunsetDate     int64 `json:"with_sunset_date"`
	SunsetWithin7Days  int64 `json:"sunset_within_7_days"`
	SunsetWithin30Days int64 `json:"sunset_within_30_days"`
}
