package storage

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// RetentionManager handles data retention policies
type RetentionManager struct {
	eventStorage  *ClickHouseEventStorage
	alertStorage  *ClickHouseAlertStorage
	eventDays     int
	alertDays     int
	checkInterval time.Duration
	logger        *zap.SugaredLogger
	stopCh        chan struct{}
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(eventStorage *ClickHouseEventStorage, alertStorage *ClickHouseAlertStorage, eventDays, alertDays int, logger *zap.SugaredLogger) *RetentionManager {
	return &RetentionManager{
		eventStorage:  eventStorage,
		alertStorage:  alertStorage,
		eventDays:     eventDays,
		alertDays:     alertDays,
		checkInterval: 24 * time.Hour, // Check daily
		logger:        logger,
		stopCh:        make(chan struct{}),
	}
}

// Start starts the retention manager
func (rm *RetentionManager) Start() {
	go rm.run()
}

func (rm *RetentionManager) run() {
	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.cleanup()
		case <-rm.stopCh:
			return
		}
	}
}

// Stop stops the retention manager
func (rm *RetentionManager) Stop() {
	close(rm.stopCh)
}

// cleanup performs retention cleanup
// Uses a context with timeout to ensure cleanup operations complete within reasonable time
// and can be cancelled during shutdown.
func (rm *RetentionManager) cleanup() {
	rm.logger.Info("Starting data retention cleanup")

	// Create context with timeout that also respects shutdown signal
	// Timeout ensures cleanup doesn't hang forever; 30 minutes is sufficient for large deletions
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Make the context cancellable via stopCh for graceful shutdown
	go func() {
		select {
		case <-rm.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	if rm.eventStorage != nil {
		if err := rm.eventStorage.CleanupOldEvents(ctx, rm.eventDays); err != nil {
			if ctx.Err() == context.Canceled {
				rm.logger.Info("Event cleanup cancelled during shutdown")
			} else {
				rm.logger.Errorf("Failed to cleanup old events: %v", err)
			}
		}
	}

	if rm.alertStorage != nil {
		if err := rm.alertStorage.CleanupOldAlerts(ctx, rm.alertDays); err != nil {
			if ctx.Err() == context.Canceled {
				rm.logger.Info("Alert cleanup cancelled during shutdown")
			} else {
				rm.logger.Errorf("Failed to cleanup old alerts: %v", err)
			}
		}
	}

	rm.logger.Info("Data retention cleanup completed")
}
