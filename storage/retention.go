package storage

import (
	"time"

	"go.uber.org/zap"
)

// RetentionManager handles data retention policies
type RetentionManager struct {
	eventStorage  *EventStorage
	alertStorage  *AlertStorage
	eventDays     int
	alertDays     int
	checkInterval time.Duration
	logger        *zap.SugaredLogger
	stopCh        chan struct{}
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(eventStorage *EventStorage, alertStorage *AlertStorage, eventDays, alertDays int, logger *zap.SugaredLogger) *RetentionManager {
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
func (rm *RetentionManager) cleanup() {
	rm.logger.Info("Starting data retention cleanup")

	if rm.eventStorage != nil {
		if err := rm.eventStorage.CleanupOldEvents(rm.eventDays); err != nil {
			rm.logger.Errorf("Failed to cleanup old events: %v", err)
		}
	}

	if rm.alertStorage != nil {
		if err := rm.alertStorage.CleanupOldAlerts(rm.alertDays); err != nil {
			rm.logger.Errorf("Failed to cleanup old alerts: %v", err)
		}
	}

	rm.logger.Info("Data retention cleanup completed")
}
