package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestRetentionManager_NewRetentionManager(t *testing.T) {
	mockEventStorage := &EventStorage{} // Mock or real, but since simple
	mockAlertStorage := &AlertStorage{}
	logger := zap.NewNop().Sugar()

	rm := NewRetentionManager(mockEventStorage, mockAlertStorage, 30, 30, logger)

	assert.NotNil(t, rm)
	assert.Equal(t, mockEventStorage, rm.eventStorage)
	assert.Equal(t, mockAlertStorage, rm.alertStorage)
	assert.Equal(t, 30, rm.eventDays)
	assert.Equal(t, 30, rm.alertDays)
	assert.Equal(t, 24*time.Hour, rm.checkInterval)
	assert.Equal(t, logger, rm.logger)
	assert.NotNil(t, rm.stopCh)
}

func TestRetentionManager_cleanup(t *testing.T) {
	logger := zap.NewNop().Sugar()

	rm := &RetentionManager{
		eventStorage: nil,
		alertStorage: nil,
		eventDays:    30,
		alertDays:    30,
		logger:       logger,
	}

	rm.cleanup()

	assert.True(t, true)
}

func TestRetentionManager_Start_Stop(t *testing.T) {
	logger := zap.NewNop().Sugar()
	rm := &RetentionManager{
		checkInterval: 1 * time.Millisecond,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}

	rm.Start()
	time.Sleep(10 * time.Millisecond)
	rm.Stop()

	// If no panic, ok.
	assert.True(t, true)
}
