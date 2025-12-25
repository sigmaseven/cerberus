package storage

import (
	"context"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestClickHouseAlertStorage_GracefulShutdown verifies that Stop() triggers graceful shutdown
// TASK 144: Context propagation test for graceful shutdown
func TestClickHouseAlertStorage_GracefulShutdown(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert)
	storage, err := NewClickHouseAlertStorage(context.Background(), nil, cfg, alertCh, logger)
	assert.NoError(t, err)

	storage.Start(2)

	go func() {
		for i := 0; i < 5; i++ {
			alertCh <- &core.Alert{AlertID: "test"}
			time.Sleep(10 * time.Millisecond)
		}
		close(alertCh)
	}()

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	storage.Stop()
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 5*time.Second, "graceful shutdown should complete quickly")
}

// TestClickHouseAlertStorage_ContextCancellation verifies context cancellation stops workers
// TASK 144: Verifies that context cancellation properly terminates background goroutines
func TestClickHouseAlertStorage_ContextCancellation(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert)
	defer close(alertCh)

	storage, err := NewClickHouseAlertStorage(context.Background(), nil, cfg, alertCh, logger)
	assert.NoError(t, err)

	storage.Start(3)

	go func() {
		for i := 0; i < 10; i++ {
			alertCh <- &core.Alert{AlertID: "test"}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		storage.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not stop within timeout - context cancellation failed")
	}
}
