package detect

import (
	"runtime"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"go.uber.org/zap"
)

// TestDetectorGoroutineLeak verifies that Detector.Stop() doesn't leak goroutines
// BLOCKING-6: Goroutine leak detection test for Detector
func TestDetectorGoroutineLeak(t *testing.T) {
	// Record initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create test channels
	inputCh := make(chan *core.Event, 10)
	outputCh := make(chan *core.Event, 10)
	alertCh := make(chan *core.Alert, 10)

	// Create test configuration
	cfg := &config.Config{}
	cfg.Engine.ActionTimeout = 5
	cfg.Engine.ActionWorkerCount = 2
	cfg.Engine.CircuitBreaker.MaxFailures = 5
	cfg.Engine.CircuitBreaker.TimeoutSeconds = 30
	cfg.Engine.CircuitBreaker.MaxHalfOpenRequests = 2

	// Create logger
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create rule engine
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 3600)

	// Create detector
	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, sugar)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Start detector (launches goroutines)
	detector.Start()

	// Allow goroutines to start
	time.Sleep(200 * time.Millisecond)

	// Stop detector
	detector.Stop()

	// Close channels
	close(inputCh)
	close(outputCh)
	close(alertCh)

	// Force GC and wait for goroutines to terminate
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	// Check final goroutine count
	finalGoroutines := runtime.NumGoroutine()

	// Allow small delta for background goroutines
	// BLOCKING-1 FIX: Detector.Stop() now has timeout, so goroutines should not leak
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestDetectorGoroutineLeakUnderLoad verifies no leaks under event load
// BLOCKING-6: Load test for goroutine leak detection
func TestDetectorGoroutineLeakUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	inputCh := make(chan *core.Event, 100)
	outputCh := make(chan *core.Event, 100)
	alertCh := make(chan *core.Alert, 100)

	cfg := &config.Config{}
	cfg.Engine.ActionTimeout = 5
	cfg.Engine.ActionWorkerCount = 4
	cfg.Engine.CircuitBreaker.MaxFailures = 5
	cfg.Engine.CircuitBreaker.TimeoutSeconds = 30
	cfg.Engine.CircuitBreaker.MaxHalfOpenRequests = 2

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 3600)
	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, sugar)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	detector.Start()

	// Send events to detector
	go func() {
		for i := 0; i < 1000; i++ {
			event := &core.Event{
				EventID:   "test-event",
				Timestamp: time.Now(),
				EventType: "test",
				Fields:    map[string]interface{}{},
			}
			select {
			case inputCh <- event:
			case <-time.After(1 * time.Second):
				return
			}
		}
	}()

	// Drain output channels
	go func() {
		for range outputCh {
		}
	}()
	go func() {
		for range alertCh {
		}
	}()

	// Let detector process events
	time.Sleep(2 * time.Second)

	// Stop detector
	detector.Stop()

	// Close channels
	close(inputCh)
	close(outputCh)
	close(alertCh)

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak under load: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak under load: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}
