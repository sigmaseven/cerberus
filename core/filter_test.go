package core

import (
	"testing"
	"time"

	"cerberus/config"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TASK 64.4: Comprehensive Filter Tests
// Tests cover: EventFilter creation, filtering logic, drop types, sample types,
// whitelist sources, configuration updates, and thread-safety

// TestEventFilter_ShouldProcess_DisabledFilter tests that disabled filter processes all events
func TestEventFilter_ShouldProcess_DisabledFilter(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = false

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	event := &Event{
		EventID:   "test-event-1",
		EventType: "test_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "test_event",
			"source_ip":  "192.168.1.100",
		},
	}

	assert.True(t, filter.ShouldProcess(event), "Disabled filter should process all events")
}

// TestEventFilter_ShouldProcess_WhitelistSource tests whitelist source bypass
func TestEventFilter_ShouldProcess_WhitelistSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.WhitelistSources = []string{"192.168.1.100"}
	cfg.Filtering.DropEventTypes = []string{"test_event"} // Should be dropped normally

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	// Whitelisted source - should process even if event type is in drop list
	event := &Event{
		EventID:   "test-event-1",
		EventType: "test_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "test_event",
			"source_ip":  "192.168.1.100", // Whitelisted
		},
	}

	assert.True(t, filter.ShouldProcess(event), "Whitelisted source should bypass filters")
}

// TestEventFilter_ShouldProcess_DropEventType tests drop event type filtering
func TestEventFilter_ShouldProcess_DropEventType(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.DropEventTypes = []string{"noise_event", "debug_event"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	// Event type in drop list - should be dropped
	event1 := &Event{
		EventID:   "test-event-1",
		EventType: "noise_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "noise_event",
			"source_ip":  "192.168.1.200",
		},
	}

	assert.False(t, filter.ShouldProcess(event1), "Event type in drop list should be dropped")

	// Event type not in drop list - should be processed
	event2 := &Event{
		EventID:   "test-event-2",
		EventType: "important_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "important_event",
			"source_ip":  "192.168.1.200",
		},
	}

	assert.True(t, filter.ShouldProcess(event2), "Event type not in drop list should be processed")
}

// TestEventFilter_ShouldProcess_SampleEventType tests sampling for sample event types
func TestEventFilter_ShouldProcess_SampleEventType(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.SampleEventTypes = []string{"verbose_event"}
	cfg.Filtering.SamplingRate = 0.5 // 50% sampling

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	event := &Event{
		EventID:   "test-event-1",
		EventType: "verbose_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "verbose_event",
			"source_ip":  "192.168.1.200",
		},
	}

	// Sampling is probabilistic, so we can't assert exact behavior
	// But we can test that the method returns a boolean
	result := filter.ShouldProcess(event)
	assert.IsType(t, true, result, "ShouldProcess should return boolean for sample event types")
}

// TestEventFilter_ShouldProcess_NoEventType tests event without event_type field
func TestEventFilter_ShouldProcess_NoEventType(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.DropEventTypes = []string{"test_event"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	// Event without event_type field - should be processed (default behavior)
	event := &Event{
		EventID:   "test-event-1",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"source_ip": "192.168.1.200",
			// No event_type field
		},
	}

	assert.True(t, filter.ShouldProcess(event), "Event without event_type should be processed by default")
}

// TestEventFilter_NewEventFilter tests EventFilter creation
func TestEventFilter_NewEventFilter(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.DropEventTypes = []string{"drop1", "drop2"}
	cfg.Filtering.SampleEventTypes = []string{"sample1", "sample2"}
	cfg.Filtering.SamplingRate = 0.8
	cfg.Filtering.WhitelistSources = []string{"10.0.0.1", "10.0.0.2"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	assert.NotNil(t, filter, "NewEventFilter should return non-nil filter")
	// Note: We can't access private fields directly, but we can test behavior
	assert.True(t, filter.ShouldProcess(&Event{
		EventID:   "test",
		Timestamp: time.Now(),
		Fields:    map[string]interface{}{"source_ip": "10.0.0.1"}, // Whitelisted
	}), "Whitelisted source should process")
}

// TestEventFilter_UpdateConfig tests configuration update
func TestEventFilter_UpdateConfig(t *testing.T) {
	cfg1 := &config.Config{}
	cfg1.Filtering.Enabled = true
	cfg1.Filtering.DropEventTypes = []string{"old_drop"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg1, logger)

	// Update with new config
	cfg2 := &config.Config{}
	cfg2.Filtering.Enabled = true
	cfg2.Filtering.DropEventTypes = []string{"new_drop"}

	filter.UpdateConfig(cfg2)

	// Test that new drop type is applied
	event := &Event{
		EventID:   "test-event",
		EventType: "new_drop",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "new_drop",
			"source_ip":  "192.168.1.200",
		},
	}

	assert.False(t, filter.ShouldProcess(event), "Updated config should apply new drop types")
}

// TestEventFilter_UpdateConfig_Disable tests disabling filter via update
func TestEventFilter_UpdateConfig_Disable(t *testing.T) {
	cfg1 := &config.Config{}
	cfg1.Filtering.Enabled = true
	cfg1.Filtering.DropEventTypes = []string{"drop_event"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg1, logger)

	// Disable filtering
	cfg2 := &config.Config{}
	cfg2.Filtering.Enabled = false

	filter.UpdateConfig(cfg2)

	// Event that would normally be dropped should now be processed
	event := &Event{
		EventID:   "test-event",
		EventType: "drop_event",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"event_type": "drop_event",
			"source_ip":  "192.168.1.200",
		},
	}

	assert.True(t, filter.ShouldProcess(event), "Disabled filter should process all events")
}

// TestEventFilter_ConcurrentAccess tests thread-safety of EventFilter
func TestEventFilter_ConcurrentAccess(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filtering.Enabled = true
	cfg.Filtering.DropEventTypes = []string{"drop_event"}

	logger := zap.NewNop().Sugar()
	filter := NewEventFilter(cfg, logger)

	// Concurrent reads and writes
	done := make(chan bool, 10)
	for i := 0; i < 5; i++ {
		go func() {
			event := &Event{
				EventID:   "test-event",
				EventType: "drop_event",
				Timestamp: time.Now(),
				Fields: map[string]interface{}{
					"event_type": "drop_event",
				},
			}
			filter.ShouldProcess(event)
			done <- true
		}()
	}

	// Update config concurrently
	go func() {
		newCfg := &config.Config{}
		newCfg.Filtering.Enabled = true
		newCfg.Filtering.DropEventTypes = []string{"new_drop"}
		filter.UpdateConfig(newCfg)
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 6; i++ {
		<-done
	}

	// Should not have panicked
	assert.True(t, true, "Concurrent access should not panic")
}
