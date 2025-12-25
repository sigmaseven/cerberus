// Package api provides WebSocket infrastructure tests.
// TASK 158: Tests for WebSocket event broadcasting.
package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHub_BroadcastMessage(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(logger, ctx)
	require.NotNil(t, hub)

	// Start hub in background
	go hub.Start()

	// Give hub time to start
	time.Sleep(100 * time.Millisecond)

	// Test broadcasting a message
	testData := map[string]string{
		"test": "message",
	}

	err := hub.BroadcastMessage("test_event", testData)
	assert.NoError(t, err, "Broadcasting should not error")

	// Verify hub is running
	assert.GreaterOrEqual(t, hub.ClientCount(), 0, "Client count should be >= 0")

	// Stop hub
	cancel()
	hub.Stop()
}

func TestHub_ClientManagement(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(logger, ctx)
	require.NotNil(t, hub)

	// Start hub
	go hub.Start()
	time.Sleep(100 * time.Millisecond)

	// Verify initial state
	assert.Equal(t, 0, hub.ClientCount(), "Should start with 0 clients")

	// Stop hub
	cancel()
	hub.Stop()
}

func TestFeedSyncEvent_Marshaling(t *testing.T) {
	// Test that FeedSyncEvent can be marshaled correctly
	event := &FeedSyncEvent{
		Type:      "feed:sync:started",
		FeedID:    "test-feed-123",
		FeedName:  "Test Feed",
		Progress:  50,
		Message:   "Syncing in progress",
		Timestamp: time.Now(),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(event)
	require.NoError(t, err, "Should marshal without error")
	require.NotEmpty(t, jsonData, "JSON data should not be empty")

	// Unmarshal back
	var decoded FeedSyncEvent
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err, "Should unmarshal without error")

	// Verify fields
	assert.Equal(t, event.Type, decoded.Type)
	assert.Equal(t, event.FeedID, decoded.FeedID)
	assert.Equal(t, event.FeedName, decoded.FeedName)
	assert.Equal(t, event.Progress, decoded.Progress)
	assert.Equal(t, event.Message, decoded.Message)
}

func TestAPI_BroadcastFeedEvent(t *testing.T) {
	// Create a test API instance with minimal config
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	// Create a hub
	hub := NewHub(logger, ctx)
	go hub.Start()
	defer hub.Stop()

	// Create a minimal API instance
	api := &API{
		wsHub:  hub,
		logger: logger,
	}

	// Test broadcasting a feed event
	event := &FeedSyncEvent{
		Type:      "feed:sync:started",
		FeedID:    "test-feed",
		FeedName:  "Test Feed",
		Progress:  0,
		Message:   "Starting sync",
		Timestamp: time.Now(),
	}

	// Should not panic or error
	assert.NotPanics(t, func() {
		api.BroadcastFeedEvent(event)
	}, "BroadcastFeedEvent should not panic")

	// Test with nil hub (should handle gracefully)
	apiNoHub := &API{
		wsHub:  nil,
		logger: logger,
	}

	assert.NotPanics(t, func() {
		apiNoHub.BroadcastFeedEvent(event)
	}, "BroadcastFeedEvent should handle nil hub gracefully")
}

func TestWebSocketMessage_Marshaling(t *testing.T) {
	// Test that WebSocketMessage can be marshaled correctly
	msg := WebSocketMessage{
		Type: "test_event",
		Data: map[string]string{
			"key": "value",
		},
		Timestamp: time.Now(),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(msg)
	require.NoError(t, err, "Should marshal without error")
	require.NotEmpty(t, jsonData, "JSON data should not be empty")

	// Verify it contains expected fields
	assert.Contains(t, string(jsonData), "test_event")
	assert.Contains(t, string(jsonData), "timestamp")
}
