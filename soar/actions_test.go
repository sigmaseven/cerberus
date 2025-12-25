package soar

import (
	"context"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestDestructiveActionsBlocked_WhenFlagDisabled verifies that destructive actions
// are blocked when the destructive_actions_enabled flag is set to false
// SECURITY: This is a CRITICAL test - destructive actions MUST NOT execute without explicit approval
func TestDestructiveActionsBlocked_WhenFlagDisabled(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	// Create test alert
	alert := &core.Alert{
		AlertID:  "test-alert-123",
		Severity: "High",
		RuleID:   "test-rule",
		EventID:  "test-event",
		Event: &core.Event{
			Fields: map[string]interface{}{
				"source_ip": "192.168.1.100",
			},
		},
	}

	t.Run("BlockIP_Blocked_WhenFlagDisabled", func(t *testing.T) {
		// Create BlockIPAction with flag DISABLED
		action := NewBlockIPAction(logger, false)

		// Attempt to execute
		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"ip_address": "192.168.1.100",
		})

		// CRITICAL: Action MUST be blocked
		require.Error(t, err, "BlockIP must return error when flag is disabled")
		assert.Contains(t, err.Error(), "destructive action blocked", "Error must indicate action was blocked")
		assert.Contains(t, err.Error(), "destructive_actions_enabled=true", "Error must mention the config flag")

		// Verify result status
		require.NotNil(t, result, "Result must be returned even on failure")
		assert.Equal(t, ActionStatusFailed, result.Status, "Status must be Failed")
		assert.Contains(t, result.Error, "Destructive action blocked", "Result error must explain why")
		assert.False(t, result.CompletedAt.IsZero(), "CompletedAt must be set")
		// Note: Duration may be 0 on fast systems, but timestamps must be set
		assert.True(t, result.CompletedAt.After(result.StartedAt) || result.CompletedAt.Equal(result.StartedAt),
			"CompletedAt must be >= StartedAt")
	})

	t.Run("BlockIP_Blocked_WithIPFromEvent", func(t *testing.T) {
		// Test that blocking is enforced even when IP is extracted from event
		action := NewBlockIPAction(logger, false)

		result, err := action.Execute(ctx, alert, map[string]interface{}{})

		require.Error(t, err, "BlockIP must be blocked even when extracting IP from event")
		assert.Contains(t, err.Error(), "destructive action blocked")
		assert.Equal(t, ActionStatusFailed, result.Status)
	})

	t.Run("IsolateHost_Blocked_WhenFlagDisabled", func(t *testing.T) {
		// Create IsolateHostAction with flag DISABLED
		action := NewIsolateHostAction(logger, false)

		// Attempt to execute
		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"hostname": "workstation-123",
		})

		// CRITICAL: Action MUST be blocked
		require.Error(t, err, "IsolateHost must return error when flag is disabled")
		assert.Contains(t, err.Error(), "destructive action blocked", "Error must indicate action was blocked")
		assert.Contains(t, err.Error(), "destructive_actions_enabled=true", "Error must mention the config flag")

		// Verify result status
		require.NotNil(t, result, "Result must be returned even on failure")
		assert.Equal(t, ActionStatusFailed, result.Status, "Status must be Failed")
		assert.Contains(t, result.Error, "Destructive action blocked", "Result error must explain why")
		assert.False(t, result.CompletedAt.IsZero(), "CompletedAt must be set")
		// Note: Duration may be 0 on fast systems, but timestamps must be set
		assert.True(t, result.CompletedAt.After(result.StartedAt) || result.CompletedAt.Equal(result.StartedAt),
			"CompletedAt must be >= StartedAt")
	})

	t.Run("MultipleActions_AllBlocked_WhenFlagDisabled", func(t *testing.T) {
		// Verify that ALL destructive actions are blocked consistently
		blockIPAction := NewBlockIPAction(logger, false)
		isolateHostAction := NewIsolateHostAction(logger, false)

		// Try BlockIP
		_, err1 := blockIPAction.Execute(ctx, alert, map[string]interface{}{
			"ip_address": "10.0.0.1",
		})

		// Try IsolateHost
		_, err2 := isolateHostAction.Execute(ctx, alert, map[string]interface{}{
			"hostname": "server-456",
		})

		// Both MUST fail
		require.Error(t, err1, "BlockIP must be blocked")
		require.Error(t, err2, "IsolateHost must be blocked")
		assert.Contains(t, err1.Error(), "destructive action blocked")
		assert.Contains(t, err2.Error(), "destructive action blocked")
	})
}

// TestDestructiveActionsAllowed_WhenFlagEnabled verifies that destructive actions
// are allowed to execute (but may fail for other reasons) when the flag is enabled
// SECURITY: When flag is enabled, actions should NOT be blocked by the flag check
func TestDestructiveActionsAllowed_WhenFlagEnabled(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:  "test-alert-456",
		Severity: "Critical",
		RuleID:   "test-rule",
		EventID:  "test-event",
		Event: &core.Event{
			Fields: map[string]interface{}{
				"source_ip": "203.0.113.10",
			},
		},
	}

	t.Run("BlockIP_NotBlockedByFlag_WhenFlagEnabled", func(t *testing.T) {
		// Create BlockIPAction with flag ENABLED
		action := NewBlockIPAction(logger, true)

		// Execute with valid IP
		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"ip_address": "203.0.113.10",
		})

		// Action should NOT be blocked by flag (may succeed or fail for other reasons)
		// The key is that error should NOT contain "destructive action blocked"
		if err != nil {
			assert.NotContains(t, err.Error(), "destructive action blocked",
				"When flag is enabled, error must NOT be about flag blocking")
		}

		// If no error, verify successful execution
		if err == nil {
			require.NotNil(t, result)
			assert.Equal(t, ActionStatusCompleted, result.Status, "Status should be Completed on success")
		}
	})

	t.Run("BlockIP_FailsGracefully_WithMissingIP", func(t *testing.T) {
		// Even with flag enabled, action should fail gracefully if IP is missing
		action := NewBlockIPAction(logger, true)

		// Create alert without IP
		alertNoIP := &core.Alert{
			AlertID: "test-no-ip",
			Event:   &core.Event{Fields: map[string]interface{}{}},
		}

		result, err := action.Execute(ctx, alertNoIP, map[string]interface{}{})

		// Should fail because no IP, NOT because of flag
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no IP address to block",
			"Error should be about missing IP, not flag")
		assert.NotContains(t, err.Error(), "destructive action blocked",
			"Error should NOT mention flag blocking")
		assert.Equal(t, ActionStatusFailed, result.Status)
	})

	t.Run("IsolateHost_NotBlockedByFlag_WhenFlagEnabled", func(t *testing.T) {
		// Create IsolateHostAction with flag ENABLED
		action := NewIsolateHostAction(logger, true)

		// Execute with valid hostname
		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"hostname": "workstation-789",
		})

		// Action should NOT be blocked by flag
		if err != nil {
			assert.NotContains(t, err.Error(), "destructive action blocked",
				"When flag is enabled, error must NOT be about flag blocking")
		}

		// If no error, verify successful execution (simulation mode)
		if err == nil {
			require.NotNil(t, result)
			assert.Equal(t, ActionStatusCompleted, result.Status)
			assert.Equal(t, "workstation-789", result.Output["hostname"])
			assert.Equal(t, true, result.Output["simulated"], "Should indicate simulation mode")
		}
	})

	t.Run("IsolateHost_FailsGracefully_WithInvalidParams", func(t *testing.T) {
		// Even with flag enabled, action should validate parameters
		action := NewIsolateHostAction(logger, true)

		// Missing hostname parameter
		_, err := action.Execute(ctx, alert, map[string]interface{}{})

		// Should fail parameter validation, NOT because of flag
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hostname must be a string")
		assert.NotContains(t, err.Error(), "destructive action blocked")
	})
}

// TestNonDestructiveActionsUnaffected verifies that non-destructive actions
// are NOT affected by the destructive_actions_enabled flag
func TestNonDestructiveActionsUnaffected(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID:  "test-alert-789",
		Severity: "Medium",
		RuleID:   "test-rule",
		EventID:  "test-event",
		Event:    &core.Event{},
	}

	t.Run("UpdateAlert_WorksRegardlessOfFlag", func(t *testing.T) {
		// UpdateAlertAction should work regardless of destructive flag
		action := NewUpdateAlertAction(logger)

		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"status":   "Investigating", // Use valid AlertStatus
			"severity": "High",
		})

		// Should succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, ActionStatusCompleted, result.Status)
		assert.Equal(t, "Investigating", string(alert.Status))
		assert.Equal(t, "High", alert.Severity)
	})

	t.Run("Notify_WorksRegardlessOfFlag", func(t *testing.T) {
		// NotifyAction should work regardless of destructive flag
		action := NewNotifyAction(logger)

		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"message": "Test notification",
			"channel": "email",
		})

		// Should succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, ActionStatusCompleted, result.Status)
		assert.Contains(t, result.Message, "Notification sent")
	})

	t.Run("CreateTicket_WorksRegardlessOfFlag", func(t *testing.T) {
		// CreateTicketAction should work regardless of destructive flag
		action := NewCreateTicketAction(logger)

		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"title":       "Security Alert",
			"description": "Test ticket",
		})

		// Should succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, ActionStatusCompleted, result.Status)
		assert.Contains(t, result.Message, "Ticket created")
		assert.True(t, result.Output["simulated"].(bool))
	})
}

// TestActionResultStructure verifies that ActionResult is properly populated
// in all scenarios (success, failure, blocked)
func TestActionResultStructure(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "result-test",
		Event:   &core.Event{Fields: map[string]interface{}{"source_ip": "1.2.3.4"}},
	}

	t.Run("BlockedResult_HasCorrectStructure", func(t *testing.T) {
		action := NewBlockIPAction(logger, false)
		startTime := time.Now()

		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"ip_address": "1.2.3.4",
		})

		require.Error(t, err)
		require.NotNil(t, result)

		// Verify all required fields are populated
		assert.Equal(t, ActionTypeBlock, result.ActionType)
		assert.Equal(t, ActionStatusFailed, result.Status)
		assert.NotEmpty(t, result.Error)
		assert.False(t, result.StartedAt.IsZero())
		assert.False(t, result.CompletedAt.IsZero())
		assert.True(t, result.CompletedAt.After(result.StartedAt) || result.CompletedAt.Equal(result.StartedAt))
		assert.True(t, result.StartedAt.After(startTime) || result.StartedAt.Equal(startTime))
		// Duration may be zero on fast systems
		assert.Equal(t, result.CompletedAt.Sub(result.StartedAt), result.Duration)
		assert.NotNil(t, result.Output) // Output map should exist even on failure
	})

	t.Run("SuccessResult_HasCorrectStructure", func(t *testing.T) {
		action := NewBlockIPAction(logger, true)

		result, err := action.Execute(ctx, alert, map[string]interface{}{
			"ip_address": "203.0.113.50",
		})

		if err == nil {
			require.NotNil(t, result)
			assert.Equal(t, ActionTypeBlock, result.ActionType)
			assert.Equal(t, ActionStatusCompleted, result.Status)
			assert.Empty(t, result.Error) // No error on success
			// Duration may be zero on fast systems
			assert.NotNil(t, result.Output)
			assert.Equal(t, "203.0.113.50", result.Output["ip_address"])
		}
	})
}

// TestConcurrentActionExecution verifies thread safety when multiple actions
// execute concurrently with different flag states
func TestConcurrentActionExecution(t *testing.T) {
	logger := zap.NewNop().Sugar()
	ctx := context.Background()

	alert := &core.Alert{
		AlertID: "concurrent-test",
		Event:   &core.Event{Fields: map[string]interface{}{"source_ip": "10.20.30.40"}},
	}

	t.Run("ConcurrentBlockedAndAllowed", func(t *testing.T) {
		const goroutines = 10
		done := make(chan bool, goroutines*2)

		// Half with flag disabled, half with flag enabled
		for i := 0; i < goroutines; i++ {
			// Disabled flag
			go func(id int) {
				action := NewBlockIPAction(logger, false)
				_, err := action.Execute(ctx, alert, map[string]interface{}{
					"ip_address": "10.20.30.40",
				})
				// Should always be blocked
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "destructive action blocked")
				done <- true
			}(i)

			// Enabled flag
			go func(id int) {
				action := NewBlockIPAction(logger, true)
				result, err := action.Execute(ctx, alert, map[string]interface{}{
					"ip_address": "203.0.113.100",
				})
				// Should not be blocked by flag
				if err != nil {
					assert.NotContains(t, err.Error(), "destructive action blocked")
				} else {
					assert.Equal(t, ActionStatusCompleted, result.Status)
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < goroutines*2; i++ {
			<-done
		}
	})
}
