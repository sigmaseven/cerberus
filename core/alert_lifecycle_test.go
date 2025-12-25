package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 40: State machine validation tests
func TestAlert_TransitionTo_ValidTransitions(t *testing.T) {
	testCases := []struct {
		name      string
		from      AlertStatus
		to        AlertStatus
		shouldErr bool
	}{
		// Valid transitions
		{"Pending to Acknowledged", AlertStatusPending, AlertStatusAcknowledged, false},
		{"Pending to Closed", AlertStatusPending, AlertStatusClosed, false},
		{"Acknowledged to Investigating", AlertStatusAcknowledged, AlertStatusInvestigating, false},
		{"Acknowledged to Closed", AlertStatusAcknowledged, AlertStatusClosed, false},
		{"Investigating to Resolved", AlertStatusInvestigating, AlertStatusResolved, false},
		{"Investigating to Escalated", AlertStatusInvestigating, AlertStatusEscalated, false},
		{"Investigating to Closed", AlertStatusInvestigating, AlertStatusClosed, false},
		{"Resolved to Closed", AlertStatusResolved, AlertStatusClosed, false},
		{"Escalated to Closed", AlertStatusEscalated, AlertStatusClosed, false},
		{"Dismissed to Closed", AlertStatusDismissed, AlertStatusClosed, false},
		{"FalsePositive to Closed", AlertStatusFalsePositive, AlertStatusClosed, false},

		// Invalid transitions
		{"Pending to Resolved", AlertStatusPending, AlertStatusResolved, true},
		{"Pending to Investigating", AlertStatusPending, AlertStatusInvestigating, true},
		{"Resolved to Investigating", AlertStatusResolved, AlertStatusInvestigating, true},
		{"Closed to any state", AlertStatusClosed, AlertStatusPending, true},
		{"Closed to Acknowledged", AlertStatusClosed, AlertStatusAcknowledged, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := &Alert{
				AlertID: "alert-1",
				Status:  tc.from,
			}

			err := alert.TransitionTo(tc.to, "user-1")
			if tc.shouldErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid transition")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.to, alert.Status)
			}
		})
	}
}

func TestAlert_CanTransitionTo(t *testing.T) {
	alert := &Alert{
		AlertID: "alert-1",
		Status:  AlertStatusPending,
	}

	// Valid transitions
	assert.True(t, alert.CanTransitionTo(AlertStatusAcknowledged))
	assert.True(t, alert.CanTransitionTo(AlertStatusClosed))

	// Invalid transitions
	assert.False(t, alert.CanTransitionTo(AlertStatusResolved))
	assert.False(t, alert.CanTransitionTo(AlertStatusInvestigating))
	assert.False(t, alert.CanTransitionTo(AlertStatusEscalated))
}

func TestAlert_GetAllowedTransitions(t *testing.T) {
	testCases := []struct {
		name             string
		status           AlertStatus
		expectedCount    int
		shouldContain    []AlertStatus
		shouldNotContain []AlertStatus
	}{
		{
			name:             "Pending",
			status:           AlertStatusPending,
			expectedCount:    2,
			shouldContain:    []AlertStatus{AlertStatusAcknowledged, AlertStatusClosed},
			shouldNotContain: []AlertStatus{AlertStatusResolved, AlertStatusInvestigating},
		},
		{
			name:             "Acknowledged",
			status:           AlertStatusAcknowledged,
			expectedCount:    2,
			shouldContain:    []AlertStatus{AlertStatusInvestigating, AlertStatusClosed},
			shouldNotContain: []AlertStatus{AlertStatusPending, AlertStatusResolved},
		},
		{
			name:             "Investigating",
			status:           AlertStatusInvestigating,
			expectedCount:    3,
			shouldContain:    []AlertStatus{AlertStatusResolved, AlertStatusEscalated, AlertStatusClosed},
			shouldNotContain: []AlertStatus{AlertStatusPending, AlertStatusAcknowledged},
		},
		{
			name:             "Closed",
			status:           AlertStatusClosed,
			expectedCount:    0,
			shouldContain:    []AlertStatus{},
			shouldNotContain: []AlertStatus{AlertStatusPending, AlertStatusAcknowledged, AlertStatusInvestigating},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := &Alert{
				AlertID: "alert-1",
				Status:  tc.status,
			}

			allowed := alert.GetAllowedTransitions()
			assert.Equal(t, tc.expectedCount, len(allowed))

			for _, expected := range tc.shouldContain {
				assert.Contains(t, allowed, expected)
			}

			for _, notExpected := range tc.shouldNotContain {
				assert.NotContains(t, allowed, notExpected)
			}
		})
	}
}

func TestAlert_IsFinalState(t *testing.T) {
	testCases := []struct {
		name     string
		status   AlertStatus
		expected bool
	}{
		{"Pending", AlertStatusPending, false},
		{"Acknowledged", AlertStatusAcknowledged, false},
		{"Investigating", AlertStatusInvestigating, false},
		{"Resolved", AlertStatusResolved, false},
		{"Escalated", AlertStatusEscalated, false},
		{"Closed", AlertStatusClosed, true},
		{"Dismissed", AlertStatusDismissed, false},
		{"FalsePositive", AlertStatusFalsePositive, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := &Alert{
				AlertID: "alert-1",
				Status:  tc.status,
			}

			assert.Equal(t, tc.expected, alert.IsFinalState())
		})
	}
}

func TestAlert_TransitionTo_InvalidStatus(t *testing.T) {
	alert := &Alert{
		AlertID: "alert-1",
		Status:  AlertStatusPending,
	}

	// Empty status
	err := alert.TransitionTo("", "user-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")

	// Invalid status
	err = alert.TransitionTo(AlertStatus("invalid"), "user-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid alert status")
}

func TestAlert_TransitionTo_AutoAssign(t *testing.T) {
	alert := &Alert{
		AlertID:    "alert-1",
		Status:     AlertStatusPending,
		AssignedTo: "",
	}

	err := alert.TransitionTo(AlertStatusAcknowledged, "user-1")
	require.NoError(t, err)
	assert.Equal(t, "user-1", alert.AssignedTo)

	// Should not override existing assignment
	alert.Status = AlertStatusAcknowledged
	alert.AssignedTo = "user-2"
	err = alert.TransitionTo(AlertStatusInvestigating, "user-1")
	require.NoError(t, err)
	assert.Equal(t, "user-2", alert.AssignedTo) // Should remain user-2
}
