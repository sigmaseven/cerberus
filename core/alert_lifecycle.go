package core

import (
	"errors"
	"fmt"
)

// validTransitions defines allowed state transitions for alerts (TASK 40)
var validTransitions = map[AlertStatus][]AlertStatus{
	AlertStatusPending:       {AlertStatusAcknowledged, AlertStatusClosed},
	AlertStatusAcknowledged:  {AlertStatusInvestigating, AlertStatusClosed},
	AlertStatusInvestigating: {AlertStatusResolved, AlertStatusEscalated, AlertStatusClosed},
	AlertStatusResolved:      {AlertStatusClosed},
	AlertStatusEscalated:     {AlertStatusClosed},
	AlertStatusClosed:        {},                  // Final state - no transitions allowed
	AlertStatusDismissed:     {AlertStatusClosed}, // Dismissed can only transition to Closed
	AlertStatusFalsePositive: {AlertStatusClosed}, // FalsePositive can only transition to Closed
}

// TransitionTo validates and executes an alert state transition (TASK 40)
// Returns error if transition is invalid
func (a *Alert) TransitionTo(newStatus AlertStatus, userID string) error {
	if newStatus == "" {
		return errors.New("new status cannot be empty")
	}

	if !newStatus.IsValid() {
		return fmt.Errorf("invalid alert status: %s", newStatus)
	}

	// Check if transition is allowed
	allowedTransitions, exists := validTransitions[a.Status]
	if !exists {
		return fmt.Errorf("unknown current status: %s", a.Status)
	}

	// Check if new status is in allowed transitions
	allowed := false
	for _, status := range allowedTransitions {
		if status == newStatus {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("invalid transition: %s → %s (allowed: %v)", a.Status, newStatus, allowedTransitions)
	}

	// Execute transition
	a.Status = newStatus

	// Update metadata
	if a.AssignedTo == "" && userID != "" {
		// Auto-assign if not already assigned
		a.AssignedTo = userID
	}

	// Note: UpdatedBy and UpdatedAt would be set by the storage layer
	// For now, we just validate the transition

	return nil
}

// CanTransitionTo checks if a transition is allowed without executing it (TASK 40)
func (a *Alert) CanTransitionTo(newStatus AlertStatus) bool {
	if !newStatus.IsValid() {
		return false
	}

	allowedTransitions, exists := validTransitions[a.Status]
	if !exists {
		return false
	}

	for _, status := range allowedTransitions {
		if status == newStatus {
			return true
		}
	}

	return false
}

// GetAllowedTransitions returns all valid transitions from the current state (TASK 40)
func (a *Alert) GetAllowedTransitions() []AlertStatus {
	allowedTransitions, exists := validTransitions[a.Status]
	if !exists {
		return []AlertStatus{}
	}

	// Return a copy to prevent external modification
	result := make([]AlertStatus, len(allowedTransitions))
	copy(result, allowedTransitions)
	return result
}

// IsFinalState checks if the alert is in a final state (TASK 40)
func (a *Alert) IsFinalState() bool {
	allowedTransitions, exists := validTransitions[a.Status]
	if !exists {
		return false
	}
	return len(allowedTransitions) == 0
}
