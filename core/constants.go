package core

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	// AlertStatusPending indicates an alert that hasn't been reviewed
	AlertStatusPending AlertStatus = "Pending"
	// AlertStatusAcknowledged indicates an alert that has been reviewed and acknowledged
	AlertStatusAcknowledged AlertStatus = "Acknowledged"
	// AlertStatusDismissed indicates an alert that has been dismissed as false positive
	AlertStatusDismissed AlertStatus = "Dismissed"
)

// String returns the string representation
func (s AlertStatus) String() string {
	return string(s)
}

// IsValid checks if the status is valid
func (s AlertStatus) IsValid() bool {
	switch s {
	case AlertStatusPending, AlertStatusAcknowledged, AlertStatusDismissed:
		return true
	default:
		return false
	}
}
