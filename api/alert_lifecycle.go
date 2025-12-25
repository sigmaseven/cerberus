package api

import (
	"cerberus/core"
)

// AcknowledgeRequest represents a request to acknowledge an alert
type AcknowledgeRequest struct {
	Note string `json:"note"`
}

// AssignRequest represents a request to assign an alert
type AssignRequest struct {
	AssignTo string `json:"assign_to"`
	Note     string `json:"note"`
}

// UpdateStatusRequest represents a request to update alert status
type UpdateStatusRequest struct {
	Status core.AlertStatus `json:"status"`
	Note   string           `json:"note"`
}

// ResolveRequest represents a request to resolve an alert
type ResolveRequest struct {
	Status          core.AlertStatus `json:"status"`
	ResolutionNotes string           `json:"resolution_notes"`
}
