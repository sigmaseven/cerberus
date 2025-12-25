package core

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// EvidenceType represents the type of evidence
type EvidenceType string

const (
	EvidenceTypeLog            EvidenceType = "log"
	EvidenceTypeFile           EvidenceType = "file"
	EvidenceTypeScreenshot     EvidenceType = "screenshot"
	EvidenceTypeNetworkCapture EvidenceType = "network_capture"
	EvidenceTypeProcessDump    EvidenceType = "process_dump"
	EvidenceTypeOther          EvidenceType = "other"
)

// Evidence represents a file attachment associated with an alert or investigation
type Evidence struct {
	ID              string       `json:"id"`
	AlertID         string       `json:"alert_id,omitempty"`
	InvestigationID string       `json:"investigation_id,omitempty"`
	Type            EvidenceType `json:"type"`
	Filename        string       `json:"filename"` // Internal stored filename (UUID)
	Name            string       `json:"name"`     // Original filename for display
	MimeType        string       `json:"mime_type"`
	Size            int64        `json:"size"`
	Description     string       `json:"description,omitempty"`
	UploadedByID    string       `json:"uploaded_by_id"` // User ID who uploaded
	UploadedBy      *UserRef     `json:"uploaded_by"`    // Full user reference for API responses
	UploadedAt      time.Time    `json:"uploaded_at"`
	Hash            string       `json:"hash,omitempty"` // SHA-256 hash of file content
}

// UserRef is a minimal user reference for evidence responses
type UserRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// InferEvidenceType determines evidence type from MIME type
func InferEvidenceType(mimeType string) EvidenceType {
	switch {
	case mimeType == "text/plain" || mimeType == "application/json" || mimeType == "text/csv":
		return EvidenceTypeLog
	case mimeType == "image/png" || mimeType == "image/jpeg" || mimeType == "image/gif" || mimeType == "image/webp":
		return EvidenceTypeScreenshot
	case mimeType == "application/vnd.tcpdump.pcap" || mimeType == "application/x-pcapng":
		return EvidenceTypeNetworkCapture
	default:
		return EvidenceTypeFile
	}
}

// NewEvidence creates a new Evidence record for an alert
func NewEvidence(alertID, originalName, mimeType string, size int64, uploadedByID string) *Evidence {
	id := uuid.New().String()
	return &Evidence{
		ID:           id,
		AlertID:      alertID,
		Type:         InferEvidenceType(mimeType),
		Name:         originalName,
		Filename:     id, // Use UUID as stored filename for security
		MimeType:     mimeType,
		Size:         size,
		UploadedByID: uploadedByID,
		UploadedAt:   time.Now().UTC(),
	}
}

// NewInvestigationEvidence creates a new Evidence record for an investigation
func NewInvestigationEvidence(investigationID, originalName, mimeType string, size int64, uploadedByID string) *Evidence {
	id := uuid.New().String()
	return &Evidence{
		ID:              id,
		InvestigationID: investigationID,
		Type:            InferEvidenceType(mimeType),
		Name:            originalName,
		Filename:        id, // Use UUID as stored filename for security
		MimeType:        mimeType,
		Size:            size,
		UploadedByID:    uploadedByID,
		UploadedAt:      time.Now().UTC(),
	}
}

// ErrInvalidEvidenceParent is returned when evidence doesn't have exactly one parent
var ErrInvalidEvidenceParent = errors.New("evidence must have exactly one parent (alert_id OR investigation_id)")

// Validate checks that evidence has exactly one parent (alert OR investigation, not both)
func (e *Evidence) Validate() error {
	hasAlert := e.AlertID != ""
	hasInvestigation := e.InvestigationID != ""

	if hasAlert == hasInvestigation {
		// Both set or both empty
		return ErrInvalidEvidenceParent
	}
	return nil
}

// EvidenceStorage interface for evidence management
type EvidenceStorage interface {
	// CreateEvidence stores evidence metadata
	CreateEvidence(ctx context.Context, evidence *Evidence) error
	// GetEvidence retrieves evidence by ID
	GetEvidence(ctx context.Context, id string) (*Evidence, error)
	// ListEvidenceByAlert lists all evidence for an alert
	ListEvidenceByAlert(ctx context.Context, alertID string) ([]*Evidence, error)
	// ListEvidenceByInvestigation lists all evidence for an investigation
	ListEvidenceByInvestigation(ctx context.Context, investigationID string) ([]*Evidence, error)
	// DeleteEvidence removes evidence metadata
	DeleteEvidence(ctx context.Context, id string) error
}
