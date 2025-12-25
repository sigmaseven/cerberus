package core

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AlertLinkType constants define standard link types between alerts
const (
	AlertLinkTypeRelated     = "related"     // Alerts are related but not directly connected
	AlertLinkTypeDuplicate   = "duplicate"   // Alert is a duplicate of another
	AlertLinkTypeEscalation  = "escalation"  // Alert escalated to another (e.g., higher severity)
	AlertLinkTypeCorrelation = "correlation" // Alerts are correlated by a correlation rule
	AlertLinkTypeCausedBy    = "caused_by"   // Alert was caused by another alert's activity
)

// AlertLink represents a bi-directional relationship between two alerts
type AlertLink struct {
	ID          string    `json:"id"`
	AlertID     string    `json:"alert_id"`
	LinkedID    string    `json:"linked_alert_id"`
	LinkType    string    `json:"link_type,omitempty"` // e.g., "related", "duplicate", "escalation"
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// AlertLinkRequest is the request body for linking alerts
type AlertLinkRequest struct {
	LinkedAlertID string `json:"linked_alert_id"`
	LinkType      string `json:"link_type,omitempty"`
	Description   string `json:"description,omitempty"`
}

// AlertLinkResponse is the response when listing related alerts
type AlertLinkResponse struct {
	AlertID     string      `json:"alert_id"`
	LinkedAlert *AlertBrief `json:"linked_alert"`
	LinkType    string      `json:"link_type,omitempty"`
	Description string      `json:"description,omitempty"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
}

// AlertBrief is a minimal representation of an alert for link responses
type AlertBrief struct {
	AlertID   string    `json:"alert_id"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name,omitempty"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// NewAlertLink creates a new AlertLink with generated ID
func NewAlertLink(alertID, linkedID, linkType, description, createdBy string) *AlertLink {
	return &AlertLink{
		ID:          uuid.New().String(),
		AlertID:     alertID,
		LinkedID:    linkedID,
		LinkType:    linkType,
		Description: description,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}
}

// AlertLinkStorage defines the interface for alert link persistence
type AlertLinkStorage interface {
	// CreateLink creates a bi-directional link between two alerts
	// This automatically creates the reverse link (B->A when linking A->B)
	CreateLink(ctx context.Context, link *AlertLink) error

	// GetLinkedAlerts returns all alerts linked to the given alert ID
	GetLinkedAlerts(ctx context.Context, alertID string) ([]*AlertLink, error)

	// DeleteLink removes a bi-directional link between two alerts
	// This automatically removes both directions
	DeleteLink(ctx context.Context, alertID, linkedAlertID string) error

	// LinkExists checks if a link already exists between two alerts
	LinkExists(ctx context.Context, alertID, linkedAlertID string) (bool, error)
}
