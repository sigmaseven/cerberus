package core

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// InvestigationStatus represents the current state of an investigation
type InvestigationStatus string

const (
	InvestigationStatusOpen           InvestigationStatus = "open"
	InvestigationStatusInProgress     InvestigationStatus = "in_progress"
	InvestigationStatusInvestigating  InvestigationStatus = "in_progress" // TASK 51.4: Alias for InProgress for backward compatibility
	InvestigationStatusAwaitingReview InvestigationStatus = "awaiting_review"
	InvestigationStatusClosed         InvestigationStatus = "closed"
	InvestigationStatusResolved       InvestigationStatus = "resolved"
	InvestigationStatusFalsePositive  InvestigationStatus = "false_positive"
)

// IsValid checks if the investigation status is valid
func (s InvestigationStatus) IsValid() bool {
	switch s {
	case InvestigationStatusOpen,
		InvestigationStatusInProgress,
		// TASK 51.4: InvestigationStatusInvestigating is an alias for InvestigationStatusInProgress (both = "in_progress")
		InvestigationStatusAwaitingReview,
		InvestigationStatusClosed,
		InvestigationStatusResolved,
		InvestigationStatusFalsePositive:
		return true
	}
	return false
}

// InvestigationPriority represents the priority level of an investigation
type InvestigationPriority string

const (
	InvestigationPriorityCritical InvestigationPriority = "critical"
	InvestigationPriorityHigh     InvestigationPriority = "high"
	InvestigationPriorityMedium   InvestigationPriority = "medium"
	InvestigationPriorityLow      InvestigationPriority = "low"
)

// IsValid checks if the investigation priority is valid
func (p InvestigationPriority) IsValid() bool {
	switch p {
	case InvestigationPriorityCritical,
		InvestigationPriorityHigh,
		InvestigationPriorityMedium,
		InvestigationPriorityLow:
		return true
	}
	return false
}

// InvestigationVerdict represents the final verdict of an investigation
type InvestigationVerdict string

const (
	InvestigationVerdictTruePositive  InvestigationVerdict = "true_positive"
	InvestigationVerdictFalsePositive InvestigationVerdict = "false_positive"
	InvestigationVerdictInconclusive  InvestigationVerdict = "inconclusive"
)

// TriggerSource constants define how an investigation was created
const (
	TriggerSourceManual      = "manual"      // Created manually by analyst
	TriggerSourceCorrelation = "correlation" // Auto-created by correlation rule match
	TriggerSourcePlaybook    = "playbook"    // Created by automated playbook
	TriggerSourceMLAlert     = "ml_alert"    // Created by ML anomaly detection
)

// IsValid checks if the investigation verdict is valid
func (v InvestigationVerdict) IsValid() bool {
	switch v {
	case InvestigationVerdictTruePositive,
		InvestigationVerdictFalsePositive,
		InvestigationVerdictInconclusive:
		return true
	}
	return false
}

// InvestigationNote represents a note in an investigation
type InvestigationNote struct {
	ID        string    `json:"id" bson:"id"`
	AnalystID string    `json:"analyst_id" bson:"analyst_id"`
	Content   string    `json:"content" bson:"content"`
	CreatedAt time.Time `json:"created_at" bson:"created_at" swaggertype:"string"`
}

// InvestigationArtifacts represents extracted artifacts from an investigation
type InvestigationArtifacts struct {
	IPs       []string `json:"ips,omitempty" bson:"ips,omitempty"`
	Hosts     []string `json:"hosts,omitempty" bson:"hosts,omitempty"`
	Users     []string `json:"users,omitempty" bson:"users,omitempty"`
	Files     []string `json:"files,omitempty" bson:"files,omitempty"`
	Hashes    []string `json:"hashes,omitempty" bson:"hashes,omitempty"`
	Processes []string `json:"processes,omitempty" bson:"processes,omitempty"`
}

// MLFeedback represents analyst feedback on ML assistance
type MLFeedback struct {
	UseForTraining  bool   `json:"use_for_training" bson:"use_for_training"`
	MLQualityRating int    `json:"ml_quality_rating" bson:"ml_quality_rating"` // 1-5 stars
	MLHelpfulness   string `json:"ml_helpfulness" bson:"ml_helpfulness"`       // very_helpful, somewhat, not_helpful
}

// Investigation represents a security investigation
type Investigation struct {
	InvestigationID    string                 `json:"investigation_id" bson:"investigation_id" example:"INV-20250108-0042"`
	Title              string                 `json:"title" bson:"title" validate:"required,min=1,max=200" example:"Suspected Lateral Movement"`
	Description        string                 `json:"description" bson:"description" validate:"max=2000" example:"Multiple failed login attempts followed by successful authentication"`
	Priority           InvestigationPriority  `json:"priority" bson:"priority" validate:"required" example:"critical"`
	Status             InvestigationStatus    `json:"status" bson:"status" validate:"required" example:"in_progress"`
	AssigneeID         string                 `json:"assignee_id" bson:"assignee_id" example:"user123"`
	CreatedBy          string                 `json:"created_by" bson:"created_by" example:"user123"`
	CreatedAt          time.Time              `json:"created_at" bson:"created_at" swaggertype:"string" example:"2025-01-08T10:23:00Z"`
	UpdatedAt          time.Time              `json:"updated_at" bson:"updated_at" swaggertype:"string" example:"2025-01-08T15:05:00Z"`
	ClosedAt           *time.Time             `json:"closed_at,omitempty" bson:"closed_at,omitempty" swaggertype:"string"`
	AlertIDs           []string               `json:"alert_ids" bson:"alert_ids" example:"alert-001,alert-002"`
	EventIDs           []string               `json:"event_ids,omitempty" bson:"event_ids,omitempty" example:"event-001,event-002"`
	MitreTactics       []string               `json:"mitre_tactics" bson:"mitre_tactics" example:"TA0001,TA0006"`
	MitreTechniques    []string               `json:"mitre_techniques" bson:"mitre_techniques" example:"T1078,T1110"`
	Artifacts          InvestigationArtifacts `json:"artifacts,omitempty" bson:"artifacts,omitempty"`
	Notes              []InvestigationNote    `json:"notes,omitempty" bson:"notes,omitempty"`
	Verdict            InvestigationVerdict   `json:"verdict,omitempty" bson:"verdict,omitempty" example:"true_positive"`
	ResolutionCategory string                 `json:"resolution_category,omitempty" bson:"resolution_category,omitempty" example:"incident_contained"`
	Summary            string                 `json:"summary,omitempty" bson:"summary,omitempty" validate:"max=5000"`
	AffectedAssets     []string               `json:"affected_assets,omitempty" bson:"affected_assets,omitempty"`
	MLFeedback         *MLFeedback            `json:"ml_feedback,omitempty" bson:"ml_feedback,omitempty"`
	Tags               []string               `json:"tags,omitempty" bson:"tags,omitempty"`

	// Correlation trigger fields - track how investigation was created
	// TriggerSource indicates how this investigation was created ("manual", "correlation", "playbook", "ml_alert")
	TriggerSource string `json:"trigger_source,omitempty" bson:"trigger_source,omitempty" example:"correlation"`
	// TriggerAlertID is the ID of the correlation alert that spawned this investigation (when TriggerSource is "correlation")
	TriggerAlertID string `json:"trigger_alert_id,omitempty" bson:"trigger_alert_id,omitempty" example:"alert-corr-001"`
	// CorrelationRuleID is the ID of the correlation rule that triggered this investigation
	CorrelationRuleID string `json:"correlation_rule_id,omitempty" bson:"correlation_rule_id,omitempty" example:"corr-rule-001"`
}

// IsValidStatus checks if the investigation status is valid
func (i *Investigation) IsValidStatus() bool {
	return i.Status.IsValid()
}

// IsValidPriority checks if the investigation priority is valid
func (i *Investigation) IsValidPriority() bool {
	return i.Priority.IsValid()
}

// IsValidVerdict checks if the investigation verdict is valid
func (i *Investigation) IsValidVerdict() bool {
	if i.Verdict == "" {
		return true // Verdict is optional until investigation is closed
	}
	return i.Verdict.IsValid()
}

// Validate performs validation on the investigation
func (i *Investigation) Validate() error {
	if i.Title == "" {
		return fmt.Errorf("investigation title is required")
	}
	if len(i.Title) > 200 {
		return fmt.Errorf("investigation title too long (max 200 characters)")
	}
	if !i.IsValidStatus() {
		return fmt.Errorf("invalid investigation status: %s", i.Status)
	}
	if !i.IsValidPriority() {
		return fmt.Errorf("invalid investigation priority: %s", i.Priority)
	}
	if !i.IsValidVerdict() {
		return fmt.Errorf("invalid investigation verdict: %s", i.Verdict)
	}
	if len(i.Description) > 2000 {
		return fmt.Errorf("investigation description too long (max 2000 characters)")
	}
	if len(i.Summary) > 5000 {
		return fmt.Errorf("investigation summary too long (max 5000 characters)")
	}
	if i.MLFeedback != nil {
		if i.MLFeedback.MLQualityRating < 1 || i.MLFeedback.MLQualityRating > 5 {
			return fmt.Errorf("ML quality rating must be between 1 and 5")
		}
	}
	return nil
}

// NewInvestigation creates a new Investigation with generated ID
func NewInvestigation(title, description string, priority InvestigationPriority, createdBy string) *Investigation {
	now := time.Now().UTC()
	return &Investigation{
		InvestigationID: generateInvestigationID(now),
		Title:           title,
		Description:     description,
		Priority:        priority,
		Status:          InvestigationStatusOpen,
		CreatedBy:       createdBy,
		AssigneeID:      createdBy, // Default to creator
		CreatedAt:       now,
		UpdatedAt:       now,
		AlertIDs:        []string{},
		EventIDs:        []string{},
		MitreTactics:    []string{},
		MitreTechniques: []string{},
		Notes:           []InvestigationNote{},
		Tags:            []string{},
		TriggerSource:   TriggerSourceManual, // Default to manual creation
	}
}

// NewCorrelationTriggeredInvestigation creates an investigation triggered by a correlation rule match.
// It automatically links the correlation alert and all contributing alerts.
// Parameters:
//   - correlationRuleID: ID of the correlation rule that triggered this
//   - correlationAlertID: ID of the alert generated by the correlation rule
//   - contributingAlertIDs: IDs of the alerts that contributed to the correlation match
//   - title, description: Investigation details
//   - priority: Investigation priority
func NewCorrelationTriggeredInvestigation(
	correlationRuleID string,
	correlationAlertID string,
	contributingAlertIDs []string,
	title, description string,
	priority InvestigationPriority,
) *Investigation {
	now := time.Now().UTC()

	// Combine correlation alert with contributing alerts
	allAlertIDs := make([]string, 0, len(contributingAlertIDs)+1)
	allAlertIDs = append(allAlertIDs, correlationAlertID)
	allAlertIDs = append(allAlertIDs, contributingAlertIDs...)

	return &Investigation{
		InvestigationID:   generateInvestigationID(now),
		Title:             title,
		Description:       description,
		Priority:          priority,
		Status:            InvestigationStatusOpen,
		CreatedBy:         "system", // System-generated by correlation
		AssigneeID:        "",       // No default assignee for automated investigations
		CreatedAt:         now,
		UpdatedAt:         now,
		AlertIDs:          allAlertIDs,
		EventIDs:          []string{},
		MitreTactics:      []string{},
		MitreTechniques:   []string{},
		Notes:             []InvestigationNote{},
		Tags:              []string{"correlation-triggered"},
		TriggerSource:     TriggerSourceCorrelation,
		TriggerAlertID:    correlationAlertID,
		CorrelationRuleID: correlationRuleID,
	}
}

// generateInvestigationID generates a unique investigation ID in format INV-YYYYMMDD-####
func generateInvestigationID(timestamp time.Time) string {
	dateStr := timestamp.Format("20060102")
	shortUUID := uuid.New().String()[:4] // First 4 chars of UUID for uniqueness
	return fmt.Sprintf("INV-%s-%s", dateStr, shortUUID)
}

// AddNote adds a note to the investigation
func (i *Investigation) AddNote(analystID, content string) {
	note := InvestigationNote{
		ID:        uuid.New().String(),
		AnalystID: analystID,
		Content:   content,
		CreatedAt: time.Now().UTC(),
	}
	i.Notes = append(i.Notes, note)
	i.UpdatedAt = time.Now().UTC()
}

// AddAlert adds an alert to the investigation
func (i *Investigation) AddAlert(alertID string) {
	// Check if alert already exists
	for _, id := range i.AlertIDs {
		if id == alertID {
			return
		}
	}
	i.AlertIDs = append(i.AlertIDs, alertID)
	i.UpdatedAt = time.Now().UTC()
}

// AddMitreTactic adds a MITRE tactic to the investigation
func (i *Investigation) AddMitreTactic(tacticID string) {
	// Check if tactic already exists
	for _, id := range i.MitreTactics {
		if id == tacticID {
			return
		}
	}
	i.MitreTactics = append(i.MitreTactics, tacticID)
	i.UpdatedAt = time.Now().UTC()
}

// AddMitreTechnique adds a MITRE technique to the investigation
func (i *Investigation) AddMitreTechnique(techniqueID string) {
	// Check if technique already exists
	for _, id := range i.MitreTechniques {
		if id == techniqueID {
			return
		}
	}
	i.MitreTechniques = append(i.MitreTechniques, techniqueID)
	i.UpdatedAt = time.Now().UTC()
}

// Close closes the investigation with a verdict
func (i *Investigation) Close(verdict InvestigationVerdict, resolutionCategory, summary string, affectedAssets []string, mlFeedback *MLFeedback) error {
	if !verdict.IsValid() {
		return fmt.Errorf("invalid verdict: %s", verdict)
	}

	now := time.Now().UTC()
	i.Status = InvestigationStatusClosed
	i.Verdict = verdict
	i.ResolutionCategory = resolutionCategory
	i.Summary = summary
	i.AffectedAssets = affectedAssets
	i.MLFeedback = mlFeedback
	i.ClosedAt = &now
	i.UpdatedAt = now

	return nil
}
