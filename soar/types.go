package soar

import (
	"context"
	"time"

	"cerberus/core"
)

// ActionType represents different types of automated actions
type ActionType string

const (
	// ActionTypeBlock represents blocking an IP address
	ActionTypeBlock        ActionType = "block_ip"
	ActionTypeIsolate      ActionType = "isolate_host"
	ActionTypeQuarantine   ActionType = "quarantine_file"
	ActionTypeNotify       ActionType = "send_notification"
	ActionTypeEnrich       ActionType = "enrich_ioc"
	ActionTypeCreateTicket ActionType = "create_ticket"
	ActionTypeUpdateAlert  ActionType = "update_alert"
	ActionTypeWebhook      ActionType = "call_webhook"
	ActionTypeScript       ActionType = "run_script"
)

// ActionStatus represents the status of an action execution
type ActionStatus string

const (
	// ActionStatusPending represents a pending action
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusRunning   ActionStatus = "running"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
	ActionStatusSkipped   ActionStatus = "skipped"
)

// Action represents an automated response action
type Action interface {
	// Execute runs the action with the given context and parameters
	Execute(ctx context.Context, alert *core.Alert, params map[string]interface{}) (*ActionResult, error)

	// Type returns the action type
	Type() ActionType

	// Name returns a human-readable name
	Name() string

	// Description returns a description of what the action does
	Description() string

	// ValidateParams validates the action parameters
	ValidateParams(params map[string]interface{}) error
}

// ActionResult represents the result of an action execution
type ActionResult struct {
	ActionType  ActionType             `json:"action_type"`
	Status      ActionStatus           `json:"status"`
	Message     string                 `json:"message"`
	Output      map[string]interface{} `json:"output"`
	Error       string                 `json:"error,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	Duration    time.Duration          `json:"duration"`
}

// PlaybookCondition represents a condition that must be met for a playbook to execute
type PlaybookCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, contains, matches
	Value    interface{} `json:"value"`
}

// PlaybookStep represents a step in a playbook
type PlaybookStep struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	ActionType      ActionType             `json:"action_type"`
	Parameters      map[string]interface{} `json:"parameters"`
	ContinueOnError bool                   `json:"continue_on_error"`
	Timeout         time.Duration          `json:"timeout"`
	Conditions      []PlaybookCondition    `json:"conditions,omitempty"`
	Approval        *ApprovalConfig        `json:"approval,omitempty"` // Approval requirements for this step
}

// Playbook represents an automated response workflow
type Playbook struct {
	ID          string            `json:"id" bson:"_id,omitempty"`
	Name        string            `json:"name" bson:"name"`
	Description string            `json:"description" bson:"description"`
	Enabled     bool              `json:"enabled" bson:"enabled"`
	Triggers    []PlaybookTrigger `json:"triggers" bson:"triggers"`
	Steps       []PlaybookStep    `json:"steps" bson:"steps"`
	CreatedBy   string            `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time         `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" bson:"updated_at"`
	Tags        []string          `json:"tags" bson:"tags"`
	Priority    int               `json:"priority" bson:"priority"` // Higher priority runs first
}

// PlaybookTrigger defines when a playbook should be triggered
type PlaybookTrigger struct {
	Type       string              `json:"type"` // alert, severity, rule_id, ioc_type
	Conditions []PlaybookCondition `json:"conditions"`
}

// PlaybookExecution represents a playbook execution instance
type PlaybookExecution struct {
	ID           string                   `json:"id" bson:"_id,omitempty"`
	PlaybookID   string                   `json:"playbook_id" bson:"playbook_id"`
	PlaybookName string                   `json:"playbook_name" bson:"playbook_name"`
	AlertID      string                   `json:"alert_id" bson:"alert_id"`
	Status       ActionStatus             `json:"status" bson:"status"`
	StartedAt    time.Time                `json:"started_at" bson:"started_at"`
	CompletedAt  time.Time                `json:"completed_at" bson:"completed_at"`
	Duration     time.Duration            `json:"duration" bson:"duration"`
	StepResults  map[string]*ActionResult `json:"step_results" bson:"step_results"`
	Error        string                   `json:"error,omitempty" bson:"error,omitempty"`
	Metadata     map[string]interface{}   `json:"metadata" bson:"metadata"`
}

// PlaybookEngine interface for executing playbooks
type PlaybookEngine interface {
	// ExecutePlaybook executes a playbook for an alert
	ExecutePlaybook(ctx context.Context, playbook *Playbook, alert *core.Alert) (*PlaybookExecution, error)

	// ShouldTrigger checks if a playbook should be triggered for an alert
	ShouldTrigger(playbook *Playbook, alert *core.Alert) bool

	// RegisterAction registers a new action type
	RegisterAction(action Action)

	// GetAction retrieves a registered action by type
	GetAction(actionType ActionType) (Action, error)
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

const (
	ApprovalStatusPending   ApprovalStatus = "pending"
	ApprovalStatusApproved  ApprovalStatus = "approved"
	ApprovalStatusRejected  ApprovalStatus = "rejected"
	ApprovalStatusExpired   ApprovalStatus = "expired"
	ApprovalStatusEscalated ApprovalStatus = "escalated"
	ApprovalStatusCancelled ApprovalStatus = "cancelled"
)

// ApprovalMode defines how approvals are evaluated
type ApprovalMode string

const (
	// ApprovalModeAny - any single approver can approve/reject
	ApprovalModeAny ApprovalMode = "any"
	// ApprovalModeAll - all designated approvers must approve
	ApprovalModeAll ApprovalMode = "all"
	// ApprovalModeMajority - majority of approvers must approve
	ApprovalModeMajority ApprovalMode = "majority"
)

// ApprovalActionType represents the type of action taken on an approval
type ApprovalActionType string

const (
	ApprovalActionApprove  ApprovalActionType = "approve"
	ApprovalActionReject   ApprovalActionType = "reject"
	ApprovalActionEscalate ApprovalActionType = "escalate"
	ApprovalActionComment  ApprovalActionType = "comment"
)

// ApprovalConfig defines approval requirements for a playbook step
type ApprovalConfig struct {
	Required         bool           `json:"required"`
	Mode             ApprovalMode   `json:"mode"`
	RequiredApprovers []string      `json:"required_approvers,omitempty"` // User IDs or role names
	MinApprovers     int            `json:"min_approvers,omitempty"`      // Minimum number of approvers
	TimeoutMinutes   int            `json:"timeout_minutes"`              // Auto-expire after this time
	EscalationConfig *EscalationConfig `json:"escalation_config,omitempty"`
	AllowSelfApproval bool          `json:"allow_self_approval"`
}

// EscalationConfig defines escalation behavior when approval times out
type EscalationConfig struct {
	Enabled            bool     `json:"enabled"`
	EscalateAfterMins  int      `json:"escalate_after_mins"`
	EscalateTo         []string `json:"escalate_to"` // User IDs or roles to escalate to
	MaxEscalationLevel int      `json:"max_escalation_level"`
}

// ApprovalRequest represents a request for approval to proceed with a playbook step
type ApprovalRequest struct {
	ID               string         `json:"id"`
	ExecutionID      string         `json:"execution_id"`
	PlaybookID       string         `json:"playbook_id"`
	PlaybookName     string         `json:"playbook_name"`
	StepID           string         `json:"step_id"`
	StepName         string         `json:"step_name"`
	AlertID          string         `json:"alert_id"`
	RequestedBy      string         `json:"requested_by"`
	Status           ApprovalStatus `json:"status"`
	Mode             ApprovalMode   `json:"mode"`
	RequiredApprovers []string      `json:"required_approvers"`
	MinApprovers     int            `json:"min_approvers"`
	ApprovalCount    int            `json:"approval_count"`
	RejectionCount   int            `json:"rejection_count"`
	EscalationLevel  int            `json:"escalation_level"`
	Context          map[string]interface{} `json:"context,omitempty"` // Alert details, step params, etc.
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	ResolvedAt       *time.Time     `json:"resolved_at,omitempty"`
	Version          int            `json:"version"` // For optimistic locking
}

// ApprovalAction represents an action taken on an approval request
type ApprovalAction struct {
	ID         string             `json:"id"`
	ApprovalID string             `json:"approval_id"`
	UserID     string             `json:"user_id"`
	Username   string             `json:"username"`
	Action     ApprovalActionType `json:"action"`
	Comment    string             `json:"comment,omitempty"`
	CreatedAt  time.Time          `json:"created_at"`
}

// ApprovalStats provides statistics about approval requests
type ApprovalStats struct {
	TotalPending   int `json:"total_pending"`
	TotalApproved  int `json:"total_approved"`
	TotalRejected  int `json:"total_rejected"`
	TotalExpired   int `json:"total_expired"`
	TotalEscalated int `json:"total_escalated"`
	AvgResponseTimeMinutes float64 `json:"avg_response_time_minutes"`
}

// ApprovalFilter defines filters for querying approval requests
type ApprovalFilter struct {
	Status      []ApprovalStatus `json:"status,omitempty"`
	PlaybookID  string           `json:"playbook_id,omitempty"`
	AlertID     string           `json:"alert_id,omitempty"`
	RequestedBy string           `json:"requested_by,omitempty"`
	ApproverID  string           `json:"approver_id,omitempty"` // Filter by approver
	Limit       int              `json:"limit,omitempty"`
	Offset      int              `json:"offset,omitempty"`
}
