package soar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ApprovalService handles playbook step approval workflow
type ApprovalService struct {
	storage         ApprovalStorage
	notifier        ApprovalNotifier
	logger          *zap.SugaredLogger
	expirationTicker *time.Ticker
	stopCh          chan struct{}
	wg              sync.WaitGroup
	mu              sync.RWMutex
	// Map of execution IDs waiting for approval -> channels to signal when resolved
	waitingApprovals map[string]chan ApprovalResult
}

// ApprovalStorage defines the interface for approval persistence
type ApprovalStorage interface {
	CreateApprovalRequest(request *ApprovalRequest) error
	GetApprovalRequest(id string) (*ApprovalRequest, error)
	GetApprovalRequestByExecution(executionID, stepID string) (*ApprovalRequest, error)
	GetApprovalRequests(filter *ApprovalFilter) ([]ApprovalRequest, int64, error)
	GetPendingApprovals(approverID string, limit, offset int) ([]ApprovalRequest, error)
	ProcessApprovalAction(approvalID, userID, username string, action ApprovalActionType, comment string, expectedVersion int) (*ApprovalRequest, error)
	GetApprovalActions(approvalID string) ([]ApprovalAction, error)
	ExpireApprovals() (int64, error)
	CancelApprovalRequest(id, userID string) error
	GetApprovalStats() (*ApprovalStats, error)
}

// ApprovalNotifier sends notifications about approval events
type ApprovalNotifier interface {
	NotifyApprovalRequired(request *ApprovalRequest) error
	NotifyApprovalResolved(request *ApprovalRequest) error
	NotifyApprovalExpiring(request *ApprovalRequest, timeRemaining time.Duration) error
}

// ApprovalResult represents the outcome of an approval request
type ApprovalResult struct {
	Approved bool
	Request  *ApprovalRequest
	Error    error
}

// NoOpApprovalNotifier is a no-op implementation of ApprovalNotifier
type NoOpApprovalNotifier struct{}

func (n *NoOpApprovalNotifier) NotifyApprovalRequired(request *ApprovalRequest) error {
	return nil
}
func (n *NoOpApprovalNotifier) NotifyApprovalResolved(request *ApprovalRequest) error {
	return nil
}
func (n *NoOpApprovalNotifier) NotifyApprovalExpiring(request *ApprovalRequest, timeRemaining time.Duration) error {
	return nil
}

// NewApprovalService creates a new approval service
func NewApprovalService(storage ApprovalStorage, notifier ApprovalNotifier, logger *zap.SugaredLogger) *ApprovalService {
	if notifier == nil {
		notifier = &NoOpApprovalNotifier{}
	}

	return &ApprovalService{
		storage:          storage,
		notifier:         notifier,
		logger:           logger,
		waitingApprovals: make(map[string]chan ApprovalResult),
		stopCh:           make(chan struct{}),
	}
}

// Start begins the approval service background tasks (expiration checker)
func (as *ApprovalService) Start() {
	as.expirationTicker = time.NewTicker(1 * time.Minute)
	as.wg.Add(1)

	go func() {
		defer as.wg.Done()
		for {
			select {
			case <-as.expirationTicker.C:
				as.checkExpiredApprovals()
			case <-as.stopCh:
				return
			}
		}
	}()

	as.logger.Info("Approval service started")
}

// Stop stops the approval service
func (as *ApprovalService) Stop() {
	close(as.stopCh)
	if as.expirationTicker != nil {
		as.expirationTicker.Stop()
	}
	as.wg.Wait()
	as.logger.Info("Approval service stopped")
}

// checkExpiredApprovals marks expired approvals and notifies waiting executions
func (as *ApprovalService) checkExpiredApprovals() {
	count, err := as.storage.ExpireApprovals()
	if err != nil {
		as.logger.Errorf("Failed to expire approvals: %v", err)
		return
	}

	if count > 0 {
		as.logger.Infof("Expired %d approval requests", count)
	}
}

// RequestApproval creates a new approval request for a playbook step
func (as *ApprovalService) RequestApproval(
	ctx context.Context,
	execution *PlaybookExecution,
	step *PlaybookStep,
	alert *core.Alert,
	requestedBy string,
) (*ApprovalRequest, error) {
	if step.Approval == nil || !step.Approval.Required {
		return nil, errors.New("step does not require approval")
	}

	config := step.Approval

	// Calculate expiration time
	timeout := time.Duration(config.TimeoutMinutes) * time.Minute
	if timeout == 0 {
		timeout = 24 * time.Hour // Default 24-hour timeout
	}

	// Build context for approvers
	approvalContext := map[string]interface{}{
		"playbook_name": execution.PlaybookName,
		"step_name":     step.Name,
		"action_type":   string(step.ActionType),
		"parameters":    step.Parameters,
	}

	if alert != nil {
		approvalContext["alert"] = map[string]interface{}{
			"id":        alert.AlertID,
			"severity":  alert.Severity,
			"rule_name": alert.RuleName,
			"timestamp": alert.Timestamp,
		}
	}

	request := &ApprovalRequest{
		ID:                uuid.New().String(),
		ExecutionID:       execution.ID,
		PlaybookID:        execution.PlaybookID,
		PlaybookName:      execution.PlaybookName,
		StepID:            step.ID,
		StepName:          step.Name,
		AlertID:           execution.AlertID,
		RequestedBy:       requestedBy,
		Status:            ApprovalStatusPending,
		Mode:              config.Mode,
		RequiredApprovers: config.RequiredApprovers,
		MinApprovers:      config.MinApprovers,
		ApprovalCount:     0,
		RejectionCount:    0,
		EscalationLevel:   0,
		Context:           approvalContext,
		ExpiresAt:         time.Now().Add(timeout),
	}

	// If no mode specified, default to "any"
	if request.Mode == "" {
		request.Mode = ApprovalModeAny
	}

	// If no min approvers specified, default to 1
	if request.MinApprovers == 0 {
		request.MinApprovers = 1
	}

	// Create the approval request
	if err := as.storage.CreateApprovalRequest(request); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	// Notify approvers
	if err := as.notifier.NotifyApprovalRequired(request); err != nil {
		as.logger.Warnf("Failed to notify approvers for request %s: %v", request.ID, err)
	}

	as.logger.Infof("Created approval request %s for execution %s step %s",
		request.ID, execution.ID, step.ID)

	return request, nil
}

// WaitForApproval blocks until the approval is resolved or context is cancelled
func (as *ApprovalService) WaitForApproval(ctx context.Context, request *ApprovalRequest) (*ApprovalResult, error) {
	// Create a channel for this approval
	resultCh := make(chan ApprovalResult, 1)
	key := fmt.Sprintf("%s:%s", request.ExecutionID, request.StepID)

	as.mu.Lock()
	as.waitingApprovals[key] = resultCh
	as.mu.Unlock()

	defer func() {
		as.mu.Lock()
		delete(as.waitingApprovals, key)
		as.mu.Unlock()
	}()

	// Calculate timeout based on request expiration
	timeout := time.Until(request.ExpiresAt)
	if timeout <= 0 {
		return &ApprovalResult{
			Approved: false,
			Request:  request,
			Error:    errors.New("approval request already expired"),
		}, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Poll for updates while waiting
	pollTicker := time.NewTicker(5 * time.Second)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return &ApprovalResult{
				Approved: false,
				Request:  request,
				Error:    ctx.Err(),
			}, ctx.Err()

		case result := <-resultCh:
			return &result, nil

		case <-timer.C:
			// Timeout reached, check final status
			updatedRequest, err := as.storage.GetApprovalRequest(request.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get approval request: %w", err)
			}

			return &ApprovalResult{
				Approved: updatedRequest.Status == ApprovalStatusApproved,
				Request:  updatedRequest,
				Error:    errors.New("approval request expired"),
			}, nil

		case <-pollTicker.C:
			// Check if approval has been resolved
			updatedRequest, err := as.storage.GetApprovalRequest(request.ID)
			if err != nil {
				as.logger.Warnf("Failed to poll approval request %s: %v", request.ID, err)
				continue
			}

			if updatedRequest.Status != ApprovalStatusPending && updatedRequest.Status != ApprovalStatusEscalated {
				return &ApprovalResult{
					Approved: updatedRequest.Status == ApprovalStatusApproved,
					Request:  updatedRequest,
				}, nil
			}
		}
	}
}

// ProcessApproval handles an approval or rejection action
func (as *ApprovalService) ProcessApproval(
	approvalID string,
	userID string,
	username string,
	action ApprovalActionType,
	comment string,
	expectedVersion int,
) (*ApprovalRequest, error) {
	// Delegate to storage which handles all validation and optimistic locking
	updatedRequest, err := as.storage.ProcessApprovalAction(
		approvalID, userID, username, action, comment, expectedVersion,
	)
	if err != nil {
		return nil, err
	}

	// If approval is resolved, notify waiting execution
	if updatedRequest.Status == ApprovalStatusApproved || updatedRequest.Status == ApprovalStatusRejected {
		as.notifyWaitingExecution(updatedRequest)

		// Send notification
		if err := as.notifier.NotifyApprovalResolved(updatedRequest); err != nil {
			as.logger.Warnf("Failed to notify approval resolution for %s: %v", approvalID, err)
		}
	}

	return updatedRequest, nil
}

// notifyWaitingExecution signals a waiting execution that approval has been resolved
func (as *ApprovalService) notifyWaitingExecution(request *ApprovalRequest) {
	key := fmt.Sprintf("%s:%s", request.ExecutionID, request.StepID)

	as.mu.RLock()
	resultCh, exists := as.waitingApprovals[key]
	as.mu.RUnlock()

	if exists {
		select {
		case resultCh <- ApprovalResult{
			Approved: request.Status == ApprovalStatusApproved,
			Request:  request,
		}:
		default:
			// Channel buffer full, result will be picked up on next poll
		}
	}
}

// GetApprovalRequest retrieves an approval request by ID
func (as *ApprovalService) GetApprovalRequest(id string) (*ApprovalRequest, error) {
	return as.storage.GetApprovalRequest(id)
}

// GetPendingApprovals retrieves pending approval requests for a user
func (as *ApprovalService) GetPendingApprovals(userID string, limit, offset int) ([]ApprovalRequest, error) {
	return as.storage.GetPendingApprovals(userID, limit, offset)
}

// GetApprovalRequests retrieves approval requests with filters
func (as *ApprovalService) GetApprovalRequests(filter *ApprovalFilter) ([]ApprovalRequest, int64, error) {
	return as.storage.GetApprovalRequests(filter)
}

// GetApprovalActions retrieves all actions for an approval request
func (as *ApprovalService) GetApprovalActions(approvalID string) ([]ApprovalAction, error) {
	return as.storage.GetApprovalActions(approvalID)
}

// CancelApproval cancels a pending approval request
func (as *ApprovalService) CancelApproval(approvalID string, userID string) error {
	err := as.storage.CancelApprovalRequest(approvalID, userID)
	if err != nil {
		return err
	}

	// Notify waiting execution
	request, err := as.storage.GetApprovalRequest(approvalID)
	if err == nil {
		as.notifyWaitingExecution(request)
	}

	return nil
}

// GetApprovalStats returns approval statistics
func (as *ApprovalService) GetApprovalStats() (*ApprovalStats, error) {
	return as.storage.GetApprovalStats()
}

// CheckStepRequiresApproval checks if a playbook step requires approval before execution
func CheckStepRequiresApproval(step *PlaybookStep) bool {
	return step.Approval != nil && step.Approval.Required
}

// ValidateApprovalConfig validates an approval configuration
func ValidateApprovalConfig(config *ApprovalConfig) error {
	if config == nil {
		return nil
	}

	if config.Required {
		// Validate mode
		switch config.Mode {
		case ApprovalModeAny, ApprovalModeAll, ApprovalModeMajority:
			// Valid
		case "":
			// Default to "any" - will be set at runtime
		default:
			return fmt.Errorf("invalid approval mode: %s", config.Mode)
		}

		// Validate timeout
		if config.TimeoutMinutes < 0 {
			return errors.New("approval timeout cannot be negative")
		}

		// Validate min approvers
		if config.MinApprovers < 0 {
			return errors.New("min approvers cannot be negative")
		}

		// Validate escalation config
		if config.EscalationConfig != nil {
			if config.EscalationConfig.Enabled {
				if config.EscalationConfig.EscalateAfterMins <= 0 {
					return errors.New("escalation timeout must be positive")
				}
				if len(config.EscalationConfig.EscalateTo) == 0 {
					return errors.New("escalation targets must be specified")
				}
			}
		}
	}

	return nil
}
