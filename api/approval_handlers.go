package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"cerberus/soar"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// =============================================================================
// Step-Level Approval Workflow Handlers
// =============================================================================

// ApprovalActionRequest represents a request to approve/reject/escalate an approval
type ApprovalActionRequest struct {
	Action          string `json:"action"`                     // approve, reject, escalate, comment
	Comment         string `json:"comment,omitempty"`          // Optional comment
	ExpectedVersion int    `json:"expected_version,omitempty"` // For optimistic locking
}

// ApprovalListResponse represents the response for listing approvals
type ApprovalListResponse struct {
	Items    []soar.ApprovalRequest `json:"items"`
	Total    int64                  `json:"total"`
	Page     int                    `json:"page"`
	Limit    int                    `json:"limit"`
	HasMore  bool                   `json:"has_more"`
}

// listApprovals handles GET /api/v1/approvals
// Lists approval requests with filtering and pagination
//
//	@Summary		List approval requests
//	@Description	Retrieve approval requests with optional filtering by status, playbook, alert
//	@Tags			approvals
//	@Produce		json
//	@Param			status      query	string	false	"Filter by status (pending, approved, rejected, expired, escalated)"
//	@Param			playbook_id query	string	false	"Filter by playbook ID"
//	@Param			alert_id    query	string	false	"Filter by alert ID"
//	@Param			approver_id query	string	false	"Filter by approver ID"
//	@Param			page        query	int		false	"Page number (default: 1)"
//	@Param			limit       query	int		false	"Items per page (default: 50, max: 100)"
//	@Success		200	{object}	ApprovalListResponse
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals [get]
func (a *API) listApprovals(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	// Parse pagination
	page := 1
	limit := 50

	if p := r.URL.Query().Get("page"); p != "" {
		if parsedPage, err := strconv.Atoi(p); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				parsedLimit = 100
			}
			limit = parsedLimit
		}
	}

	offset := (page - 1) * limit

	// Build filter
	filter := &soar.ApprovalFilter{
		Limit:  limit,
		Offset: offset,
	}

	// Parse status filter (can be comma-separated)
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = []soar.ApprovalStatus{soar.ApprovalStatus(status)}
	}

	if playbookID := r.URL.Query().Get("playbook_id"); playbookID != "" {
		filter.PlaybookID = playbookID
	}

	if alertID := r.URL.Query().Get("alert_id"); alertID != "" {
		filter.AlertID = alertID
	}

	if approverID := r.URL.Query().Get("approver_id"); approverID != "" {
		filter.ApproverID = approverID
	}

	// Query approvals
	approvals, total, err := a.approvalStorage.GetApprovalRequests(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list approvals", err, a.logger)
		return
	}

	response := ApprovalListResponse{
		Items:   approvals,
		Total:   total,
		Page:    page,
		Limit:   limit,
		HasMore: int64(offset+limit) < total,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getApproval handles GET /api/v1/approvals/{id}
// Get a single approval request by ID
//
//	@Summary		Get approval request
//	@Description	Retrieve a specific approval request by ID
//	@Tags			approvals
//	@Produce		json
//	@Param			id	path		string	true	"Approval request ID"
//	@Success		200	{object}	soar.ApprovalRequest
//	@Failure		404	{object}	map[string]string	"Approval not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/{id} [get]
func (a *API) getApproval(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		writeError(w, http.StatusBadRequest, "Approval ID is required", nil, a.logger)
		return
	}

	approval, err := a.approvalStorage.GetApprovalRequest(id)
	if err != nil {
		if errors.Is(err, storage.ErrApprovalNotFound) {
			writeError(w, http.StatusNotFound, "Approval request not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get approval", err, a.logger)
		return
	}

	a.respondJSON(w, approval, http.StatusOK)
}

// processApproval handles PATCH /api/v1/approvals/{id}
// Process an approval action (approve, reject, escalate, comment)
//
//	@Summary		Process approval action
//	@Description	Approve, reject, escalate, or comment on an approval request
//	@Tags			approvals
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Approval request ID"
//	@Param			request	body		ApprovalActionRequest	true	"Action to perform"
//	@Success		200		{object}	soar.ApprovalRequest	"Updated approval request"
//	@Failure		400		{object}	map[string]string		"Invalid request"
//	@Failure		404		{object}	map[string]string		"Approval not found"
//	@Failure		409		{object}	map[string]string		"Conflict - optimistic lock failed"
//	@Failure		500		{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/{id} [patch]
func (a *API) processApproval(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		writeError(w, http.StatusBadRequest, "Approval ID is required", nil, a.logger)
		return
	}

	// Parse request body
	var req ApprovalActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error(), err, a.logger)
		return
	}

	// Validate action
	var actionType soar.ApprovalActionType
	switch req.Action {
	case "approve":
		actionType = soar.ApprovalActionApprove
	case "reject":
		actionType = soar.ApprovalActionReject
	case "escalate":
		actionType = soar.ApprovalActionEscalate
	case "comment":
		actionType = soar.ApprovalActionComment
	default:
		writeError(w, http.StatusBadRequest, "Invalid action: must be approve, reject, escalate, or comment", nil, a.logger)
		return
	}

	// Validate comment for comment action
	if actionType == soar.ApprovalActionComment && req.Comment == "" {
		writeError(w, http.StatusBadRequest, "Comment is required for comment action", nil, a.logger)
		return
	}

	// Get user info - require authentication
	userID := getUserIDFromContext(r.Context())
	username := getUsernameFromContext(r.Context())

	// SECURITY: Reject anonymous users - both userID and username must not be empty
	if userID == "" && username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required to process approvals", nil, a.logger)
		return
	}

	if userID == "" {
		userID = username // Fallback to username if userID is not set
	}

	// Final validation: ensure we have a valid user identifier for audit trail
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "User identification failed", nil, a.logger)
		return
	}

	// Fetch current approval to validate status and get version if needed
	current, err := a.approvalStorage.GetApprovalRequest(id)
	if err != nil {
		if errors.Is(err, storage.ErrApprovalNotFound) {
			writeError(w, http.StatusNotFound, "Approval request not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get approval", err, a.logger)
		return
	}

	// SECURITY: Validate expiration at handler level (fail fast)
	if time.Now().After(current.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "Approval request has expired", nil, a.logger)
		return
	}

	// Validate approval is still pending or escalated
	if current.Status != soar.ApprovalStatusPending && current.Status != soar.ApprovalStatusEscalated {
		writeError(w, http.StatusBadRequest, "Approval request is already resolved", nil, a.logger)
		return
	}

	// Use provided version or current version
	if req.ExpectedVersion == 0 {
		req.ExpectedVersion = current.Version
	}

	// Process the approval action
	updatedApproval, err := a.approvalStorage.ProcessApprovalAction(
		id, userID, username, actionType, req.Comment, req.ExpectedVersion,
	)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrApprovalNotFound):
			writeError(w, http.StatusNotFound, "Approval request not found", err, a.logger)
		case errors.Is(err, storage.ErrApprovalExpired):
			writeError(w, http.StatusBadRequest, "Approval request has expired", err, a.logger)
		case errors.Is(err, storage.ErrApprovalResolved):
			writeError(w, http.StatusBadRequest, "Approval request already resolved", err, a.logger)
		case errors.Is(err, storage.ErrSelfApprovalDenied):
			writeError(w, http.StatusForbidden, "Self-approval is not allowed", err, a.logger)
		case errors.Is(err, storage.ErrOptimisticLockFailed):
			writeError(w, http.StatusConflict, "Approval was modified by another user, please refresh and try again", err, a.logger)
		case errors.Is(err, storage.ErrNotAuthorizedApprover):
			writeError(w, http.StatusForbidden, "You are not authorized to approve this request", err, a.logger)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to process approval", err, a.logger)
		}
		return
	}

	// Log the action
	a.logger.Infow("Approval action processed",
		"approval_id", id,
		"action", req.Action,
		"user_id", userID,
		"new_status", updatedApproval.Status)

	a.respondJSON(w, updatedApproval, http.StatusOK)
}

// getApprovalActions handles GET /api/v1/approvals/{id}/actions
// Get all actions (history) for an approval request
//
//	@Summary		Get approval actions
//	@Description	Retrieve the history of actions for an approval request
//	@Tags			approvals
//	@Produce		json
//	@Param			id	path		string	true	"Approval request ID"
//	@Success		200	{array}		soar.ApprovalAction
//	@Failure		404	{object}	map[string]string	"Approval not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/{id}/actions [get]
func (a *API) getApprovalActions(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		writeError(w, http.StatusBadRequest, "Approval ID is required", nil, a.logger)
		return
	}

	// Verify approval exists
	_, err := a.approvalStorage.GetApprovalRequest(id)
	if err != nil {
		if errors.Is(err, storage.ErrApprovalNotFound) {
			writeError(w, http.StatusNotFound, "Approval request not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get approval", err, a.logger)
		return
	}

	actions, err := a.approvalStorage.GetApprovalActions(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get approval actions", err, a.logger)
		return
	}

	a.respondJSON(w, actions, http.StatusOK)
}

// cancelApproval handles DELETE /api/v1/approvals/{id}
// Cancel a pending approval request
//
//	@Summary		Cancel approval request
//	@Description	Cancel a pending approval request
//	@Tags			approvals
//	@Param			id	path	string	true	"Approval request ID"
//	@Success		204	"Approval cancelled"
//	@Failure		400	{object}	map[string]string	"Invalid request or approval not pending"
//	@Failure		404	{object}	map[string]string	"Approval not found"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/{id} [delete]
func (a *API) cancelApproval(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		writeError(w, http.StatusBadRequest, "Approval ID is required", nil, a.logger)
		return
	}

	userID := getUserIDFromContext(r.Context())
	username := getUsernameFromContext(r.Context())

	// SECURITY: Reject anonymous users
	if userID == "" && username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required to cancel approvals", nil, a.logger)
		return
	}

	if userID == "" {
		userID = username // Fallback
	}

	err := a.approvalStorage.CancelApprovalRequest(id, userID)
	if err != nil {
		if errors.Is(err, storage.ErrApprovalNotFound) {
			writeError(w, http.StatusNotFound, "Approval request not found or already resolved", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to cancel approval", err, a.logger)
		return
	}

	a.logger.Infow("Approval request cancelled",
		"approval_id", id,
		"cancelled_by", userID)

	w.WriteHeader(http.StatusNoContent)
}

// getPendingApprovalsForUser handles GET /api/v1/approvals/pending
// Get pending approvals for the current user
//
//	@Summary		Get my pending approvals
//	@Description	Retrieve pending approval requests where the current user is an authorized approver
//	@Tags			approvals
//	@Produce		json
//	@Param			limit	query	int	false	"Items per page (default: 50, max: 100)"
//	@Param			offset	query	int	false	"Offset (default: 0)"
//	@Success		200		{array}	soar.ApprovalRequest
//	@Failure		500		{object}	map[string]string	"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/pending [get]
func (a *API) getPendingApprovalsForUser(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	userID := getUserIDFromContext(r.Context())
	username := getUsernameFromContext(r.Context())

	// SECURITY: Reject anonymous users
	if userID == "" && username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required to view pending approvals", nil, a.logger)
		return
	}

	if userID == "" {
		userID = username // Fallback
	}

	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				parsedLimit = 100
			}
			limit = parsedLimit
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsedOffset, err := strconv.Atoi(o); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	approvals, err := a.approvalStorage.GetPendingApprovals(userID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get pending approvals", err, a.logger)
		return
	}

	a.respondJSON(w, approvals, http.StatusOK)
}

// getApprovalStatsHandler handles GET /api/v1/approvals/stats
// Returns real approval workflow statistics
//
//	@Summary		Get approval statistics
//	@Description	Get statistics about playbook approval workflows
//	@Tags			approvals
//	@Produce		json
//	@Success		200	{object}	soar.ApprovalStats	"Approval statistics"
//	@Failure		500	{object}	map[string]string	"Server error"
//	@Router			/api/v1/approvals/stats [get]
func (a *API) getApprovalStatsHandler(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		// Return empty stats if approval storage not configured
		stats := &soar.ApprovalStats{
			TotalPending:           0,
			TotalApproved:          0,
			TotalRejected:          0,
			TotalExpired:           0,
			TotalEscalated:         0,
			AvgResponseTimeMinutes: 0,
		}
		a.respondJSON(w, stats, http.StatusOK)
		return
	}

	stats, err := a.approvalStorage.GetApprovalStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get approval stats", err, a.logger)
		return
	}

	a.respondJSON(w, stats, http.StatusOK)
}

// expireApprovals handles POST /api/v1/approvals/expire (admin only)
// Manually trigger expiration of expired approvals
//
//	@Summary		Expire approvals
//	@Description	Manually trigger expiration check for expired approval requests
//	@Tags			approvals
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Expiration result"
//	@Failure		500	{object}	map[string]string		"Server error"
//	@Security		BearerAuth
//	@Router			/api/v1/approvals/expire [post]
func (a *API) expireApprovals(w http.ResponseWriter, r *http.Request) {
	if a.approvalStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Approval storage not available", nil, a.logger)
		return
	}

	count, err := a.approvalStorage.ExpireApprovals()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to expire approvals", err, a.logger)
		return
	}

	a.logger.Infow("Manual approval expiration triggered",
		"expired_count", count,
		"triggered_by", getUsernameFromContext(r.Context()))

	response := map[string]interface{}{
		"expired_count": count,
		"message":       fmt.Sprintf("Expired %d approval requests", count),
	}

	a.respondJSON(w, response, http.StatusOK)
}
