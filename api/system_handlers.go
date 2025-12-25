// Package api provides system-level API handlers.
// TASK 160.1: First-run wizard API endpoints.
package api

import (
	"net/http"
)

// FirstRunResponse represents the response for the first-run check endpoint.
// TASK 160.1: Used by frontend to determine if setup wizard should be shown.
type FirstRunResponse struct {
	IsFirstRun bool `json:"is_first_run"`
}

// SetupCompleteRequest represents the request body for completing setup.
// TASK 160.1: Optional fields for setup completion metadata.
type SetupCompleteRequest struct {
	// SkippedWizard indicates if the user skipped the setup wizard
	SkippedWizard bool `json:"skipped_wizard,omitempty"`
}

// SetupCompleteResponse represents the response for the setup completion endpoint.
type SetupCompleteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// getFirstRun handles GET /api/v1/system/first-run
// @Summary		Check if this is the first run
// @Description	Returns whether the application is running for the first time and needs setup
// @Tags			system
// @Accept			json
// @Produce		json
// @Success		200	{object}	FirstRunResponse
// @Failure		500	{object}	ErrorResponse
// @Router			/api/v1/system/first-run [get]
func (a *API) getFirstRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// SECURITY: This endpoint is intentionally unauthenticated
	// It only returns a boolean flag, no sensitive data

	isFirstRun, err := a.sqlite.IsFirstRun(ctx)
	if err != nil {
		a.logger.Errorw("Failed to check first-run status",
			"error", err,
			"request_id", ctx.Value(ContextKeyRequestID))
		writeError(w, http.StatusInternalServerError, "Failed to check setup status", err, a.logger)
		return
	}

	response := FirstRunResponse{
		IsFirstRun: isFirstRun,
	}

	a.logger.Debugw("First-run check completed",
		"is_first_run", isFirstRun,
		"request_id", ctx.Value(ContextKeyRequestID))

	a.respondJSON(w, response, http.StatusOK)
}

// completeSetup handles POST /api/v1/system/complete-setup
// @Summary		Mark setup as complete
// @Description	Marks the first-run setup wizard as completed
// @Tags			system
// @Accept			json
// @Produce		json
// @Param			request	body		SetupCompleteRequest	true	"Setup completion data"
// @Success		200		{object}	SetupCompleteResponse
// @Failure		400		{object}	ErrorResponse
// @Failure		500		{object}	ErrorResponse
// @Router			/api/v1/system/complete-setup [post]
// @Security		BearerAuth
func (a *API) completeSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body (optional)
	var req SetupCompleteRequest
	// Body is optional, ignore decode errors
	_ = a.decodeJSONBody(w, r, &req)

	// Mark setup as completed
	err := a.sqlite.SetSetupCompleted(ctx)
	if err != nil {
		a.logger.Errorw("Failed to complete setup",
			"error", err,
			"request_id", ctx.Value(ContextKeyRequestID))
		writeError(w, http.StatusInternalServerError, "Failed to complete setup", err, a.logger)
		return
	}

	// Audit logging
	message := "Setup wizard completed"
	if req.SkippedWizard {
		message = "Setup wizard skipped"
	}

	a.logger.Infow(message,
		"skipped_wizard", req.SkippedWizard,
		"request_id", ctx.Value(ContextKeyRequestID))

	response := SetupCompleteResponse{
		Success: true,
		Message: message,
	}

	a.respondJSON(w, response, http.StatusOK)
}
