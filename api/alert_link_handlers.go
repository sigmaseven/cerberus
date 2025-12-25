package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"cerberus/core"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// linkAlerts creates a bi-directional link between two alerts
// @Summary Link alerts
// @Description Create a bi-directional relationship between two alerts. This operation is idempotent - if the link already exists, returns 200 OK with the existing link.
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path string true "Alert ID"
// @Param body body core.AlertLinkRequest true "Link request"
// @Success 200 {object} core.AlertLink "Link already exists (idempotent)"
// @Success 201 {object} core.AlertLink "Link created"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Alert not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/related [post]
func (a *API) linkAlerts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Check if alert link storage is available
	if a.alertLinkStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert link storage not available", nil, a.logger)
		return
	}

	// Parse request body
	var req core.AlertLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate linked alert ID
	if err := validateUUID(req.LinkedAlertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid linked_alert_id format", err, a.logger)
		return
	}

	// Prevent self-linking
	if alertID == req.LinkedAlertID {
		writeError(w, http.StatusBadRequest, "Cannot link an alert to itself", nil, a.logger)
		return
	}

	// Check if link already exists - if so, return success (idempotent behavior)
	exists, err := a.alertLinkStorage.LinkExists(r.Context(), alertID, req.LinkedAlertID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check link existence", err, a.logger)
		return
	}
	if exists {
		// Return existing link info instead of error (idempotent)
		// This makes the API more user-friendly - "ensure link exists" always succeeds
		links, err := a.alertLinkStorage.GetLinkedAlerts(r.Context(), alertID)
		if err != nil {
			// Even if we can't get the link details, the link exists - return success
			a.respondJSON(w, map[string]interface{}{
				"message":         "Link already exists between these alerts",
				"alert_id":        alertID,
				"linked_alert_id": req.LinkedAlertID,
			}, http.StatusOK)
			return
		}
		// Find and return the existing link
		for _, link := range links {
			if link.LinkedID == req.LinkedAlertID {
				a.respondJSON(w, link, http.StatusOK)
				return
			}
		}
		// Link exists but couldn't find details - still return success
		a.respondJSON(w, map[string]interface{}{
			"message":         "Link already exists between these alerts",
			"alert_id":        alertID,
			"linked_alert_id": req.LinkedAlertID,
		}, http.StatusOK)
		return
	}

	// Verify both alerts exist
	if a.alertStorage != nil {
		_, err := a.alertStorage.GetAlertByID(r.Context(), alertID)
		if err != nil {
			if errors.Is(err, storage.ErrAlertNotFound) {
				writeError(w, http.StatusNotFound, "Alert not found", err, a.logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed to verify alert exists", err, a.logger)
			return
		}

		_, err = a.alertStorage.GetAlertByID(r.Context(), req.LinkedAlertID)
		if err != nil {
			if errors.Is(err, storage.ErrAlertNotFound) {
				writeError(w, http.StatusNotFound, "Linked alert not found", err, a.logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed to verify linked alert exists", err, a.logger)
			return
		}
	}

	// Get username from request
	username := r.Header.Get("X-Username")
	if username == "" {
		username = "anonymous"
	}

	// Set default link type if not provided
	linkType := req.LinkType
	if linkType == "" {
		linkType = "related"
	}

	// Create the link
	link := core.NewAlertLink(alertID, req.LinkedAlertID, linkType, req.Description, username)

	if err := a.alertLinkStorage.CreateLink(r.Context(), link); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create alert link", err, a.logger)
		return
	}

	a.logger.Infow("Alert link created",
		"alert_id", alertID,
		"linked_alert_id", req.LinkedAlertID,
		"link_type", linkType,
		"created_by", username,
	)

	a.respondJSON(w, link, http.StatusCreated)
}

// listRelatedAlerts returns all alerts linked to the given alert
// @Summary List related alerts
// @Description Get all alerts that are linked to the specified alert
// @Tags alerts
// @Produce json
// @Param id path string true "Alert ID"
// @Success 200 {array} core.AlertLinkResponse
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/related [get]
func (a *API) listRelatedAlerts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Check if alert link storage is available
	if a.alertLinkStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert link storage not available", nil, a.logger)
		return
	}

	// Get linked alerts
	links, err := a.alertLinkStorage.GetLinkedAlerts(r.Context(), alertID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get linked alerts", err, a.logger)
		return
	}

	// Build response with alert details
	responses := make([]*core.AlertLinkResponse, 0, len(links))
	for _, link := range links {
		response := &core.AlertLinkResponse{
			AlertID:     link.AlertID,
			LinkType:    link.LinkType,
			Description: link.Description,
			CreatedBy:   link.CreatedBy,
			CreatedAt:   link.CreatedAt,
		}

		// Try to get linked alert details
		if a.alertStorage != nil {
			linkedAlert, err := a.alertStorage.GetAlertByID(r.Context(), link.LinkedID)
			if err == nil && linkedAlert != nil {
				response.LinkedAlert = &core.AlertBrief{
					AlertID:   linkedAlert.AlertID,
					RuleID:    linkedAlert.RuleID,
					RuleName:  linkedAlert.RuleName,
					Severity:  linkedAlert.Severity,
					Status:    string(linkedAlert.Status),
					Timestamp: linkedAlert.Timestamp,
				}
			} else {
				// Linked alert may have been deleted, still return the link
				response.LinkedAlert = &core.AlertBrief{
					AlertID: link.LinkedID,
				}
			}
		} else {
			response.LinkedAlert = &core.AlertBrief{
				AlertID: link.LinkedID,
			}
		}

		responses = append(responses, response)
	}

	a.respondJSON(w, responses, http.StatusOK)
}

// unlinkAlerts removes a bi-directional link between two alerts
// @Summary Unlink alerts
// @Description Remove the bi-directional relationship between two alerts. This operation is idempotent - if the link doesn't exist, returns 204 No Content.
// @Tags alerts
// @Produce json
// @Param id path string true "Alert ID"
// @Param related_id path string true "Related Alert ID to unlink"
// @Success 204 "No content (link deleted or didn't exist)"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/related/{related_id} [delete]
func (a *API) unlinkAlerts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]
	relatedID := vars["related_id"]

	// Validate IDs
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}
	if err := validateUUID(relatedID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid related alert ID format", err, a.logger)
		return
	}

	// Check if alert link storage is available
	if a.alertLinkStorage == nil {
		writeError(w, http.StatusInternalServerError, "Alert link storage not available", nil, a.logger)
		return
	}

	// Delete the link (both directions) - idempotent: if not found, still return success
	if err := a.alertLinkStorage.DeleteLink(r.Context(), alertID, relatedID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Idempotent: link doesn't exist, that's fine - the desired state is achieved
			a.logger.Debugw("Unlink request for non-existent link (idempotent success)",
				"alert_id", alertID,
				"related_id", relatedID,
			)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete alert link", err, a.logger)
		return
	}

	username := r.Header.Get("X-Username")
	a.logger.Infow("Alert link deleted",
		"alert_id", alertID,
		"linked_alert_id", relatedID,
		"deleted_by", username,
	)

	w.WriteHeader(http.StatusNoContent)
}
