package api

import (
	"fmt"
	"net/http"

	"cerberus/storage"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

// Get all saved searches
func (a *API) getSavedSearches(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	// Get query parameters
	isPublic := r.URL.Query().Get("public") == "true"
	createdBy := r.URL.Query().Get("created_by")

	searches, err := a.savedSearchStorage.GetAll(isPublic, createdBy)
	if err != nil {
		a.logger.Errorw("Failed to fetch saved searches", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to fetch saved searches", err, a.logger)
		return
	}

	// Ensure we return empty array, not null, when there are no searches
	// This prevents frontend validation errors
	if searches == nil {
		searches = []storage.SavedSearch{}
	}

	// Return in pagination format expected by frontend
	response := map[string]interface{}{
		"items": searches,
		"total": len(searches),
	}
	a.respondJSON(w, response, http.StatusOK)
}

// Create new saved search
func (a *API) createSavedSearch(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	var search storage.SavedSearch
	if err := a.decodeJSONBody(w, r, &search); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate input
	validate := validator.New()
	if err := validate.Struct(search); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Validation failed: %v", err), err, a.logger)
		return
	}

	// Additional validation: either query or filters must be provided
	if search.Query == "" && len(search.Filters) == 0 {
		writeError(w, http.StatusBadRequest, "Query or filters are required", nil, a.logger)
		return
	}

	// Create saved search
	if err := a.savedSearchStorage.Create(&search); err != nil {
		a.logger.Errorw("Failed to create saved search", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create saved search", err, a.logger)
		return
	}

	a.respondJSON(w, search, http.StatusCreated)
}

// Get single saved search
func (a *API) getSavedSearch(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	search, err := a.savedSearchStorage.Get(id)
	if err != nil {
		if err.Error() == "saved search not found" {
			writeError(w, http.StatusNotFound, "Saved search not found", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to fetch saved search", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to fetch saved search", err, a.logger)
		return
	}

	a.respondJSON(w, search, http.StatusOK)
}

// Update saved search
func (a *API) updateSavedSearch(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var updates storage.SavedSearch
	if err := a.decodeJSONBody(w, r, &updates); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if err := a.savedSearchStorage.Update(id, &updates); err != nil {
		if err.Error() == "saved search not found" {
			writeError(w, http.StatusNotFound, "Saved search not found", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to update saved search", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to update saved search", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"success": true,
		"message": "Saved search updated successfully",
	}, http.StatusOK)
}

// Delete saved search
func (a *API) deleteSavedSearch(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.savedSearchStorage.Delete(id); err != nil {
		if err.Error() == "saved search not found" {
			writeError(w, http.StatusNotFound, "Saved search not found", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to delete saved search", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to delete saved search", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"success": true,
		"message": "Saved search deleted successfully",
	}, http.StatusOK)
}

//lint:ignore U1000 Reserved for saved search execution API endpoint - route not yet registered
func (a *API) executeSavedSearch(w http.ResponseWriter, r *http.Request) {
	if a.savedSearchStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Saved search storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get saved search
	search, err := a.savedSearchStorage.Get(id)
	if err != nil {
		if err.Error() == "saved search not found" {
			writeError(w, http.StatusNotFound, "Saved search not found", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to fetch saved search", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to fetch saved search", err, a.logger)
		return
	}

	// Increment usage count
	if err := a.savedSearchStorage.IncrementUsageCount(id); err != nil {
		a.logger.Warnw("Failed to increment usage count", "error", err, "id", id)
	}

	// Execute the search using existing search endpoint
	// For now, return the search query and filters
	a.respondJSON(w, map[string]interface{}{
		"search":  search,
		"message": "Execute this query using the /api/v1/events/search endpoint",
	}, http.StatusOK)
}
