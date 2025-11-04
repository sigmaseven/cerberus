package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"cerberus/search"
	"cerberus/storage"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
)

// searchEvents handles event search requests
func (a *API) searchEvents(w http.ResponseWriter, r *http.Request) {
	var req search.SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate request
	if req.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "query is required")
		return
	}

	// Set defaults
	if req.Page == 0 {
		req.Page = 1
	}
	if req.Limit == 0 {
		req.Limit = 50
	}
	if req.Limit > 500 {
		req.Limit = 500 // Max limit
	}

	// Get database connection
	db, ok := a.eventStorage.(interface{ GetDatabase() *mongo.Database })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "database connection not available")
		return
	}

	// Execute search
	executor := search.NewExecutor(db.GetDatabase())
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, &req)
	if err != nil {
		a.logger.Error("Search execution failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("search failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// validateQuery validates a query without executing it
func (a *API) validateQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	parser := search.NewParser(req.Query)
	ast, err := parser.Parse()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	if err := ast.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "query is valid",
	})
}

// getSavedSearches retrieves all saved searches for a user
func (a *API) getSavedSearches(w http.ResponseWriter, r *http.Request) {
	// TODO: Get user from context (JWT)
	userID := "default_user"

	// Optional query parameters
	tags := r.URL.Query().Get("tags")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get saved search storage
	searchStorage, ok := a.eventStorage.(interface{ GetSavedSearchStorage() *storage.SavedSearchStorage })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "saved search storage not available")
		return
	}

	var searches []*storage.SavedSearch
	var err error

	if tags != "" {
		tagList := []string{tags}
		searches, err = searchStorage.GetSavedSearchStorage().GetByTags(ctx, userID, tagList)
	} else {
		searches, err = searchStorage.GetSavedSearchStorage().GetByUser(ctx, userID)
	}

	if err != nil {
		a.logger.Error("Failed to fetch saved searches", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to fetch saved searches")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": searches,
		"total": len(searches),
	})
}

// getSavedSearch retrieves a single saved search by ID
func (a *API) getSavedSearch(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	searchStorage, ok := a.eventStorage.(interface{ GetSavedSearchStorage() *storage.SavedSearchStorage })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "saved search storage not available")
		return
	}

	savedSearch, err := searchStorage.GetSavedSearchStorage().GetByID(ctx, id)
	if err != nil {
		a.logger.Error("Failed to fetch saved search", "error", err, "id", id)
		writeJSONError(w, http.StatusNotFound, "saved search not found")
		return
	}

	// Record usage
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		searchStorage.GetSavedSearchStorage().RecordUsage(ctx, id)
	}()

	writeJSON(w, http.StatusOK, savedSearch)
}

// createSavedSearch creates a new saved search
func (a *API) createSavedSearch(w http.ResponseWriter, r *http.Request) {
	var savedSearch storage.SavedSearch
	if err := json.NewDecoder(r.Body).Decode(&savedSearch); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate required fields
	if savedSearch.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if savedSearch.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "query is required")
		return
	}

	// Validate query syntax
	parser := search.NewParser(savedSearch.Query)
	ast, err := parser.Parse()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid query: %v", err))
		return
	}
	if err := ast.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid query: %v", err))
		return
	}

	// TODO: Get user from context
	savedSearch.UserID = "default_user"

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	searchStorage, ok := a.eventStorage.(interface{ GetSavedSearchStorage() *storage.SavedSearchStorage })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "saved search storage not available")
		return
	}

	if err := searchStorage.GetSavedSearchStorage().Create(ctx, &savedSearch); err != nil {
		a.logger.Error("Failed to create saved search", "error", err)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, savedSearch)
}

// updateSavedSearch updates an existing saved search
func (a *API) updateSavedSearch(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var savedSearch storage.SavedSearch
	if err := json.NewDecoder(r.Body).Decode(&savedSearch); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	savedSearch.ID = id

	// Validate query syntax if provided
	if savedSearch.Query != "" {
		parser := search.NewParser(savedSearch.Query)
		ast, err := parser.Parse()
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid query: %v", err))
			return
		}
		if err := ast.Validate(); err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid query: %v", err))
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	searchStorage, ok := a.eventStorage.(interface{ GetSavedSearchStorage() *storage.SavedSearchStorage })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "saved search storage not available")
		return
	}

	if err := searchStorage.GetSavedSearchStorage().Update(ctx, &savedSearch); err != nil {
		a.logger.Error("Failed to update saved search", "error", err)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, savedSearch)
}

// deleteSavedSearch deletes a saved search
func (a *API) deleteSavedSearch(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	searchStorage, ok := a.eventStorage.(interface{ GetSavedSearchStorage() *storage.SavedSearchStorage })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "saved search storage not available")
		return
	}

	if err := searchStorage.GetSavedSearchStorage().Delete(ctx, id); err != nil {
		a.logger.Error("Failed to delete saved search", "error", err)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "search deleted"})
}

// exportEvents exports search results
func (a *API) exportEvents(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string              `json:"query"`
		TimeRange *search.TimeRange   `json:"time_range,omitempty"`
		Format    string              `json:"format"`
		Limit     int                 `json:"limit"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate
	if req.Format != "json" && req.Format != "csv" {
		writeJSONError(w, http.StatusBadRequest, "format must be json or csv")
		return
	}

	if req.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "query is required")
		return
	}

	if req.Limit == 0 {
		req.Limit = 10000
	}
	if req.Limit > 10000 {
		req.Limit = 10000
	}

	// Get database connection
	db, ok := a.eventStorage.(interface{ GetDatabase() *mongo.Database })
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "database connection not available")
		return
	}

	// Execute search
	executor := search.NewExecutor(db.GetDatabase())
	searchReq := &search.SearchRequest{
		Query:     req.Query,
		TimeRange: req.TimeRange,
		Page:      1,
		Limit:     req.Limit,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, searchReq)
	if err != nil {
		a.logger.Error("Export search failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "export failed")
		return
	}

	// Export based on format
	filename := "cerberus_events_" + time.Now().Format("2006-01-02_150405")

	switch req.Format {
	case "json":
		w.Header().Set("Content-Disposition", "attachment; filename="+filename+".json")
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"metadata": map[string]interface{}{
				"query":          req.Query,
				"time_range":     req.TimeRange,
				"exported_at":    time.Now(),
				"total_exported": len(result.Events),
				"total_matched":  result.Total,
			},
			"events": result.Events,
		})

	case "csv":
		w.Header().Set("Content-Disposition", "attachment; filename="+filename+".csv")
		w.Header().Set("Content-Type", "text/csv")

		writer := csv.NewWriter(w)
		defer writer.Flush()

		// Write header
		if len(result.Events) > 0 {
			fieldSet := make(map[string]bool)
			for _, event := range result.Events {
				for k := range event {
					fieldSet[k] = true
				}
			}

			var header []string
			for field := range fieldSet {
				header = append(header, field)
			}
			writer.Write(header)

			for _, event := range result.Events {
				row := make([]string, len(header))
				for i, field := range header {
					if val, ok := event[field]; ok {
						row[i] = fmt.Sprintf("%v", val)
					}
				}
				writer.Write(row)
			}
		}
	}
}

// getSearchFields returns available fields for query building
func (a *API) getSearchFields(w http.ResponseWriter, r *http.Request) {
	fields := []map[string]interface{}{
		{"name": "event_id", "type": "string", "description": "Unique event identifier"},
		{"name": "event_type", "type": "string", "description": "Type of event"},
		{"name": "timestamp", "type": "datetime", "description": "Event timestamp"},
		{"name": "severity", "type": "string", "description": "Event severity level"},
		{"name": "source_ip", "type": "string", "description": "Source IP address"},
		{"name": "source_format", "type": "string", "description": "Log format"},
		{"name": "message", "type": "string", "description": "Event message"},
		{"name": "fields.user", "type": "string", "description": "Username"},
		{"name": "fields.status", "type": "string", "description": "Status"},
		{"name": "fields.action", "type": "string", "description": "Action performed"},
		{"name": "fields.filename", "type": "string", "description": "Filename"},
		{"name": "fields.destination_ip", "type": "string", "description": "Destination IP"},
		{"name": "fields.port", "type": "number", "description": "Port number"},
		{"name": "fields.bytes_sent", "type": "number", "description": "Bytes sent"},
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"fields": fields,
	})
}

// getSearchOperators returns available operators
func (a *API) getSearchOperators(w http.ResponseWriter, r *http.Request) {
	operators := []map[string]interface{}{
		{"value": "equals", "label": "Equals", "symbol": "=", "types": []string{"string", "number"}},
		{"value": "not_equals", "label": "Not Equals", "symbol": "!=", "types": []string{"string", "number"}},
		{"value": "contains", "label": "Contains", "types": []string{"string"}},
		{"value": "startswith", "label": "Starts With", "types": []string{"string"}},
		{"value": "endswith", "label": "Ends With", "types": []string{"string"}},
		{"value": "gt", "label": "Greater Than", "symbol": ">", "types": []string{"number", "datetime"}},
		{"value": "lt", "label": "Less Than", "symbol": "<", "types": []string{"number", "datetime"}},
		{"value": "gte", "label": "Greater Than or Equal", "symbol": ">=", "types": []string{"number", "datetime"}},
		{"value": "lte", "label": "Less Than or Equal", "symbol": "<=", "types": []string{"number", "datetime"}},
		{"value": "in", "label": "In", "types": []string{"string", "number"}},
		{"value": "not in", "label": "Not In", "types": []string{"string", "number"}},
		{"value": "matches", "label": "Matches (Regex)", "symbol": "~=", "types": []string{"string"}},
		{"value": "exists", "label": "Exists", "types": []string{"any"}},
		{"value": "not exists", "label": "Not Exists", "types": []string{"any"}},
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"operators": operators,
	})
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{"error": message})
}
