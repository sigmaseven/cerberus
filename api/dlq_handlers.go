package api

import (
	"database/sql"
	"net/http"
	"strconv"

	"cerberus/ingest"
	"cerberus/metrics"

	"github.com/gorilla/mux"
)

// listDLQEvents godoc
//
//	@Summary		List DLQ events
//	@Description	Returns a paginated list of dead-letter queue events with optional filtering
//	@Tags			dlq
//	@Produce		json
//	@Param			page		query		int		false	"Page number (default 1)"
//	@Param			limit		query		int		false	"Items per page (default 50, max 100)"
//	@Param			status		query		string	false	"Filter by status (pending, replayed, discarded)"
//	@Param			protocol	query		string	false	"Filter by protocol (syslog, cef, json, fluentd)"
//	@Success		200			{object}	PaginationResponse
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/dlq [get]
//	TASK 7.4: DLQ API endpoints for listing, replaying, and discarding events
func (a *API) listDLQEvents(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	// Parse pagination parameters
	params := ParsePaginationParams(r, 50, 100)

	// Parse filters
	filters := make(map[string]interface{})
	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}
	if protocol := r.URL.Query().Get("protocol"); protocol != "" {
		filters["protocol"] = protocol
	}

	// Get DLQ events
	events, total, err := a.dlq.List(params.Page, params.Limit, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DLQ events", err, a.logger)
		return
	}

	// Create paginated response
	response := NewPaginationResponse(events, int64(total), params.Page, params.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// getDLQEvent godoc
//
//	@Summary		Get DLQ event
//	@Description	Returns a single DLQ event by ID
//	@Tags			dlq
//	@Produce		json
//	@Param			id	path		int		true	"DLQ Event ID"
//	@Success		200	{object}	ingest.DLQEvent
//	@Failure		404	{string}	string	"DLQ event not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/dlq/{id} [get]
func (a *API) getDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	event, err := a.dlq.Get(id)
	if err != nil {
		if err.Error() == "DLQ event not found: id="+idStr {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	a.respondJSON(w, event, http.StatusOK)
}

// replayDLQEvent godoc
//
//	@Summary		Replay DLQ event
//	@Description	Attempts to re-ingest a DLQ event through the appropriate ingestion handler
//	@Tags			dlq
//	@Accept			json
//	@Produce		json
//	@Param			id	path		int		true	"DLQ Event ID"
//	@Success		200	{object}	map[string]string	"Success message"
//	@Failure		404	{string}	string	"DLQ event not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/dlq/{id}/replay [post]
//	TASK 7.4: Replay functionality for DLQ events
func (a *API) replayDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	// Get the event
	event, err := a.dlq.Get(id)
	if err != nil {
		errStr := err.Error()
		if errStr == "DLQ event not found: id="+idStr || errStr == sql.ErrNoRows.Error() {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	// Attempt to re-ingest based on protocol
	// TASK 7.4: Replay event through appropriate parser
	var parseErr error
	switch event.Protocol {
	case "syslog":
		_, parseErr = ingest.ParseSyslog(event.RawEvent)
	case "cef":
		_, parseErr = ingest.ParseCEF(event.RawEvent)
	case "json":
		_, parseErr = ingest.ParseJSON(event.RawEvent)
	default:
		writeError(w, http.StatusBadRequest, "Unsupported protocol for replay: "+event.Protocol, nil, a.logger)
		return
	}

	// Update status and increment retries
	if parseErr != nil {
		// Still failed - increment retries
		if err := a.dlq.IncrementRetries(id); err != nil {
			a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", id, err)
		}
		// Update metrics
		metrics.DLQReplayFailure.WithLabelValues(event.Protocol, "parse_failure").Inc()
		writeError(w, http.StatusBadRequest, "Failed to replay event: "+parseErr.Error(), parseErr, a.logger)
		return
	}

	// Success - mark as replayed
	if err := a.dlq.UpdateStatus(id, "replayed"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update DLQ event status", err, a.logger)
		return
	}

	// Increment retries (even on success, we track attempts)
	if err := a.dlq.IncrementRetries(id); err != nil {
		a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", id, err)
	}

	// Update metrics - access metrics through DLQ struct
	metrics.DLQReplaySuccess.WithLabelValues(event.Protocol).Inc()

	response := map[string]string{
		"message": "DLQ event replayed successfully",
		"id":      idStr,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// discardDLQEvent godoc
//
//	@Summary		Discard DLQ event
//	@Description	Marks a DLQ event as discarded (does not delete it)
//	@Tags			dlq
//	@Accept			json
//	@Produce		json
//	@Param			id	path		int		true	"DLQ Event ID"
//	@Success		200	{object}	map[string]string	"Success message"
//	@Failure		404	{string}	string	"DLQ event not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/dlq/{id} [delete]
//	TASK 7.4: Discard functionality for DLQ events
func (a *API) discardDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	// Verify event exists
	_, err = a.dlq.Get(id)
	if err != nil {
		if err.Error() == "DLQ event not found: id="+idStr {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	// Mark as discarded
	if err := a.dlq.UpdateStatus(id, "discarded"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update DLQ event status", err, a.logger)
		return
	}

	response := map[string]string{
		"message": "DLQ event discarded successfully",
		"id":      idStr,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// replayAllDLQEvents godoc
//
//	@Summary		Replay all pending DLQ events
//	@Description	Attempts to re-ingest all pending DLQ events in batch
//	@Tags			dlq
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Replay statistics"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/dlq/replay-all [post]
//	TASK 7.4: Batch replay functionality for DLQ events
func (a *API) replayAllDLQEvents(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	// Get all pending events (with reasonable limit to prevent overload)
	events, _, err := a.dlq.List(1, 1000, map[string]interface{}{"status": "pending"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DLQ events", err, a.logger)
		return
	}

	successCount := 0
	failureCount := 0

	// Replay each event
	for _, event := range events {
		var parseErr error
		switch event.Protocol {
		case "syslog":
			_, parseErr = ingest.ParseSyslog(event.RawEvent)
		case "cef":
			_, parseErr = ingest.ParseCEF(event.RawEvent)
		case "json":
			_, parseErr = ingest.ParseJSON(event.RawEvent)
		default:
			failureCount++
			continue
		}

		if parseErr != nil {
			if err := a.dlq.IncrementRetries(event.ID); err != nil {
				a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", event.ID, err)
			}
			metrics.DLQReplayFailure.WithLabelValues(event.Protocol, "parse_failure").Inc()
			failureCount++
			continue
		}

		// Success
		if err := a.dlq.UpdateStatus(event.ID, "replayed"); err != nil {
			a.logger.Warnf("Failed to update status for DLQ event %d: %v", event.ID, err)
		}
		if err := a.dlq.IncrementRetries(event.ID); err != nil {
			a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", event.ID, err)
		}
		metrics.DLQReplaySuccess.WithLabelValues(event.Protocol).Inc()
		successCount++
	}

	response := map[string]interface{}{
		"message": "Batch replay completed",
		"total":   len(events),
		"success": successCount,
		"failed":  failureCount,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// listListenerDLQEvents godoc
//
//	@Summary		List DLQ events for a specific listener
//	@Description	Returns a paginated list of dead-letter queue events for a specific listener
//	@Tags			listeners,dlq
//	@Produce		json
//	@Param			id		path		string	true	"Listener ID"
//	@Param			page	query		int		false	"Page number (default 1)"
//	@Param			limit	query		int		false	"Items per page (default 50, max 100)"
//	@Param			status	query		string	false	"Filter by status (pending, replayed, discarded)"
//	@Success		200		{object}	PaginationResponse
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/listeners/{id}/dlq [get]
func (a *API) listListenerDLQEvents(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	listenerID := vars["id"]

	// Parse pagination parameters
	params := ParsePaginationParams(r, 50, 100)

	// Parse filters - always include listener_id
	filters := map[string]interface{}{
		"listener_id": listenerID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}
	if protocol := r.URL.Query().Get("protocol"); protocol != "" {
		filters["protocol"] = protocol
	}

	// Get DLQ events
	events, total, err := a.dlq.List(params.Page, params.Limit, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DLQ events", err, a.logger)
		return
	}

	// Create paginated response
	response := NewPaginationResponse(events, int64(total), params.Page, params.Limit)
	a.respondJSON(w, response, http.StatusOK)
}

// getListenerDLQEvent godoc
//
//	@Summary		Get DLQ event for a specific listener
//	@Description	Returns a single DLQ event by ID, verifying it belongs to the specified listener
//	@Tags			listeners,dlq
//	@Produce		json
//	@Param			id			path		string	true	"Listener ID"
//	@Param			eventId		path		int		true	"DLQ Event ID"
//	@Success		200			{object}	ingest.DLQEvent
//	@Failure		404			{string}	string	"DLQ event not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/listeners/{id}/dlq/{eventId} [get]
func (a *API) getListenerDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	listenerID := vars["id"]
	eventIDStr := vars["eventId"]

	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	event, err := a.dlq.Get(eventID)
	if err != nil {
		if err.Error() == "DLQ event not found: id="+eventIDStr {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	// Verify event belongs to this listener
	if event.ListenerID != listenerID {
		writeError(w, http.StatusNotFound, "DLQ event not found for this listener", nil, a.logger)
		return
	}

	a.respondJSON(w, event, http.StatusOK)
}

// replayListenerDLQEvent godoc
//
//	@Summary		Replay DLQ event for a specific listener
//	@Description	Attempts to re-ingest a DLQ event, verifying it belongs to the specified listener
//	@Tags			listeners,dlq
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string	true	"Listener ID"
//	@Param			eventId		path		int		true	"DLQ Event ID"
//	@Success		200			{object}	map[string]string	"Success message"
//	@Failure		404			{string}	string	"DLQ event not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/listeners/{id}/dlq/{eventId}/replay [post]
func (a *API) replayListenerDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	listenerID := vars["id"]
	eventIDStr := vars["eventId"]

	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	// Get the event
	event, err := a.dlq.Get(eventID)
	if err != nil {
		errStr := err.Error()
		if errStr == "DLQ event not found: id="+eventIDStr || errStr == sql.ErrNoRows.Error() {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	// Verify event belongs to this listener
	if event.ListenerID != listenerID {
		writeError(w, http.StatusNotFound, "DLQ event not found for this listener", nil, a.logger)
		return
	}

	// Attempt to re-ingest based on protocol
	var parseErr error
	switch event.Protocol {
	case "syslog":
		_, parseErr = ingest.ParseSyslog(event.RawEvent)
	case "cef":
		_, parseErr = ingest.ParseCEF(event.RawEvent)
	case "json":
		_, parseErr = ingest.ParseJSON(event.RawEvent)
	default:
		writeError(w, http.StatusBadRequest, "Unsupported protocol for replay: "+event.Protocol, nil, a.logger)
		return
	}

	// Update status and increment retries
	if parseErr != nil {
		if err := a.dlq.IncrementRetries(eventID); err != nil {
			a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", eventID, err)
		}
		metrics.DLQReplayFailure.WithLabelValues(event.Protocol, "parse_failure").Inc()
		writeError(w, http.StatusBadRequest, "Failed to replay event: "+parseErr.Error(), parseErr, a.logger)
		return
	}

	// Success - mark as replayed
	if err := a.dlq.UpdateStatus(eventID, "replayed"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update DLQ event status", err, a.logger)
		return
	}

	if err := a.dlq.IncrementRetries(eventID); err != nil {
		a.logger.Warnf("Failed to increment retries for DLQ event %d: %v", eventID, err)
	}

	metrics.DLQReplaySuccess.WithLabelValues(event.Protocol).Inc()

	response := map[string]string{
		"message": "DLQ event replayed successfully",
		"id":      eventIDStr,
	}
	a.respondJSON(w, response, http.StatusOK)
}

// discardListenerDLQEvent godoc
//
//	@Summary		Discard DLQ event for a specific listener
//	@Description	Marks a DLQ event as discarded, verifying it belongs to the specified listener
//	@Tags			listeners,dlq
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string	true	"Listener ID"
//	@Param			eventId		path		int		true	"DLQ Event ID"
//	@Success		200			{object}	map[string]string	"Success message"
//	@Failure		404			{string}	string	"DLQ event not found"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/api/v1/listeners/{id}/dlq/{eventId} [delete]
func (a *API) discardListenerDLQEvent(w http.ResponseWriter, r *http.Request) {
	if a.dlq == nil {
		writeError(w, http.StatusServiceUnavailable, "DLQ not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	listenerID := vars["id"]
	eventIDStr := vars["eventId"]

	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DLQ event ID", err, a.logger)
		return
	}

	// Get the event to verify it belongs to this listener
	event, err := a.dlq.Get(eventID)
	if err != nil {
		if err.Error() == "DLQ event not found: id="+eventIDStr {
			writeError(w, http.StatusNotFound, "DLQ event not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get DLQ event", err, a.logger)
		return
	}

	// Verify event belongs to this listener
	if event.ListenerID != listenerID {
		writeError(w, http.StatusNotFound, "DLQ event not found for this listener", nil, a.logger)
		return
	}

	// Mark as discarded
	if err := a.dlq.UpdateStatus(eventID, "discarded"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update DLQ event status", err, a.logger)
		return
	}

	response := map[string]string{
		"message": "DLQ event discarded successfully",
		"id":      eventIDStr,
	}
	a.respondJSON(w, response, http.StatusOK)
}
