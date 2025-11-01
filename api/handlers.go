package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"cerberus/core"
	"cerberus/storage"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// respondJSON writes a JSON response with proper error handling
func (a *API) respondJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		a.logger.Errorw("Failed to encode JSON response",
			"error", err,
			"data_type", fmt.Sprintf("%T", data))
		// Response already started, can't send error to client
		// Error is logged for monitoring
	}
}

// getEvents godoc
//
//	@Summary		Get events
//	@Description	Returns a list of recent security events
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			limit	query	int	false	"Maximum number of results (1-1000)"	minimum(1)	maximum(1000)	default(100)
//	@Success		200	{array}		core.Event
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/events [get]
func (a *API) getEvents(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil {
		http.Error(w, "Event storage not available", http.StatusInternalServerError)
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	events, err := a.eventStorage.GetEvents(limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get events: %v", err), http.StatusInternalServerError)
		return
	}
	a.respondJSON(w, events, http.StatusOK)
}

// getAlerts godoc
//
//	@Summary		Get alerts
//	@Description	Returns a list of alerts
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.Alert
//	@Router			/api/alerts [get]
func (a *API) getAlerts(w http.ResponseWriter, r *http.Request) {
	if a.alertStorage == nil {
		http.Error(w, "Alert storage not available", http.StatusInternalServerError)
		return
	}
	alerts, err := a.alertStorage.GetAlerts(100)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get alerts: %v", err), http.StatusInternalServerError)
		return
	}
	a.respondJSON(w, alerts, http.StatusOK)
}

// acknowledgeAlert godoc
//
//	@Summary		Acknowledge alert
//	@Description	Acknowledge an alert by ID
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Alert ID"
//	@Success		200	{string}	string	"Alert acknowledged"
//	@Failure		404	{string}	string	"Alert not found"
//	@Failure		503	{string}	string	"Alert storage not available"
//	@Router			/api/alerts/{id}/acknowledge [post]
func (a *API) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	if a.alertStorage == nil {
		http.Error(w, "Alert storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.alertStorage.AcknowledgeAlert(id); err != nil {
		if errors.Is(err, storage.ErrAlertNotFound) {
			http.Error(w, "Alert not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	a.respondJSON(w, map[string]string{"status": "acknowledged"}, http.StatusOK)
}

// dismissAlert godoc
//
//	@Summary		Dismiss alert
//	@Description	Dismiss an alert by ID
//	@Tags			alerts
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Alert ID"
//	@Success		200	{object}	map[string]string
//	@Failure		404	{string}	string	"Alert not found"
//	@Failure		503	{string}	string	"Alert storage not available"
//	@Router			/api/alerts/{id}/dismiss [post]
func (a *API) dismissAlert(w http.ResponseWriter, r *http.Request) {
	if a.alertStorage == nil {
		http.Error(w, "Alert storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.alertStorage.DismissAlert(id); err != nil {
		if errors.Is(err, storage.ErrAlertNotFound) {
			http.Error(w, "Alert not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	a.respondJSON(w, map[string]string{"status": "dismissed"}, http.StatusOK)
}

// getRules godoc
//
//	@Summary		Get rules
//	@Description	Returns a list of all detection rules
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.Rule
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules [get]
func (a *API) getRules(w http.ResponseWriter, r *http.Request) {
	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	rules, err := a.ruleStorage.GetRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rules); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// getRule godoc
//
//	@Summary		Get rule
//	@Description	Get a detection rule by ID
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Rule ID"
//	@Success		200	{object}	core.Rule
//	@Failure		400	{string}	string
//	@Failure		404	{string}	string
//	@Failure		500	{string}	string
//	@Router			/api/v1/rules/{id} [get]
func (a *API) getRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "Rule ID is required", http.StatusBadRequest)
		return
	}

	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	rule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			http.Error(w, "Rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rule); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// createRule godoc
//
//	@Summary		Create rule
//	@Description	Create a new detection rule
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			rule	body		core.Rule	true	"Rule object"
//	@Success		201	{object}	core.Rule
//	@Failure		400	{string}	string	"Invalid JSON"
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules [post]
func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	var rule core.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = uuid.New().String()

	if err := a.ruleStorage.CreateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.respondJSON(w, rule, http.StatusCreated)
}

// updateRule godoc
//
//	@Summary		Update rule
//	@Description	Update an existing detection rule
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string		true	"Rule ID"
//	@Param			rule	body		core.Rule	true	"Rule object"
//	@Success		200		{object}	core.Rule
//	@Failure		400		{string}	string		"Invalid JSON"
//	@Failure		404		{string}	string		"Rule not found"
//	@Failure		503		{string}	string		"Rule storage not available"
//	@Router			/api/rules/{id} [put]
func (a *API) updateRule(w http.ResponseWriter, r *http.Request) {
	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var rule core.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = id

	if err := a.ruleStorage.UpdateRule(id, &rule); err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			http.Error(w, "Rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	a.respondJSON(w, rule, http.StatusOK)
}

// deleteRule godoc
//
//	@Summary		Delete rule
//	@Description	Delete a detection rule by ID
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Rule ID"
//	@Success		200	{string}	string	"Rule deleted"
//	@Failure		404	{string}	string	"Rule not found"
//	@Failure		503	{string}	string	"Rule storage not available"
//	@Router			/api/rules/{id} [delete]
func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	if a.ruleStorage == nil {
		http.Error(w, "Rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.ruleStorage.DeleteRule(id); err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			http.Error(w, "Rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	a.respondJSON(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// getActions godoc
//
//	@Summary		Get actions
//	@Description	Returns a list of all actions
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.Action
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions [get]
func (a *API) getActions(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	actions, err := a.actionStorage.GetActions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(actions)
}

// getAction godoc
//
//	@Summary		Get action
//	@Description	Get an action by ID
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Action ID"
//	@Success		200	{object}	core.Action
//	@Failure		404	{string}	string	"Action not found"
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions/{id} [get]
func (a *API) getAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	action, err := a.actionStorage.GetAction(id)
	if err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			http.Error(w, "Action not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(action)
}

// createAction godoc
//
//	@Summary		Create action
//	@Description	Create a new action
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			action	body		core.Action	true	"Action object"
//	@Success		201		{object}	core.Action
//	@Failure		400		{string}	string		"Invalid JSON"
//	@Failure		503		{string}	string		"Action storage not available"
//	@Router			/api/actions [post]
func (a *API) createAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	var action core.Action
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	action.ID = uuid.New().String()

	if err := a.actionStorage.CreateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(action)
}

// updateAction godoc
//
//	@Summary		Update action
//	@Description	Update an existing action
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string		true	"Action ID"
//	@Param			action		body		core.Action	true	"Action object"
//	@Success		200			{object}	core.Action
//	@Failure		400			{string}	string		"Invalid JSON"
//	@Failure		404			{string}	string		"Action not found"
//	@Failure		503			{string}	string		"Action storage not available"
//	@Router			/api/actions/{id} [put]
func (a *API) updateAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var action core.Action
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	action.ID = id

	if err := a.actionStorage.UpdateAction(id, &action); err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			http.Error(w, "Action not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(action)
}

// deleteAction godoc
//
//	@Summary		Delete action
//	@Description	Delete an action by ID
//	@Tags			actions
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Action ID"
//	@Success		200	{string}	string	"Action deleted"
//	@Failure		404	{string}	string	"Action not found"
//	@Failure		503	{string}	string	"Action storage not available"
//	@Router			/api/actions/{id} [delete]
func (a *API) deleteAction(w http.ResponseWriter, r *http.Request) {
	if a.actionStorage == nil {
		http.Error(w, "Action storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.actionStorage.DeleteAction(id); err != nil {
		if errors.Is(err, storage.ErrActionNotFound) {
			http.Error(w, "Action not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// getCorrelationRules godoc
//
//	@Summary		Get correlation rules
//	@Description	Returns a list of all correlation rules
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		core.CorrelationRule
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules [get]
func (a *API) getCorrelationRules(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	rules, err := a.correlationRuleStorage.GetCorrelationRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// getCorrelationRule godoc
//
//	@Summary		Get correlation rule
//	@Description	Get a correlation rule by ID
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{object}	core.CorrelationRule
//	@Failure		404	{string}	string	"Correlation rule not found"
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [get]
func (a *API) getCorrelationRule(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	rule, err := a.correlationRuleStorage.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			http.Error(w, "Correlation rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

// createCorrelationRule godoc
//
//	@Summary		Create correlation rule
//	@Description	Create a new correlation rule
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			rule	body		core.CorrelationRule	true	"Correlation Rule object"
//	@Success		201		{object}	core.CorrelationRule
//	@Failure		400		{string}	string				"Invalid JSON"
//	@Failure		503		{string}	string				"Correlation rule storage not available"
//	@Router			/api/correlation-rules [post]
func (a *API) createCorrelationRule(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	var rule core.CorrelationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateCorrelationRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = uuid.New().String()

	if err := a.correlationRuleStorage.CreateCorrelationRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

// updateCorrelationRule godoc
//
//	@Summary		Update correlation rule
//	@Description	Update an existing correlation rule
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Correlation Rule ID"
//	@Param			rule	body		core.CorrelationRule	true	"Correlation Rule object"
//	@Success		200		{object}	core.CorrelationRule
//	@Failure		400		{string}	string				"Invalid JSON"
//	@Failure		404		{string}	string				"Correlation rule not found"
//	@Failure		503		{string}	string				"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [put]
func (a *API) updateCorrelationRule(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var rule core.CorrelationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validateCorrelationRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = id

	if err := a.correlationRuleStorage.UpdateCorrelationRule(id, &rule); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			http.Error(w, "Correlation rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

// deleteCorrelationRule godoc
//
//	@Summary		Delete correlation rule
//	@Description	Delete a correlation rule by ID
//	@Tags			correlation-rules
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Correlation Rule ID"
//	@Success		200	{string}	string	"Correlation rule deleted"
//	@Failure		404	{string}	string	"Correlation rule not found"
//	@Failure		503	{string}	string	"Correlation rule storage not available"
//	@Router			/api/correlation-rules/{id} [delete]
func (a *API) deleteCorrelationRule(w http.ResponseWriter, r *http.Request) {
	if a.correlationRuleStorage == nil {
		http.Error(w, "Correlation rule storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.correlationRuleStorage.DeleteCorrelationRule(id); err != nil {
		if errors.Is(err, storage.ErrCorrelationRuleNotFound) {
			http.Error(w, "Correlation rule not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// getListeners godoc
//
//	@Summary		Get listeners
//	@Description	Returns information about active listeners
//	@Tags			system
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Router			/api/listeners [get]
func (a *API) getListeners(w http.ResponseWriter, r *http.Request) {
	listeners := map[string]interface{}{
		"syslog": map[string]interface{}{
			"host": a.config.Listeners.Syslog.Host,
			"port": a.config.Listeners.Syslog.Port,
		},
		"cef": map[string]interface{}{
			"host": a.config.Listeners.CEF.Host,
			"port": a.config.Listeners.CEF.Port,
		},
		"json": map[string]interface{}{
			"host": a.config.Listeners.JSON.Host,
			"port": a.config.Listeners.JSON.Port,
			"tls":  a.config.Listeners.JSON.TLS,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listeners)
}

// getDashboardStats godoc
//
//	@Summary		Get dashboard stats
//	@Description	Returns dashboard statistics
//	@Tags			dashboard
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		503	{string}	string	"Storage not available"
//	@Router			/api/dashboard [get]
func (a *API) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil || a.alertStorage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	eventCount, err := a.eventStorage.GetEventCount()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get event count: %v", err), http.StatusInternalServerError)
		return
	}

	alertCount, err := a.alertStorage.GetAlertCount()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get alert count: %v", err), http.StatusInternalServerError)
		return
	}

	stats := map[string]interface{}{
		"events": eventCount,
		"alerts": alertCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// getDashboardChart godoc
//
//	@Summary		Get dashboard chart data
//	@Description	Returns historical chart data for events and alerts
//	@Tags			dashboard
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}	map[string]interface{}
//	@Failure		503	{string}	string	"Storage not available"
//	@Router			/api/dashboard/chart [get]
func (a *API) getDashboardChart(w http.ResponseWriter, r *http.Request) {
	if a.eventStorage == nil || a.alertStorage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	eventData, err := a.eventStorage.GetEventCountsByMonth()
	if err != nil {
		a.logger.Errorw("Failed to get event counts", "error", err)
		http.Error(w, "Failed to retrieve event data", http.StatusInternalServerError)
		return
	}

	alertData, err := a.alertStorage.GetAlertCountsByMonth()
	if err != nil {
		a.logger.Errorw("Failed to get alert counts", "error", err)
		http.Error(w, "Failed to retrieve alert data", http.StatusInternalServerError)
		return
	}

	// Merge event and alert data
	alertMap := make(map[string]int)
	for _, alert := range alertData {
		if name, ok := alert["name"].(string); ok {
			if a, ok := alert["alerts"].(int); ok {
				alertMap[name] = a
			}
		}
	}
	chartData := make([]map[string]interface{}, len(eventData))
	for i, event := range eventData {
		name := event["name"]
		events := event["events"]
		alerts := 0
		if nameStr, ok := name.(string); ok {
			alerts = alertMap[nameStr]
		}
		chartData[i] = map[string]interface{}{
			"name":   name,
			"events": events,
			"alerts": alerts,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chartData)
}

// healthCheck godoc
//
//	@Summary		Health check
//	@Description	Returns the health status of the service
//	@Tags			system
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]string
//	@Router			/health [get]
func (a *API) healthCheck(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	if a.eventStorage == nil || a.alertStorage == nil {
		status = "degraded"
	}

	response := map[string]string{
		"status": status,
		"time":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
