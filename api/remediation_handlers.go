package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// =============================================================================
// ALRT-006: One-Click Remediation Actions
// Backend API endpoints for security remediation workflows
// =============================================================================

// BlockIPRequest represents a request to block an IP address
type BlockIPRequest struct {
	IP      string `json:"ip"`
	AlertID string `json:"alertId,omitempty"` // Optional: for audit trail
	Reason  string `json:"reason,omitempty"`  // Optional
}

// BlockIPResponse represents the response from blocking an IP
type BlockIPResponse struct {
	Success bool   `json:"success"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Message string `json:"message"`
}

// HuntIOCsRequest represents a request to hunt for IOCs
type HuntIOCsRequest struct {
	IOCs    []IOCEntry `json:"iocs"`
	AlertID string     `json:"alertId,omitempty"` // Optional: for context
}

// IOCEntry represents a single indicator of compromise
type IOCEntry struct {
	Type  string `json:"type"`  // ip, domain, hash, url
	Value string `json:"value"`
}

// HuntIOCsResponse represents the response from initiating an IOC hunt
type HuntIOCsResponse struct {
	Success  bool   `json:"success"`
	Action   string `json:"action"`
	HuntID   string `json:"huntId"`
	IOCCount int    `json:"iocCount"`
	Message  string `json:"message"`
}

// RemediationError represents a validation error response
type RemediationError struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// Valid IOC types for hunting
var validIOCTypes = map[string]bool{
	"ip":     true,
	"domain": true,
	"hash":   true,
	"url":    true,
	"file":   true,
	"email":  true,
}

// BLOCKER 8 FIX: Combined hash pattern for efficiency (single regex match)
// Matches MD5 (32), SHA1 (40), SHA256 (64), or SHA512 (128) hex strings
var hashPattern = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$`)

// domainPattern validates domain names (ReDoS-safe pattern)
// IMMUTABLE: Compiled once at package init, safe for concurrent access
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// Maximum IOC value length (defense against memory exhaustion)
const maxIOCValueLength = 4096

// sanitizeLogField is defined in playbook_handlers.go
// BLOCKER 4 FIX: Prevent log injection attacks

// blockIP handles POST /api/v1/remediation/block-ip
// ALRT-006: Block a malicious IP address
//
//	@Summary		Block IP address
//	@Description	Block a malicious IP address. This is a placeholder endpoint that logs the remediation request.
//	@Description	In production, this would integrate with a firewall, EDR, or SOAR platform.
//	@Tags			remediation
//	@Accept			json
//	@Produce		json
//	@Param			request	body		BlockIPRequest		true	"Block IP request"
//	@Success		200		{object}	BlockIPResponse		"IP blocked successfully"
//	@Failure		400		{object}	RemediationError	"Validation error"
//	@Failure		401		{object}	map[string]string	"Unauthorized"
//	@Failure		500		{object}	RemediationError	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/remediation/block-ip [post]
func (a *API) blockIP(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// Validate IP address is provided
	if req.IP == "" {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "IP address required")
		return
	}

	// Validate IP address format
	if net.ParseIP(req.IP) == nil {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid IP address format")
		return
	}

	// Get context for audit logging
	username := getUsernameFromContext(r.Context())
	requestID := GetRequestIDOrDefault(r.Context())
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// BLOCKER 4 FIX: Sanitize user input before logging
	sanitizedAlertID := sanitizeLogField(req.AlertID)
	sanitizedReason := sanitizeLogField(req.Reason)

	// Audit log the remediation request with complete context
	a.logger.Infow("Remediation: Block IP request",
		"request_id", requestID,
		"action", "block_ip",
		"outcome", "success",
		"ip", req.IP,
		"alert_id", sanitizedAlertID,
		"reason", sanitizedReason,
		"requested_by", username,
		"client_ip", clientIP,
		"user_agent", userAgent)

	// PLACEHOLDER: In production, this would integrate with:
	// - Firewall API (e.g., Palo Alto, Cisco, Fortinet)
	// - EDR platform (e.g., CrowdStrike, SentinelOne)
	// - SOAR platform (e.g., Phantom, Demisto)
	// For now, we just log the request and return success

	response := BlockIPResponse{
		Success: true,
		Action:  "block-ip",
		Target:  req.IP,
		Message: fmt.Sprintf("IP %s has been blocked", req.IP),
	}

	a.respondJSON(w, response, http.StatusOK)
}

// huntIOCs handles POST /api/v1/hunt/iocs
// ALRT-006: Initiate an IOC hunt across security telemetry
//
//	@Summary		Hunt for IOCs
//	@Description	Initiate a threat hunt for specified indicators of compromise.
//	@Description	This is a placeholder endpoint that logs the hunt request.
//	@Description	In production, this would trigger searches across SIEM, EDR, and other security tools.
//	@Tags			remediation
//	@Accept			json
//	@Produce		json
//	@Param			request	body		HuntIOCsRequest		true	"Hunt IOCs request"
//	@Success		200		{object}	HuntIOCsResponse	"IOC hunt initiated"
//	@Failure		400		{object}	RemediationError	"Validation error"
//	@Failure		401		{object}	map[string]string	"Unauthorized"
//	@Failure		500		{object}	RemediationError	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/hunt/iocs [post]
func (a *API) huntIOCs(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req HuntIOCsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// Validate IOCs array is provided (handles both nil and empty)
	if req.IOCs == nil || len(req.IOCs) == 0 {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "IOCs array required")
		return
	}

	// Validate each IOC
	for i, ioc := range req.IOCs {
		if ioc.Type == "" {
			a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("IOC %d: type is required", i))
			return
		}
		if !validIOCTypes[ioc.Type] {
			a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("IOC %d: invalid type '%s'", i, ioc.Type))
			return
		}
		if ioc.Value == "" {
			a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("IOC %d: value is required", i))
			return
		}
		// QUALITY 5 FIX: Early length check before type-specific validation
		if len(ioc.Value) > maxIOCValueLength {
			a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("IOC %d: value too long (max %d chars)", i, maxIOCValueLength))
			return
		}

		// Type-specific validation
		if err := validateIOCValue(ioc.Type, ioc.Value); err != nil {
			a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("IOC %d: %s", i, err.Error()))
			return
		}
	}

	// Get context for audit logging
	username := getUsernameFromContext(r.Context())
	requestID := GetRequestIDOrDefault(r.Context())
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// BLOCKER 9 FIX: Generate collision-resistant hunt ID using UUID
	huntID := fmt.Sprintf("hunt-%s", uuid.New().String())

	// BLOCKER 4 FIX: Sanitize user input before logging
	sanitizedAlertID := sanitizeLogField(req.AlertID)

	// Audit log the hunt request with complete context
	a.logger.Infow("Remediation: IOC hunt initiated",
		"request_id", requestID,
		"action", "hunt_iocs",
		"outcome", "success",
		"hunt_id", huntID,
		"ioc_count", len(req.IOCs),
		"alert_id", sanitizedAlertID,
		"requested_by", username,
		"client_ip", clientIP,
		"user_agent", userAgent)

	// Log individual IOCs at debug level
	for _, ioc := range req.IOCs {
		a.logger.Debugw("IOC hunt target",
			"hunt_id", huntID,
			"type", ioc.Type,
			"value", sanitizeLogField(ioc.Value))
	}

	// PLACEHOLDER: In production, this would:
	// - Create a search job in the SIEM
	// - Query EDR for endpoint matches
	// - Search threat intelligence feeds
	// - Trigger automated investigation workflows

	response := HuntIOCsResponse{
		Success:  true,
		Action:   "hunt-iocs",
		HuntID:   huntID,
		IOCCount: len(req.IOCs),
		Message:  "IOC hunt initiated",
	}

	a.respondJSON(w, response, http.StatusOK)
}

// validateIOCValue performs type-specific validation on IOC values
func validateIOCValue(iocType, value string) error {
	switch iocType {
	case "ip":
		if net.ParseIP(value) == nil {
			return fmt.Errorf("invalid IP address format")
		}
	case "domain":
		// BLOCKER 7 FIX: Add minimum length check
		if len(value) < 1 || len(value) > 253 {
			return fmt.Errorf("domain name length must be 1-253 characters")
		}
		if !domainPattern.MatchString(value) {
			return fmt.Errorf("invalid domain format")
		}
	case "hash":
		// BLOCKER 8 FIX: Use combined pattern for efficiency
		if !hashPattern.MatchString(value) {
			return fmt.Errorf("invalid hash format (expected MD5, SHA1, SHA256, or SHA512)")
		}
	case "url":
		// BLOCKER 5 FIX: Bounds-safe URL validation
		if len(value) < 10 { // Minimum: "http://a.b"
			return fmt.Errorf("URL too short")
		}
		hasHTTP := len(value) >= 7 && value[:7] == "http://"
		hasHTTPS := len(value) >= 8 && value[:8] == "https://"
		if !hasHTTP && !hasHTTPS {
			return fmt.Errorf("URL must start with http:// or https://")
		}
		// Parse URL to validate structure
		if _, err := url.Parse(value); err != nil {
			return fmt.Errorf("invalid URL format: %v", err)
		}
	case "file":
		// QUALITY 6 FIX: Add sanity checks for file paths
		if len(value) == 0 || len(value) > 4096 {
			return fmt.Errorf("invalid file path length")
		}
		// Reject obvious path traversal attempts
		if strings.Contains(value, "..") {
			return fmt.Errorf("file path cannot contain '..'")
		}
		// Reject null bytes (common in path traversal)
		if strings.Contains(value, "\x00") {
			return fmt.Errorf("file path contains invalid characters")
		}
	case "email":
		// BLOCKER 6 FIX: Use net/mail for safe email validation
		if len(value) > 254 { // RFC 5321 max email length
			return fmt.Errorf("email address too long")
		}
		if _, err := mail.ParseAddress(value); err != nil {
			return fmt.Errorf("invalid email format")
		}
	}
	return nil
}

// writeRemediationError writes a JSON error response with code and error fields
// BLOCKER 2/3 FIX: Now a method on *API for access to logger
func (a *API) writeRemediationError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(RemediationError{
		Code:  code,
		Error: message,
	}); err != nil {
		// Response already started, log for monitoring
		a.logger.Errorw("Failed to encode remediation error response",
			"error", err,
			"code", code,
			"message", message)
	}
}

// =============================================================================
// Additional Remediation Endpoints for E2E Test Support
// =============================================================================

// UnblockIPRequest represents a request to unblock an IP address
type UnblockIPRequest struct {
	IP      string `json:"ip"`
	AlertID string `json:"alertId,omitempty"` // Optional: for audit trail
	Reason  string `json:"reason,omitempty"`  // Optional
}

// UnblockIPResponse represents the response from unblocking an IP
type UnblockIPResponse struct {
	Success bool   `json:"success"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Message string `json:"message"`
}

// RemediationActionRecord represents a single remediation action taken for an alert
type RemediationActionRecord struct {
	ActionID    string `json:"actionId"`
	AlertID     string `json:"alertId"`
	ActionType  string `json:"actionType"` // block-ip, unblock-ip, hunt-iocs
	Target      string `json:"target"`
	Status      string `json:"status"` // pending, completed, failed
	RequestedBy string `json:"requestedBy"`
	RequestedAt string `json:"requestedAt"`
	CompletedAt string `json:"completedAt,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// GetRemediationActionsResponse represents the response for listing remediation actions
type GetRemediationActionsResponse struct {
	Success bool                      `json:"success"`
	Data    []RemediationActionRecord `json:"data"`
}

// unblockIP handles POST /api/v1/remediation/unblock-ip
// Unblock a previously blocked IP address
//
//	@Summary		Unblock IP address
//	@Description	Unblock a previously blocked IP address. This is a placeholder endpoint that logs the remediation request.
//	@Description	In production, this would integrate with a firewall, EDR, or SOAR platform.
//	@Tags			remediation
//	@Accept			json
//	@Produce		json
//	@Param			request	body		UnblockIPRequest	true	"Unblock IP request"
//	@Success		200		{object}	UnblockIPResponse	"IP unblocked successfully"
//	@Failure		400		{object}	RemediationError	"Validation error"
//	@Failure		401		{object}	map[string]string	"Unauthorized"
//	@Failure		500		{object}	RemediationError	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/remediation/unblock-ip [post]
func (a *API) unblockIP(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req UnblockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// Validate IP address is provided
	if req.IP == "" {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "IP address required")
		return
	}

	// Validate IP address format
	if net.ParseIP(req.IP) == nil {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid IP address format")
		return
	}

	// Get context for audit logging
	username := getUsernameFromContext(r.Context())
	requestID := GetRequestIDOrDefault(r.Context())
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Sanitize user input before logging
	sanitizedAlertID := sanitizeLogField(req.AlertID)
	sanitizedReason := sanitizeLogField(req.Reason)

	// Audit log the remediation request with complete context
	a.logger.Infow("Remediation: Unblock IP request",
		"request_id", requestID,
		"action", "unblock_ip",
		"outcome", "success",
		"ip", req.IP,
		"alert_id", sanitizedAlertID,
		"reason", sanitizedReason,
		"requested_by", username,
		"client_ip", clientIP,
		"user_agent", userAgent)

	// PLACEHOLDER: In production, this would integrate with:
	// - Firewall API (e.g., Palo Alto, Cisco, Fortinet)
	// - EDR platform (e.g., CrowdStrike, SentinelOne)
	// - SOAR platform (e.g., Phantom, Demisto)

	response := UnblockIPResponse{
		Success: true,
		Action:  "unblock-ip",
		Target:  req.IP,
		Message: fmt.Sprintf("IP %s has been unblocked", req.IP),
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getRemediationActions handles GET /api/v1/remediation/actions/{alertId}
// Get remediation actions for a specific alert
//
//	@Summary		Get remediation actions for alert
//	@Description	Retrieve all remediation actions taken for a specific alert.
//	@Description	This is a placeholder endpoint that returns mock data.
//	@Tags			remediation
//	@Produce		json
//	@Param			alertId	path		string							true	"Alert ID"
//	@Success		200		{object}	GetRemediationActionsResponse	"Remediation actions list"
//	@Failure		400		{object}	RemediationError				"Validation error"
//	@Failure		401		{object}	map[string]string				"Unauthorized"
//	@Failure		404		{object}	RemediationError				"Alert not found"
//	@Failure		500		{object}	RemediationError				"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/remediation/actions/{alertId} [get]
func (a *API) getRemediationActions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["alertId"]

	// Validate alert ID is provided
	if alertID == "" {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Alert ID required")
		return
	}

	// Validate alert ID length to prevent injection attacks
	if len(alertID) > 100 {
		a.writeRemediationError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid alert ID format")
		return
	}

	// PLACEHOLDER: In production, this would query a remediation actions database
	// For now, return an empty list to unblock E2E tests
	// The actual implementation would:
	// 1. Query remediation_actions table filtered by alertId
	// 2. Return all actions associated with the alert

	response := GetRemediationActionsResponse{
		Success: true,
		Data:    []RemediationActionRecord{}, // Empty list - no actions yet
	}

	a.respondJSON(w, response, http.StatusOK)
}
