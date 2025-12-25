package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidateRequest represents a validation request
type ValidateRequest struct {
	SigmaYAML string `json:"sigma_yaml"`
}

// ValidateResponse represents the validation result
type ValidateResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Category string   `json:"category"` // Detected category: detection|correlation
}

// handleValidateRule validates SIGMA YAML without creating a rule
// POST /api/v1/rules/validate
//
// Security: YAML bomb protection, no state changes, rate limiting applied
// Production: Returns detailed validation errors and warnings
//
// @Summary		Validate rule
// @Description	Validate SIGMA YAML without creating the rule
// @Tags		rules
// @Accept		json
// @Produce		json
// @Param		request body ValidateRequest true "SIGMA YAML to validate"
// @Success		200 {object} ValidateResponse
// @Failure		400 {string} string "Invalid request"
// @Router		/api/v1/rules/validate [post]
func (a *API) handleValidateRule(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest
	if err := a.decodeJSONBodyWithLimit(w, r, &req, 1*1024*1024); err != nil {
		return
	}

	response := &ValidateResponse{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		Category: "detection", // default
	}

	// Validate SIGMA YAML is not empty
	trimmedYAML := strings.TrimSpace(req.SigmaYAML)
	if trimmedYAML == "" {
		response.Valid = false
		response.Errors = append(response.Errors, "sigma_yaml cannot be empty")
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// Security: Protect against YAML bombs
	const maxYAMLSize = 1024 * 1024 // 1MB
	if len(req.SigmaYAML) > maxYAMLSize {
		response.Valid = false
		response.Errors = append(response.Errors,
			fmt.Sprintf("sigma_yaml too large: %d bytes (max %d)", len(req.SigmaYAML), maxYAMLSize))
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// Parse YAML structure
	var sigmaRule map[string]interface{}
	if err := yaml.Unmarshal([]byte(req.SigmaYAML), &sigmaRule); err != nil {
		response.Valid = false
		response.Errors = append(response.Errors, fmt.Sprintf("invalid YAML syntax: %v", err))
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	// Validate required SIGMA fields
	a.validateSigmaRequiredFields(sigmaRule, response)

	// Validate SIGMA structure
	a.validateSigmaStructure(sigmaRule, response)

	// Detect category (correlation vs detection)
	if _, hasCorrelation := sigmaRule["correlation"]; hasCorrelation {
		response.Category = "correlation"
		a.validateSigmaCorrelation(sigmaRule, response)
	} else {
		response.Category = "detection"
		a.validateSigmaDetection(sigmaRule, response)
	}

	// Add warnings for best practices
	a.addSigmaWarnings(sigmaRule, response)

	a.respondJSON(w, response, http.StatusOK)
}

// validateSigmaRequiredFields checks for required SIGMA fields
// CCN: 6 (within limit of 10)
func (a *API) validateSigmaRequiredFields(sigmaRule map[string]interface{}, response *ValidateResponse) {
	// Required fields according to SIGMA specification
	requiredFields := []string{"title", "description", "detection"}

	for _, field := range requiredFields {
		if _, ok := sigmaRule[field]; !ok {
			response.Valid = false
			response.Errors = append(response.Errors, fmt.Sprintf("missing required field: %s", field))
		} else {
			// Check if field is empty string
			if str, ok := sigmaRule[field].(string); ok && strings.TrimSpace(str) == "" {
				response.Valid = false
				response.Errors = append(response.Errors, fmt.Sprintf("field cannot be empty: %s", field))
			}
		}
	}

	// Validate level field if present
	if level, ok := sigmaRule["level"]; ok {
		levelStr, ok := level.(string)
		if !ok {
			response.Valid = false
			response.Errors = append(response.Errors, "level must be a string")
		} else {
			validLevels := map[string]bool{
				"critical": true, "high": true, "medium": true, "low": true, "informational": true,
			}
			if !validLevels[strings.ToLower(levelStr)] {
				response.Valid = false
				response.Errors = append(response.Errors,
					fmt.Sprintf("invalid level: %s (must be critical, high, medium, low, or informational)", levelStr))
			}
		}
	}
}

// validateSigmaStructure validates SIGMA YAML structure
// CCN: 5 (within limit of 10)
func (a *API) validateSigmaStructure(sigmaRule map[string]interface{}, response *ValidateResponse) {
	// Validate logsource if present
	if logsource, ok := sigmaRule["logsource"]; ok {
		logsourceMap, ok := logsource.(map[string]interface{})
		if !ok {
			response.Valid = false
			response.Errors = append(response.Errors, "logsource must be a map")
		} else {
			// Validate at least one logsource field is present
			if len(logsourceMap) == 0 {
				response.Warnings = append(response.Warnings, "logsource is empty (consider adding category, product, or service)")
			}
		}
	}

	// Validate tags if present
	if tags, ok := sigmaRule["tags"]; ok {
		if _, ok := tags.([]interface{}); !ok {
			response.Valid = false
			response.Errors = append(response.Errors, "tags must be an array")
		}
	}

	// Validate references if present
	if references, ok := sigmaRule["references"]; ok {
		if _, ok := references.([]interface{}); !ok {
			response.Valid = false
			response.Errors = append(response.Errors, "references must be an array")
		}
	}
}

// validateSigmaDetection validates SIGMA detection section
// CCN: 5 (within limit of 10)
func (a *API) validateSigmaDetection(sigmaRule map[string]interface{}, response *ValidateResponse) {
	detection, ok := sigmaRule["detection"]
	if !ok {
		response.Valid = false
		response.Errors = append(response.Errors, "missing detection section")
		return
	}

	detectionMap, ok := detection.(map[string]interface{})
	if !ok {
		response.Valid = false
		response.Errors = append(response.Errors, "detection must be a map")
		return
	}

	// Check for condition field
	if _, hasCondition := detectionMap["condition"]; !hasCondition {
		response.Valid = false
		response.Errors = append(response.Errors, "detection section must have a condition")
	}

	// Validate that at least one selection exists
	hasSelection := false
	for key := range detectionMap {
		if key != "condition" && key != "timeframe" {
			hasSelection = true
			break
		}
	}
	if !hasSelection {
		response.Valid = false
		response.Errors = append(response.Errors, "detection section must have at least one selection")
	}
}

// validateSigmaCorrelation validates SIGMA correlation section
// CCN: 6 (within limit of 10)
func (a *API) validateSigmaCorrelation(sigmaRule map[string]interface{}, response *ValidateResponse) {
	correlation, ok := sigmaRule["correlation"]
	if !ok {
		return // Already checked in caller
	}

	corrMap, ok := correlation.(map[string]interface{})
	if !ok {
		response.Valid = false
		response.Errors = append(response.Errors, "correlation must be a map")
		return
	}

	// Validate type
	if corrType, ok := corrMap["type"]; ok {
		typeStr, ok := corrType.(string)
		if !ok {
			response.Valid = false
			response.Errors = append(response.Errors, "correlation.type must be a string")
		} else {
			validTypes := map[string]bool{
				"event_count": true, "value_count": true, "temporal": true,
			}
			if !validTypes[strings.ToLower(typeStr)] {
				response.Warnings = append(response.Warnings,
					fmt.Sprintf("unknown correlation type: %s (expected event_count, value_count, or temporal)", typeStr))
			}
		}
	} else {
		response.Valid = false
		response.Errors = append(response.Errors, "correlation section must have a type")
	}

	// Validate timespan
	if _, ok := corrMap["timespan"]; !ok {
		response.Valid = false
		response.Errors = append(response.Errors, "correlation section must have a timespan")
	}
}

// addSigmaWarnings adds best practice warnings
// CCN: 4 (within limit of 10)
func (a *API) addSigmaWarnings(sigmaRule map[string]interface{}, response *ValidateResponse) {
	// Warn if no author
	if _, ok := sigmaRule["author"]; !ok {
		response.Warnings = append(response.Warnings, "no author specified (recommended)")
	}

	// Warn if no date
	if _, ok := sigmaRule["date"]; !ok {
		response.Warnings = append(response.Warnings, "no date specified (recommended)")
	}

	// Warn if no level
	if _, ok := sigmaRule["level"]; !ok {
		response.Warnings = append(response.Warnings, "no level specified (recommended: critical, high, medium, low)")
	}

	// Warn if no tags
	if _, ok := sigmaRule["tags"]; !ok {
		response.Warnings = append(response.Warnings, "no tags specified (recommended for categorization)")
	}
}

// handleDeprecatedEndpoint returns 410 Gone for deprecated correlation-rules endpoints
// This handler is used for all /api/v1/correlation-rules/* endpoints
//
// Security: Logs access attempts for monitoring migration progress
// Production: Returns migration guidance in response headers
//
// @Summary		Deprecated endpoint
// @Description	This endpoint has been deprecated and replaced by unified /api/v1/rules
// @Tags		rules
// @Produce		json
// @Success		410 {string} string "Endpoint deprecated"
// @Router		/api/v1/correlation-rules [get]
func (a *API) handleDeprecatedEndpoint(w http.ResponseWriter, r *http.Request) {
	// Set deprecation headers
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Sunset", "2025-06-01")
	w.Header().Set("Link", "</api/v1/rules?category=correlation>; rel=\"successor-version\"")

	// Log access for monitoring
	userID := "unknown"
	if uid, ok := GetUserID(r.Context()); ok {
		userID = uid
	}
	a.logger.Warnw("Deprecated endpoint accessed",
		"path", r.URL.Path,
		"method", r.Method,
		"user_id", userID,
		"remote_addr", r.RemoteAddr)

	// Return 410 Gone with migration guidance
	response := map[string]interface{}{
		"error":   "This endpoint is deprecated",
		"message": "Please use /api/v1/rules?category=correlation instead",
		"migration_guide": map[string]string{
			"list":   "GET /api/v1/rules?category=correlation",
			"get":    "GET /api/v1/rules/{id}",
			"create": "POST /api/v1/rules (auto-detects correlation)",
			"update": "PUT /api/v1/rules/{id}",
			"delete": "DELETE /api/v1/rules/{id}",
		},
		"sunset_date": "2025-06-01",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Errorw("Failed to encode deprecation response", "error", err)
	}
}
