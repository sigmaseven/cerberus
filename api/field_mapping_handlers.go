package api

import (
	"fmt"
	"net/http"

	"cerberus/storage"

	"github.com/gorilla/mux"
)

// getFieldMappings returns all field mappings
func (a *API) getFieldMappings(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	mappings, err := a.fieldMappingStorage.List()
	if err != nil {
		a.logger.Errorw("Failed to fetch field mappings", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to fetch field mappings", err, a.logger)
		return
	}

	// Ensure we return empty array, not null
	if mappings == nil {
		mappings = []*storage.FieldMapping{}
	}

	a.respondJSON(w, mappings, http.StatusOK)
}

// getFieldMapping returns a specific field mapping by ID or name
func (a *API) getFieldMapping(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	idOrName := vars["id"]

	// Try to get by ID first
	mapping, err := a.fieldMappingStorage.Get(idOrName)
	if err != nil {
		// Try by name
		mapping, err = a.fieldMappingStorage.GetByName(idOrName)
		if err != nil {
			writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
			return
		}
	}

	a.respondJSON(w, mapping, http.StatusOK)
}

// createFieldMapping creates a new field mapping
func (a *API) createFieldMapping(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	var mapping storage.FieldMapping
	if err := a.decodeJSONBody(w, r, &mapping); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate required fields
	if mapping.Name == "" {
		writeError(w, http.StatusBadRequest, "Name is required", nil, a.logger)
		return
	}

	if err := a.fieldMappingStorage.Create(&mapping); err != nil {
		a.logger.Errorw("Failed to create field mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create field mapping", err, a.logger)
		return
	}

	a.respondJSON(w, mapping, http.StatusCreated)
}

// updateFieldMapping updates an existing field mapping
func (a *API) updateFieldMapping(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	// Get existing mapping
	existing, err := a.fieldMappingStorage.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
		return
	}

	var updates storage.FieldMapping
	if err := a.decodeJSONBody(w, r, &updates); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Preserve ID and apply updates
	updates.ID = existing.ID

	if err := a.fieldMappingStorage.Update(&updates); err != nil {
		if err.Error() == fmt.Sprintf("cannot update builtin field mapping: %s", existing.Name) {
			writeError(w, http.StatusForbidden, "Cannot update builtin field mapping", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to update field mapping", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to update field mapping", err, a.logger)
		return
	}

	// Get the updated mapping to return
	updated, _ := a.fieldMappingStorage.Get(id)
	a.respondJSON(w, updated, http.StatusOK)
}

// deleteFieldMapping deletes a field mapping
func (a *API) deleteFieldMapping(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.fieldMappingStorage.Delete(id); err != nil {
		if err.Error() == "field mapping not found: "+id {
			writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
			return
		}
		// Check if it's a builtin protection error
		existing, _ := a.fieldMappingStorage.Get(id)
		if existing != nil && existing.IsBuiltin {
			writeError(w, http.StatusForbidden, "Cannot delete builtin field mapping", err, a.logger)
			return
		}
		a.logger.Errorw("Failed to delete field mapping", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Failed to delete field mapping", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"success": true,
		"message": "Field mapping deleted successfully",
	}, http.StatusOK)
}

// reloadFieldMappings reloads field mappings from YAML file
func (a *API) reloadFieldMappings(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	// Use default path or get from config
	yamlPath := "config/field_mappings.yaml"
	if a.config != nil && a.config.FieldMappings.YAMLPath != "" {
		yamlPath = a.config.FieldMappings.YAMLPath
	}

	if err := a.fieldMappingStorage.SeedDefaults(yamlPath); err != nil {
		a.logger.Errorw("Failed to reload field mappings", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to reload field mappings", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"success": true,
		"message": "Field mappings reloaded successfully",
	}, http.StatusOK)
}

// testFieldMapping tests a field mapping against a sample log
func (a *API) testFieldMapping(w http.ResponseWriter, r *http.Request) {
	if a.fieldMappingStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Field mapping storage is not configured", nil, a.logger)
		return
	}

	var request struct {
		MappingID string                 `json:"mapping_id"`
		SampleLog map[string]interface{} `json:"sample_log"`
	}

	if err := a.decodeJSONBody(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if request.MappingID == "" || request.SampleLog == nil {
		writeError(w, http.StatusBadRequest, "mapping_id and sample_log are required", nil, a.logger)
		return
	}

	// Get the mapping
	mapping, err := a.fieldMappingStorage.Get(request.MappingID)
	if err != nil {
		mapping, err = a.fieldMappingStorage.GetByName(request.MappingID)
		if err != nil {
			writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
			return
		}
	}

	// Apply mapping to sample log
	normalizedFields := make(map[string]interface{})
	unmappedFields := make([]string, 0)

	for rawField, value := range request.SampleLog {
		if sigmaField, ok := mapping.Mappings[rawField]; ok {
			normalizedFields[sigmaField] = value
		} else {
			unmappedFields = append(unmappedFields, rawField)
		}
	}

	a.respondJSON(w, map[string]interface{}{
		"mapping_id":        mapping.ID,
		"mapping_name":      mapping.Name,
		"original_fields":   len(request.SampleLog),
		"normalized_fields": normalizedFields,
		"unmapped_fields":   unmappedFields,
		"coverage":          float64(len(normalizedFields)) / float64(len(request.SampleLog)) * 100,
	}, http.StatusOK)
}

// discoverFields discovers field mappings from a sample log
func (a *API) discoverFields(w http.ResponseWriter, r *http.Request) {
	var sampleLog map[string]interface{}

	if err := a.decodeJSONBody(w, r, &sampleLog); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	if len(sampleLog) == 0 {
		writeError(w, http.StatusBadRequest, "Sample log is empty", nil, a.logger)
		return
	}

	// Extract fields and suggest SIGMA field names
	suggestions := make(map[string]string)
	for field := range sampleLog {
		// Simple heuristic-based suggestions
		suggestion := suggestSigmaField(field)
		if suggestion != "" {
			suggestions[field] = suggestion
		}
	}

	a.respondJSON(w, map[string]interface{}{
		"fields":      extractFieldNames(sampleLog),
		"suggestions": suggestions,
	}, http.StatusOK)
}

// suggestSigmaField suggests a SIGMA field name based on common patterns
func suggestSigmaField(field string) string {
	// Common field name patterns to SIGMA mappings
	patterns := map[string]string{
		"src_ip":          "SourceIp",
		"source_ip":       "SourceIp",
		"srcip":           "SourceIp",
		"dst_ip":          "DestinationIp",
		"dest_ip":         "DestinationIp",
		"destination_ip":  "DestinationIp",
		"dstip":           "DestinationIp",
		"user":            "User",
		"username":        "User",
		"user_name":       "User",
		"process":         "Image",
		"process_name":    "Image",
		"command":         "CommandLine",
		"command_line":    "CommandLine",
		"commandline":     "CommandLine",
		"cmd":             "CommandLine",
		"parent_process":  "ParentImage",
		"parent_image":    "ParentImage",
		"hash":            "Hashes",
		"md5":             "Hashes",
		"sha256":          "Hashes",
		"event_id":        "EventID",
		"eventid":         "EventID",
		"event_type":      "EventType",
		"eventtype":       "EventType",
		"target_user":     "TargetUserName",
		"target_username": "TargetUserName",
		"logon_type":      "LogonType",
		"hostname":        "ComputerName",
		"computer_name":   "ComputerName",
		"computer":        "ComputerName",
		"registry_key":    "TargetObject",
		"registry_value":  "Details",
		"file_path":       "TargetFilename",
		"filename":        "TargetFilename",
		"service_name":    "ServiceName",
		"service":         "ServiceName",
	}

	// Convert to lowercase for comparison
	lowerField := field
	if mapped, ok := patterns[lowerField]; ok {
		return mapped
	}

	return ""
}

// extractFieldNames extracts all field names from a nested JSON structure
func extractFieldNames(data map[string]interface{}) []string {
	fields := make([]string, 0, len(data))
	for field := range data {
		fields = append(fields, field)
	}
	return fields
}
