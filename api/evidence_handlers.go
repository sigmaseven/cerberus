package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cerberus/core"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// investigationIDPattern validates investigation ID format (INV-YYYYMMDD-XXXX)
// This is critical for path traversal prevention
var investigationIDPattern = regexp.MustCompile(`^INV-\d{8}-[a-fA-F0-9]{4}$`)

const (
	maxUploadSize    = 50 * 1024 * 1024 // 50 MB max file size
	evidenceBasePath = "data/evidence"
)

// uploadEvidence handles evidence file upload for an alert
// @Summary Upload evidence
// @Description Upload an evidence file and attach it to an alert
// @Tags evidence
// @Accept multipart/form-data
// @Produce json
// @Param id path string true "Alert ID"
// @Param file formData file true "Evidence file"
// @Param description formData string false "Description of the evidence"
// @Success 201 {object} core.Evidence
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Alert not found"
// @Failure 413 {object} ErrorResponse "File too large"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/evidence [post]
func (a *API) uploadEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	// Check if evidence storage is available
	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Limit request size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "File too large (max 50MB)", err, a.logger)
			return
		}
		writeError(w, http.StatusBadRequest, "Failed to parse form", err, a.logger)
		return
	}

	// Get uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "No file uploaded", err, a.logger)
		return
	}
	defer file.Close()

	// Get description (optional)
	description := r.FormValue("description")

	// Validate file type (basic check)
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Get username from request
	username := r.Header.Get("X-Username")
	if username == "" {
		username = "anonymous"
	}

	// Create evidence record
	evidence := core.NewEvidence(alertID, header.Filename, mimeType, header.Size, username)
	evidence.Description = description

	// Ensure evidence directory exists
	evidenceDir := filepath.Join(evidenceBasePath, alertID)
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create evidence directory", err, a.logger)
		return
	}

	// Create file on disk
	filePath := filepath.Join(evidenceDir, evidence.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create file", err, a.logger)
		return
	}
	defer dst.Close()

	// Copy file and calculate hash
	hash := sha256.New()
	tee := io.TeeReader(file, hash)

	written, err := io.Copy(dst, tee)
	if err != nil {
		os.Remove(filePath) // Cleanup on error
		writeError(w, http.StatusInternalServerError, "Failed to save file", err, a.logger)
		return
	}

	evidence.Size = written
	evidence.Hash = hex.EncodeToString(hash.Sum(nil))

	// Store metadata
	if err := a.evidenceStorage.CreateEvidence(r.Context(), evidence); err != nil {
		os.Remove(filePath) // Cleanup on error
		writeError(w, http.StatusInternalServerError, "Failed to save evidence metadata", err, a.logger)
		return
	}

	a.logger.Infow("Evidence uploaded",
		"evidence_id", evidence.ID,
		"alert_id", alertID,
		"filename", evidence.Name,
		"size", evidence.Size,
		"uploaded_by", username,
	)

	// Populate UploadedBy user reference for response
	a.enrichEvidenceWithUserRef(r.Context(), evidence)

	a.respondJSON(w, evidence, http.StatusCreated)
}

// enrichEvidenceWithUserRef populates the UploadedBy field with user details
func (a *API) enrichEvidenceWithUserRef(ctx context.Context, evidence *core.Evidence) {
	if evidence.UploadedByID == "" {
		return
	}

	// Try to get user details from storage
	if a.userStorage != nil {
		user, err := a.userStorage.GetUserByUsername(ctx, evidence.UploadedByID)
		if err == nil && user != nil {
			role := user.RoleName
			if role == "" && len(user.Roles) > 0 {
				role = strings.Join(user.Roles, ",")
			}
			evidence.UploadedBy = &core.UserRef{
				ID:   user.Username, // Use username as ID since User struct doesn't have ID
				Name: user.Username,
				Role: role,
			}
			return
		}
	}

	// Fallback: create a minimal user reference with the ID as name
	evidence.UploadedBy = &core.UserRef{
		ID:   evidence.UploadedByID,
		Name: evidence.UploadedByID,
	}
}

// enrichEvidenceListWithUserRef populates UploadedBy for a list of evidence
func (a *API) enrichEvidenceListWithUserRef(ctx context.Context, evidenceList []*core.Evidence) {
	for _, ev := range evidenceList {
		a.enrichEvidenceWithUserRef(ctx, ev)
	}
}

// listEvidence returns all evidence for an alert
// @Summary List evidence
// @Description Get all evidence files attached to an alert
// @Tags evidence
// @Produce json
// @Param id path string true "Alert ID"
// @Success 200 {array} core.Evidence
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/evidence [get]
func (a *API) listEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Validate alert ID
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	evidenceList, err := a.evidenceStorage.ListEvidenceByAlert(r.Context(), alertID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list evidence", err, a.logger)
		return
	}

	if evidenceList == nil {
		evidenceList = []*core.Evidence{}
	}

	// Enrich with user references
	a.enrichEvidenceListWithUserRef(r.Context(), evidenceList)

	a.respondJSON(w, evidenceList, http.StatusOK)
}

// getEvidence downloads a specific evidence file
// @Summary Download evidence
// @Description Download a specific evidence file
// @Tags evidence
// @Produce application/octet-stream
// @Param id path string true "Alert ID"
// @Param evidence_id path string true "Evidence ID"
// @Success 200 {file} binary
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/evidence/{evidence_id} [get]
func (a *API) getEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]
	evidenceID := vars["evidence_id"]

	// Validate IDs
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}
	if err := validateUUID(evidenceID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid evidence ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Get evidence metadata
	evidence, err := a.evidenceStorage.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Evidence not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get evidence", err, a.logger)
		return
	}

	// Verify evidence belongs to the alert
	if evidence.AlertID != alertID {
		writeError(w, http.StatusNotFound, "Evidence not found for this alert", nil, a.logger)
		return
	}

	// Open file
	filePath := filepath.Join(evidenceBasePath, alertID, evidence.Filename)
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "Evidence file not found on disk", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to open evidence file", err, a.logger)
		return
	}
	defer file.Close()

	// Set headers for download
	w.Header().Set("Content-Type", evidence.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", evidence.Name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", evidence.Size))

	// Stream file to response
	io.Copy(w, file)
}

// downloadEvidence handles the /download endpoint variant that the frontend expects
// @Summary Download evidence file
// @Description Download a specific evidence file (alternate endpoint)
// @Tags evidence
// @Produce application/octet-stream
// @Param id path string true "Alert ID"
// @Param evidence_id path string true "Evidence ID"
// @Success 200 {file} binary
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/evidence/{evidence_id}/download [get]
func (a *API) downloadEvidence(w http.ResponseWriter, r *http.Request) {
	// Delegate to getEvidence which already handles file download
	a.getEvidence(w, r)
}

// deleteEvidence removes an evidence file
// @Summary Delete evidence
// @Description Delete an evidence file from an alert
// @Tags evidence
// @Produce json
// @Param id path string true "Alert ID"
// @Param evidence_id path string true "Evidence ID"
// @Success 204 "No content"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/alerts/{id}/evidence/{evidence_id} [delete]
func (a *API) deleteEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]
	evidenceID := vars["evidence_id"]

	// Validate IDs
	if err := validateUUID(alertID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid alert ID format", err, a.logger)
		return
	}
	if err := validateUUID(evidenceID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid evidence ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Get evidence to verify ownership and get filename
	evidence, err := a.evidenceStorage.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Evidence not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get evidence", err, a.logger)
		return
	}

	// Verify evidence belongs to the alert
	if evidence.AlertID != alertID {
		writeError(w, http.StatusNotFound, "Evidence not found for this alert", nil, a.logger)
		return
	}

	// Delete file from disk
	filePath := filepath.Join(evidenceBasePath, alertID, evidence.Filename)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		a.logger.Warnw("Failed to delete evidence file from disk", "path", filePath, "error", err)
		// Continue with metadata deletion even if file deletion fails
	}

	// Delete metadata
	if err := a.evidenceStorage.DeleteEvidence(r.Context(), evidenceID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete evidence", err, a.logger)
		return
	}

	username := r.Header.Get("X-Username")
	a.logger.Infow("Evidence deleted",
		"evidence_id", evidenceID,
		"alert_id", alertID,
		"deleted_by", username,
	)

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Investigation Evidence Handlers
// =============================================================================

// validateInvestigationID validates investigation ID format to prevent path traversal
// Investigation IDs follow the pattern: INV-YYYYMMDD-XXXX (e.g., INV-20250108-a1b2)
func validateInvestigationID(id string) error {
	if !investigationIDPattern.MatchString(id) {
		return fmt.Errorf("invalid investigation ID format: must match INV-YYYYMMDD-XXXX")
	}
	return nil
}

// validateFilename performs security validation on uploaded filenames
func validateFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	if len(filename) > 255 {
		return fmt.Errorf("filename too long (max 255 characters)")
	}
	// Check for path traversal attempts
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("filename contains invalid characters")
	}
	return nil
}

// allowedMimeTypes defines the allowed MIME types for evidence uploads
var allowedMimeTypes = map[string]bool{
	// Documents
	"application/pdf":    true,
	"application/json":   true,
	"text/plain":         true,
	"text/csv":           true,
	"application/xml":    true,
	"text/xml":           true,
	"text/html":          true,
	"application/msword": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
	// Images
	"image/png":  true,
	"image/jpeg": true,
	"image/gif":  true,
	"image/webp": true,
	"image/bmp":  true,
	"image/tiff": true,
	// Network captures
	"application/vnd.tcpdump.pcap": true,
	"application/x-pcapng":         true,
	// Archives
	"application/zip":    true,
	"application/x-gzip": true,
	"application/gzip":   true,
	"application/x-tar":  true,
	"application/x-7z-compressed": true,
	// Binary/Generic
	"application/octet-stream": true,
	// Logs
	"text/x-log": true,
}

// validateMimeType checks if the MIME type is allowed
func validateMimeType(mimeType string) error {
	if mimeType == "" {
		return nil // Will default to application/octet-stream
	}
	// Normalize MIME type (remove parameters like charset)
	if idx := strings.Index(mimeType, ";"); idx != -1 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	if !allowedMimeTypes[mimeType] {
		return fmt.Errorf("unsupported MIME type: %s", mimeType)
	}
	return nil
}

// uploadInvestigationEvidence handles evidence file upload for an investigation
// @Summary Upload investigation evidence
// @Description Upload an evidence file and attach it to an investigation
// @Tags evidence,investigations
// @Accept multipart/form-data
// @Produce json
// @Param id path string true "Investigation ID (format: INV-YYYYMMDD-XXXX)"
// @Param file formData file true "Evidence file"
// @Param description formData string false "Description of the evidence"
// @Success 201 {object} core.Evidence
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 403 {object} ErrorResponse "Investigation is closed"
// @Failure 404 {object} ErrorResponse "Investigation not found"
// @Failure 413 {object} ErrorResponse "File too large"
// @Failure 415 {object} ErrorResponse "Unsupported media type"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/investigations/{id}/evidence [post]
func (a *API) uploadInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	investigationID := vars["id"]

	// Validate investigation ID format (critical for path traversal prevention)
	if err := validateInvestigationID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", err, a.logger)
		return
	}

	// Check if storages are available
	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}
	if a.investigationStorage == nil {
		writeError(w, http.StatusInternalServerError, "Investigation storage not available", nil, a.logger)
		return
	}

	// Verify investigation exists and is not closed
	investigation, err := a.investigationStorage.GetInvestigation(investigationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to verify investigation", err, a.logger)
		return
	}

	// Check if investigation is closed (cannot add evidence to closed investigations)
	if investigation.Status == core.InvestigationStatusClosed ||
		investigation.Status == core.InvestigationStatusResolved ||
		investigation.Status == core.InvestigationStatusFalsePositive {
		writeError(w, http.StatusForbidden, "Cannot add evidence to a closed investigation", nil, a.logger)
		return
	}

	// Limit request size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "File too large (max 50MB)", err, a.logger)
			return
		}
		writeError(w, http.StatusBadRequest, "Failed to parse form", err, a.logger)
		return
	}

	// Get uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "No file uploaded", err, a.logger)
		return
	}
	defer file.Close()

	// Validate filename
	if err := validateFilename(header.Filename); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid filename", err, a.logger)
		return
	}

	// Get and validate MIME type
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	if err := validateMimeType(mimeType); err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "Unsupported file type", err, a.logger)
		return
	}

	// Get description (optional)
	description := r.FormValue("description")
	if len(description) > 2000 {
		writeError(w, http.StatusBadRequest, "Description too long (max 2000 characters)", nil, a.logger)
		return
	}

	// Get username from request
	username := r.Header.Get("X-Username")
	if username == "" {
		username = "anonymous"
	}

	// Create evidence record
	evidence := core.NewInvestigationEvidence(investigationID, header.Filename, mimeType, header.Size, username)
	evidence.Description = description

	// Validate single-parent constraint
	if err := evidence.Validate(); err != nil {
		writeError(w, http.StatusInternalServerError, "Evidence validation failed", err, a.logger)
		return
	}

	// Ensure evidence directory exists (separate from alerts)
	evidenceDir := filepath.Join(evidenceBasePath, "investigations", investigationID)
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create evidence directory", err, a.logger)
		return
	}

	// Create file on disk (filename is UUID, not user-provided name)
	filePath := filepath.Join(evidenceDir, evidence.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create file", err, a.logger)
		return
	}
	defer dst.Close()

	// Copy file and calculate hash
	hash := sha256.New()
	tee := io.TeeReader(file, hash)

	written, err := io.Copy(dst, tee)
	if err != nil {
		os.Remove(filePath) // Cleanup on error
		writeError(w, http.StatusInternalServerError, "Failed to save file", err, a.logger)
		return
	}

	evidence.Size = written
	evidence.Hash = hex.EncodeToString(hash.Sum(nil))

	// Store metadata
	if err := a.evidenceStorage.CreateEvidence(r.Context(), evidence); err != nil {
		os.Remove(filePath) // Cleanup on error
		writeError(w, http.StatusInternalServerError, "Failed to save evidence metadata", err, a.logger)
		return
	}

	// Audit logging
	a.logger.Infow("Investigation evidence uploaded",
		"evidence_id", evidence.ID,
		"investigation_id", investigationID,
		"filename", evidence.Name,
		"size", evidence.Size,
		"mime_type", evidence.MimeType,
		"hash", evidence.Hash,
		"uploaded_by", username,
	)

	// Populate UploadedBy user reference for response
	a.enrichEvidenceWithUserRef(r.Context(), evidence)

	a.respondJSON(w, evidence, http.StatusCreated)
}

// listInvestigationEvidence returns all evidence for an investigation
// @Summary List investigation evidence
// @Description Get all evidence files attached to an investigation
// @Tags evidence,investigations
// @Produce json
// @Param id path string true "Investigation ID (format: INV-YYYYMMDD-XXXX)"
// @Success 200 {array} core.Evidence
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Investigation not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/investigations/{id}/evidence [get]
func (a *API) listInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	investigationID := vars["id"]

	// Validate investigation ID format
	if err := validateInvestigationID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Optionally verify investigation exists (for better error messages)
	if a.investigationStorage != nil {
		_, err := a.investigationStorage.GetInvestigation(investigationID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
				return
			}
			// Don't fail on other errors, just proceed with listing
		}
	}

	evidenceList, err := a.evidenceStorage.ListEvidenceByInvestigation(r.Context(), investigationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list evidence", err, a.logger)
		return
	}

	if evidenceList == nil {
		evidenceList = []*core.Evidence{}
	}

	// Enrich with user references
	a.enrichEvidenceListWithUserRef(r.Context(), evidenceList)

	a.respondJSON(w, evidenceList, http.StatusOK)
}

// getInvestigationEvidence retrieves metadata for a specific evidence file
// @Summary Get investigation evidence metadata
// @Description Get metadata for a specific evidence file attached to an investigation
// @Tags evidence,investigations
// @Produce json
// @Param id path string true "Investigation ID (format: INV-YYYYMMDD-XXXX)"
// @Param evidence_id path string true "Evidence ID (UUID)"
// @Success 200 {object} core.Evidence
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/investigations/{id}/evidence/{evidence_id} [get]
func (a *API) getInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	investigationID := vars["id"]
	evidenceID := vars["evidence_id"]

	// Validate IDs
	if err := validateInvestigationID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", err, a.logger)
		return
	}
	if err := validateUUID(evidenceID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid evidence ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Get evidence metadata
	evidence, err := a.evidenceStorage.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Evidence not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get evidence", err, a.logger)
		return
	}

	// Verify evidence belongs to the investigation
	if evidence.InvestigationID != investigationID {
		writeError(w, http.StatusNotFound, "Evidence not found for this investigation", nil, a.logger)
		return
	}

	// Enrich with user reference
	a.enrichEvidenceWithUserRef(r.Context(), evidence)

	a.respondJSON(w, evidence, http.StatusOK)
}

// downloadInvestigationEvidence downloads a specific evidence file with integrity verification
// @Summary Download investigation evidence
// @Description Download a specific evidence file attached to an investigation
// @Tags evidence,investigations
// @Produce application/octet-stream
// @Param id path string true "Investigation ID (format: INV-YYYYMMDD-XXXX)"
// @Param evidence_id path string true "Evidence ID (UUID)"
// @Success 200 {file} binary
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/investigations/{id}/evidence/{evidence_id}/download [get]
func (a *API) downloadInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	investigationID := vars["id"]
	evidenceID := vars["evidence_id"]

	// Validate IDs
	if err := validateInvestigationID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", err, a.logger)
		return
	}
	if err := validateUUID(evidenceID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid evidence ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}

	// Get evidence metadata
	evidence, err := a.evidenceStorage.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Evidence not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get evidence", err, a.logger)
		return
	}

	// Verify evidence belongs to the investigation
	if evidence.InvestigationID != investigationID {
		writeError(w, http.StatusNotFound, "Evidence not found for this investigation", nil, a.logger)
		return
	}

	// Open file (stored under investigations subdirectory)
	filePath := filepath.Join(evidenceBasePath, "investigations", investigationID, evidence.Filename)
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "Evidence file not found on disk", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to open evidence file", err, a.logger)
		return
	}
	defer file.Close()

	// Verify file integrity using SHA-256 hash
	if evidence.Hash != "" {
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to verify file integrity", err, a.logger)
			return
		}
		computedHash := hex.EncodeToString(hash.Sum(nil))
		if computedHash != evidence.Hash {
			a.logger.Errorw("Evidence file integrity check failed",
				"evidence_id", evidenceID,
				"investigation_id", investigationID,
				"expected_hash", evidence.Hash,
				"computed_hash", computedHash,
			)
			writeError(w, http.StatusInternalServerError, "Evidence file integrity check failed", nil, a.logger)
			return
		}
		// Seek back to beginning for download
		if _, err := file.Seek(0, 0); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to read file", err, a.logger)
			return
		}
	}

	// Audit log the download
	username := r.Header.Get("X-Username")
	a.logger.Infow("Investigation evidence downloaded",
		"evidence_id", evidenceID,
		"investigation_id", investigationID,
		"filename", evidence.Name,
		"downloaded_by", username,
	)

	// Set headers for download
	w.Header().Set("Content-Type", evidence.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", evidence.Name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", evidence.Size))
	w.Header().Set("X-Content-SHA256", evidence.Hash)

	// Stream file to response
	io.Copy(w, file)
}

// deleteInvestigationEvidence removes an evidence file from an investigation
// @Summary Delete investigation evidence
// @Description Delete an evidence file from an investigation
// @Tags evidence,investigations
// @Produce json
// @Param id path string true "Investigation ID (format: INV-YYYYMMDD-XXXX)"
// @Param evidence_id path string true "Evidence ID (UUID)"
// @Success 204 "No content"
// @Failure 400 {object} ErrorResponse "Bad request"
// @Failure 403 {object} ErrorResponse "Investigation is closed"
// @Failure 404 {object} ErrorResponse "Evidence not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/investigations/{id}/evidence/{evidence_id} [delete]
func (a *API) deleteInvestigationEvidence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	investigationID := vars["id"]
	evidenceID := vars["evidence_id"]

	// Validate IDs
	if err := validateInvestigationID(investigationID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid investigation ID format", err, a.logger)
		return
	}
	if err := validateUUID(evidenceID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid evidence ID format", err, a.logger)
		return
	}

	if a.evidenceStorage == nil {
		writeError(w, http.StatusInternalServerError, "Evidence storage not available", nil, a.logger)
		return
	}
	if a.investigationStorage == nil {
		writeError(w, http.StatusInternalServerError, "Investigation storage not available", nil, a.logger)
		return
	}

	// Verify investigation exists and is not closed
	investigation, err := a.investigationStorage.GetInvestigation(investigationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Investigation not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to verify investigation", err, a.logger)
		return
	}

	// Check if investigation is closed (cannot delete evidence from closed investigations)
	if investigation.Status == core.InvestigationStatusClosed ||
		investigation.Status == core.InvestigationStatusResolved ||
		investigation.Status == core.InvestigationStatusFalsePositive {
		writeError(w, http.StatusForbidden, "Cannot delete evidence from a closed investigation", nil, a.logger)
		return
	}

	// Get evidence to verify ownership and get filename
	evidence, err := a.evidenceStorage.GetEvidence(r.Context(), evidenceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Evidence not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get evidence", err, a.logger)
		return
	}

	// Verify evidence belongs to the investigation
	if evidence.InvestigationID != investigationID {
		writeError(w, http.StatusNotFound, "Evidence not found for this investigation", nil, a.logger)
		return
	}

	// Delete file from disk
	filePath := filepath.Join(evidenceBasePath, "investigations", investigationID, evidence.Filename)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		a.logger.Warnw("Failed to delete evidence file from disk", "path", filePath, "error", err)
		// Continue with metadata deletion even if file deletion fails
	}

	// Delete metadata
	if err := a.evidenceStorage.DeleteEvidence(r.Context(), evidenceID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete evidence", err, a.logger)
		return
	}

	// Audit logging
	username := r.Header.Get("X-Username")
	a.logger.Infow("Investigation evidence deleted",
		"evidence_id", evidenceID,
		"investigation_id", investigationID,
		"filename", evidence.Name,
		"deleted_by", username,
	)

	w.WriteHeader(http.StatusNoContent)
}
