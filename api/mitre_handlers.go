package api

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"cerberus/mitre"

	"github.com/gorilla/mux"
)

// importMITREBundle godoc
//
//	@Summary		Import MITRE ATT&CK STIX bundle
//	@Description	Imports techniques, sub-techniques, tactics, and data sources from a STIX bundle file
//	@Tags			mitre
//	@Accept			multipart/form-data
//	@Produce		json
//	@Param			file	formData	file	true	"STIX bundle JSON file"
//	@Success		200		{object}	map[string]interface{}	"Import result"
//	@Failure		400		{string}	string	"Bad Request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/api/v1/mitre/import [post]
//	TASK 9.6: MITRE import endpoint
func (a *API) importMITREBundle(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		writeError(w, http.StatusNotImplemented, "MITRE storage not available", nil, a.logger)
		return
	}

	// Parse multipart form (32MB max)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "Failed to parse form", err, a.logger)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "No file uploaded", err, a.logger)
		return
	}
	defer file.Close()

	// Save uploaded file to temp location
	tmpFile, err := a.saveUploadedFile(file, header.Filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save uploaded file", err, a.logger)
		return
	}
	defer a.cleanupTempFile(tmpFile)

	// Import using STIX importer
	importer := mitre.NewSTIXImporter(a.mitreStorage, a.logger)
	result, err := importer.ImportBundle(tmpFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to import bundle", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"message":               "Bundle imported successfully",
		"techniques_imported":   result.TechniquesImported,
		"tactics_imported":      result.TacticsImported,
		"data_sources_imported": result.DataSourcesImported,
		"errors":                result.Errors,
	}, http.StatusOK)
}

// updateMITREBundle godoc
//
//	@Summary		Update MITRE ATT&CK data from latest bundle
//	@Description	Downloads and imports the latest MITRE ATT&CK STIX bundle from GitHub
//	@Tags			mitre
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Import result"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/mitre/update [post]
//	TASK 9.6: MITRE update endpoint
func (a *API) updateMITREBundle(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		writeError(w, http.StatusNotImplemented, "MITRE storage not available", nil, a.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute) // Long timeout for download
	defer cancel()

	// Import latest using STIX importer
	importer := mitre.NewSTIXImporter(a.mitreStorage, a.logger)
	result, err := importer.ImportLatest(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to import latest bundle", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"message":               "Latest bundle imported successfully",
		"techniques_imported":   result.TechniquesImported,
		"tactics_imported":      result.TacticsImported,
		"data_sources_imported": result.DataSourcesImported,
		"errors":                result.Errors,
	}, http.StatusOK)
}

// getSubTechniques godoc
//
//	@Summary		Get sub-techniques for a parent technique
//	@Description	Returns all sub-techniques for a given parent technique ID
//	@Tags			mitre
//	@Produce		json
//	@Param			id	path		string	true	"Parent technique ID (e.g., T1055)"
//	@Success		200	{array}		mitre.Technique	"Sub-techniques"
//	@Failure		400	{string}	string	"Invalid technique ID"
//	@Failure		404	{string}	string	"Technique not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/mitre/techniques/{id}/subtechniques [get]
//	TASK 9.6: Sub-techniques endpoint
func (a *API) getSubTechniques(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		writeError(w, http.StatusNotImplemented, "MITRE storage not available", nil, a.logger)
		return
	}

	vars := mux.Vars(r)
	techniqueID := vars["id"]

	if techniqueID == "" {
		writeError(w, http.StatusBadRequest, "Technique ID required", nil, a.logger)
		return
	}

	subTechniques, err := a.mitreStorage.GetSubTechniques(techniqueID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get sub-techniques", err, a.logger)
		return
	}

	a.respondJSON(w, subTechniques, http.StatusOK)
}

// getDataSources godoc
//
//	@Summary		Get all MITRE ATT&CK data sources
//	@Description	Returns all data sources from the MITRE ATT&CK framework
//	@Tags			mitre
//	@Produce		json
//	@Success		200	{array}		mitre.DataSource	"Data sources"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/mitre/data-sources [get]
//	TASK 9.6: Data sources endpoint
func (a *API) getDataSources(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		writeError(w, http.StatusNotImplemented, "MITRE storage not available", nil, a.logger)
		return
	}

	dataSources, err := a.mitreStorage.GetDataSources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get data sources", err, a.logger)
		return
	}

	a.respondJSON(w, dataSources, http.StatusOK)
}

// getDataSourceCoverage godoc
//
//	@Summary		Get coverage by data source
//	@Description	Returns coverage statistics grouped by data source
//	@Tags			mitre
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Data source coverage"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/api/v1/mitre/coverage/data-sources [get]
//	TASK 9.6: Data source coverage endpoint
func (a *API) getDataSourceCoverage(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		writeError(w, http.StatusNotImplemented, "MITRE storage not available", nil, a.logger)
		return
	}

	// Get all data sources
	dataSources, err := a.mitreStorage.GetDataSources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get data sources", err, a.logger)
		return
	}

	// Get all techniques with their coverage
	allTechniques, err := a.mitreStorage.GetTechniques(10000, 0, "") // Get all techniques
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get techniques", err, a.logger)
		return
	}

	// Get covered techniques from rules
	coveredTechniques := make(map[string]bool)
	rules, err := a.ruleStorage.GetAllRules()
	if err == nil {
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			for _, techID := range rule.MitreTechniques {
				coveredTechniques[techID] = true
				// Also mark sub-techniques if the rule covers a parent
				subTechs, err := a.mitreStorage.GetSubTechniques(techID)
				if err == nil {
					for _, subTech := range subTechs {
						coveredTechniques[subTech.GetTechniqueID()] = true
					}
				}
			}
		}
	}

	// Build data source coverage map
	coverage := make(map[string]map[string]interface{})
	for _, ds := range dataSources {
		totalTechniques := 0
		coveredTechniquesCount := 0

		// Count techniques that use this data source
		for _, tech := range allTechniques {
			for _, dsName := range tech.DataSources {
				if dsName == ds.Name {
					totalTechniques++
					if coveredTechniques[tech.GetTechniqueID()] {
						coveredTechniquesCount++
					}
					// Also check sub-techniques
					if tech.IsSubTechnique() {
						continue // Skip sub-techniques in main count
					}
					subTechs, err := a.mitreStorage.GetSubTechniques(tech.GetTechniqueID())
					if err == nil {
						for _, subTech := range subTechs {
							totalTechniques++
							if coveredTechniques[subTech.GetTechniqueID()] {
								coveredTechniquesCount++
							}
						}
					}
				}
			}
		}

		coveragePercent := 0.0
		if totalTechniques > 0 {
			coveragePercent = (float64(coveredTechniquesCount) / float64(totalTechniques)) * 100
		}

		coverage[ds.ID] = map[string]interface{}{
			"id":                 ds.ID,
			"name":               ds.Name,
			"total_techniques":   totalTechniques,
			"covered_techniques": coveredTechniquesCount,
			"coverage_percent":   coveragePercent,
			"description":        ds.Description,
			"collection_layers":  ds.CollectionLayers,
		}
	}

	a.respondJSON(w, map[string]interface{}{
		"data_source_coverage": coverage,
		"last_updated":         time.Now().UTC().Format(time.RFC3339),
	}, http.StatusOK)
}

// Helper functions for file upload handling
func (a *API) saveUploadedFile(file multipart.File, _ string) (string, error) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "mitre-import-*.json")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()

	// Copy uploaded file to temp file
	_, err = io.Copy(tmpFile, file)
	tmpFile.Close()

	if err != nil {
		os.Remove(tmpPath)
		return "", err
	}

	return tmpPath, nil
}

func (a *API) cleanupTempFile(path string) {
	if err := os.Remove(path); err != nil {
		a.logger.Warnf("Failed to remove temp file %s: %v", path, err)
	}
}

// getTactics godoc
//
//	@Summary		Get MITRE ATT&CK tactics
//	@Description	Returns all MITRE ATT&CK tactics
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		mitre.Tactic
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"MITRE storage not available"
//	@Router			/api/v1/mitre/tactics [get]
func (a *API) getTactics(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		http.Error(w, "MITRE storage not available", http.StatusServiceUnavailable)
		return
	}

	tactics, err := a.mitreStorage.GetTactics()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get tactics", err, a.logger)
		return
	}

	a.respondJSON(w, tactics, http.StatusOK)
}

// getTactic godoc
//
//	@Summary		Get MITRE ATT&CK tactic by ID
//	@Description	Returns a single MITRE ATT&CK tactic
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Tactic ID"
//	@Success		200	{object}	mitre.Tactic
//	@Failure		404	{string}	string	"Tactic not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"MITRE storage not available"
//	@Router			/api/v1/mitre/tactics/{id} [get]
func (a *API) getTactic(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		http.Error(w, "MITRE storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	tactic, err := a.mitreStorage.GetTactic(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Tactic not found", err, a.logger)
		return
	}

	a.respondJSON(w, tactic, http.StatusOK)
}

// getTechniques godoc
//
//	@Summary		Get MITRE ATT&CK techniques
//	@Description	Returns MITRE ATT&CK techniques with pagination
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Param			page	query		int		false	"Page number (default: 1)"
//	@Param			limit	query		int		false	"Items per page (default: 50)"
//	@Param			tacticId	query	string	false	"Filter by tactic ID"
//	@Success		200	{object}	map[string]interface{}	"Paginated techniques"
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"MITRE storage not available"
//	@Router			/api/v1/mitre/techniques [get]
func (a *API) getTechniques(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		http.Error(w, "MITRE storage not available", http.StatusServiceUnavailable)
		return
	}

	// Parse pagination parameters
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	tacticID := r.URL.Query().Get("tacticId")
	offset := (page - 1) * limit

	techniques, err := a.mitreStorage.GetTechniques(limit, offset, tacticID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get techniques", err, a.logger)
		return
	}

	// Get total count
	total, err := a.mitreStorage.GetTechniqueCount()
	if err != nil {
		a.logger.Warnw("Failed to get technique count", "error", err)
		total = int64(len(techniques))
	}

	// Calculate total pages
	totalPages := (int(total) + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	response := map[string]interface{}{
		"items":       techniques,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getTechnique godoc
//
//	@Summary		Get MITRE ATT&CK technique by ID
//	@Description	Returns a single MITRE ATT&CK technique
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Technique ID"
//	@Success		200	{object}	mitre.Technique
//	@Failure		404	{string}	string	"Technique not found"
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"MITRE storage not available"
//	@Router			/api/v1/mitre/techniques/{id} [get]
func (a *API) getTechnique(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		http.Error(w, "MITRE storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	technique, err := a.mitreStorage.GetTechnique(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Technique not found", err, a.logger)
		return
	}

	a.respondJSON(w, technique, http.StatusOK)
}

// getMITREStatistics godoc
//
//	@Summary		Get MITRE ATT&CK statistics
//	@Description	Returns statistics about MITRE ATT&CK framework coverage
//	@Tags			mitre
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		500	{string}	string	"Internal server error"
//	@Failure		503	{string}	string	"MITRE storage not available"
//	@Router			/api/v1/mitre/statistics [get]
func (a *API) getMITREStatistics(w http.ResponseWriter, r *http.Request) {
	if a.mitreStorage == nil {
		http.Error(w, "MITRE storage not available", http.StatusServiceUnavailable)
		return
	}

	tactics, err := a.mitreStorage.GetTactics()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get tactics", err, a.logger)
		return
	}

	techniqueCount, err := a.mitreStorage.GetTechniqueCount()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get technique count", err, a.logger)
		return
	}

	tacticCoverage, err := a.mitreStorage.GetTacticCoverage()
	if err != nil {
		a.logger.Warnw("Failed to get tactic coverage", "error", err)
		tacticCoverage = []mitre.TacticCoverage{}
	}

	techniqueCoverage, err := a.mitreStorage.GetTechniqueCoverage()
	if err != nil {
		a.logger.Warnw("Failed to get technique coverage", "error", err)
		techniqueCoverage = []mitre.TechniqueCoverage{}
	}

	// Calculate coverage percentages
	coveredTechniques := 0
	for _, tc := range techniqueCoverage {
		if tc.TotalRules > 0 {
			coveredTechniques++
		}
	}

	coveragePercentage := 0.0
	if techniqueCount > 0 {
		coveragePercentage = float64(coveredTechniques) / float64(techniqueCount) * 100
	}

	stats := map[string]interface{}{
		"totalTactics":       len(tactics),
		"totalTechniques":    techniqueCount,
		"coveredTechniques":  coveredTechniques,
		"coveragePercentage": coveragePercentage,
		"tacticCoverage":     tacticCoverage,
		"techniqueCoverage":  techniqueCoverage,
	}

	a.respondJSON(w, stats, http.StatusOK)
}
