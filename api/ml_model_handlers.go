package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"cerberus/storage"

	"github.com/gorilla/mux"
)

// getMLModels godoc
//
//	@Summary		List ML models
//	@Description	Returns a list of all ML models with their metadata
//	@Tags			ml-models
//	@Produce		json
//	@Param			name	query		string	false	"Filter by model name"
//	@Param			status	query		string	false	"Filter by status (active, retired, training)"
//	@Param			algorithm	query	string	false	"Filter by algorithm"
//	@Success		200			{array}		storage.ModelMetadata
//	@Failure		500			{object}	map[string]string
//	@Router			/api/v1/ml/models [get]
func (a *API) getMLModels(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: List ML models endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// Get query parameters
	name := r.URL.Query().Get("name")
	status := r.URL.Query().Get("status")
	algorithm := r.URL.Query().Get("algorithm")

	var models []storage.ModelMetadata
	var err error

	if name != "" {
		// Get all versions of a specific model
		models, err = a.mlModelStorage.GetModelVersions(ctx, name)
	} else if status == "active" {
		if algorithm != "" {
			// Get active models by algorithm
			models, err = a.mlModelStorage.GetActiveModelsByAlgorithm(ctx, algorithm)
		} else {
			// Get all active models
			models, err = a.mlModelStorage.GetActiveModels(ctx)
		}
	} else {
		// Get all models (would need a new method, for now return active)
		models, err = a.mlModelStorage.GetActiveModels(ctx)
	}

	if err != nil {
		a.logger.Errorw("Failed to get ML models", "error", err)
		a.respondJSON(w, map[string]string{"error": "Failed to retrieve models"}, http.StatusInternalServerError)
		return
	}

	// Filter by status if specified and not already filtered
	if status != "" && status != "active" {
		filtered := []storage.ModelMetadata{}
		for _, model := range models {
			if model.Status == status {
				filtered = append(filtered, model)
			}
		}
		models = filtered
	}

	a.respondJSON(w, models, http.StatusOK)
}

// getMLModel godoc
//
//	@Summary		Get ML model
//	@Description	Returns metadata for a specific ML model version
//	@Tags			ml-models
//	@Produce		json
//	@Param			name	path		string	true	"Model name"
//	@Param			version	path		string	true	"Model version"
//	@Success		200		{object}	storage.ModelMetadata
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/ml/models/{name}/{version} [get]
func (a *API) getMLModel(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: Get specific ML model endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	version := vars["version"]

	if name == "" || version == "" {
		a.respondJSON(w, map[string]string{"error": "Model name and version are required"}, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Get all versions and find the specific one
	versions, err := a.mlModelStorage.GetModelVersions(ctx, name)
	if err != nil {
		a.logger.Errorw("Failed to get model versions", "error", err, "name", name)
		a.respondJSON(w, map[string]string{"error": "Failed to retrieve model"}, http.StatusInternalServerError)
		return
	}

	// Find the specific version
	for _, model := range versions {
		if model.Version == version {
			a.respondJSON(w, model, http.StatusOK)
			return
		}
	}

	a.respondJSON(w, map[string]string{"error": "Model not found"}, http.StatusNotFound)
}

// activateMLModel godoc
//
//	@Summary		Activate ML model
//	@Description	Activates a specific model version and retires previous active versions
//	@Tags			ml-models
//	@Produce		json
//	@Param			name	path		string	true	"Model name"
//	@Param			version	path		string	true	"Model version"
//	@Success		200		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/ml/models/{name}/{version}/activate [post]
func (a *API) activateMLModel(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: Activate ML model endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	version := vars["version"]

	if name == "" || version == "" {
		a.respondJSON(w, map[string]string{"error": "Model name and version are required"}, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if err := a.mlModelStorage.ActivateModel(ctx, name, version); err != nil {
		a.logger.Errorw("Failed to activate model", "error", err, "name", name, "version", version)
		a.respondJSON(w, map[string]string{"error": "Failed to activate model: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Model activated successfully"}, http.StatusOK)
}

// rollbackMLModel godoc
//
//	@Summary		Rollback ML model
//	@Description	Rolls back to a previous model version
//	@Tags			ml-models
//	@Produce		json
//	@Param			name	path		string	true	"Model name"
//	@Param			version	path		string	true	"Target version to rollback to"
//	@Success		200		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/ml/models/{name}/{version}/rollback [post]
func (a *API) rollbackMLModel(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: Rollback ML model endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	version := vars["version"]

	if name == "" || version == "" {
		a.respondJSON(w, map[string]string{"error": "Model name and version are required"}, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if err := a.mlModelStorage.RollbackModel(ctx, name, version); err != nil {
		a.logger.Errorw("Failed to rollback model", "error", err, "name", name, "version", version)
		status := http.StatusInternalServerError
		if err.Error() == "model "+name+" v"+version+" not found" {
			status = http.StatusNotFound
		}
		a.respondJSON(w, map[string]string{"error": "Failed to rollback model: " + err.Error()}, status)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Model rolled back successfully"}, http.StatusOK)
}

// pruneMLModelVersions godoc
//
//	@Summary		Prune ML model versions
//	@Description	Retires old model versions, keeping only the specified number of recent versions
//	@Tags			ml-models
//	@Produce		json
//	@Param			name			path		string	true	"Model name"
//	@Param			keep_versions	query		int		true	"Number of versions to keep"
//	@Success		200				{object}	map[string]string
//	@Failure		400				{object}	map[string]string
//	@Failure		500				{object}	map[string]string
//	@Router			/api/v1/ml/models/{name}/prune [post]
func (a *API) pruneMLModelVersions(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: Prune ML model versions endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	if name == "" {
		a.respondJSON(w, map[string]string{"error": "Model name is required"}, http.StatusBadRequest)
		return
	}

	keepVersionsStr := r.URL.Query().Get("keep_versions")
	if keepVersionsStr == "" {
		keepVersionsStr = "3" // Default: keep last 3 versions
	}

	keepVersions, err := strconv.Atoi(keepVersionsStr)
	if err != nil || keepVersions < 1 {
		a.respondJSON(w, map[string]string{"error": "keep_versions must be a positive integer"}, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if err := a.mlModelStorage.PruneOldVersions(ctx, name, keepVersions); err != nil {
		a.logger.Errorw("Failed to prune model versions", "error", err, "name", name)
		a.respondJSON(w, map[string]string{"error": "Failed to prune versions: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Model versions pruned successfully"}, http.StatusOK)
}

// updateMLModelStatus godoc
//
//	@Summary		Update ML model status
//	@Description	Updates the status of a model version
//	@Tags			ml-models
//	@Accept			json
//	@Produce		json
//	@Param			name	path		string	true	"Model name"
//	@Param			version	path		string	true	"Model version"
//	@Param			status	body		map[string]string	true	"Status object with 'status' field"
//	@Success		200		{object}	map[string]string
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/ml/models/{name}/{version}/status [put]
func (a *API) updateMLModelStatus(w http.ResponseWriter, r *http.Request) {
	// TASK 37.5: Update ML model status endpoint
	if a.mlModelStorage == nil {
		a.respondJSON(w, map[string]string{"error": "ML model storage not initialized"}, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	version := vars["version"]

	if name == "" || version == "" {
		a.respondJSON(w, map[string]string{"error": "Model name and version are required"}, http.StatusBadRequest)
		return
	}

	var req struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondJSON(w, map[string]string{"error": "Invalid request body"}, http.StatusBadRequest)
		return
	}

	if req.Status == "" {
		a.respondJSON(w, map[string]string{"error": "Status is required"}, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if err := a.mlModelStorage.UpdateModelStatus(ctx, name, version, req.Status); err != nil {
		a.logger.Errorw("Failed to update model status", "error", err, "name", name, "version", version)
		status := http.StatusInternalServerError
		if err.Error() == "model "+name+" v"+version+" not found" {
			status = http.StatusNotFound
		}
		a.respondJSON(w, map[string]string{"error": "Failed to update status: " + err.Error()}, status)
		return
	}

	a.respondJSON(w, map[string]string{"message": "Model status updated successfully"}, http.StatusOK)
}
