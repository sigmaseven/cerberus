package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

// MLModelStorage handles ML model persistence
// TASK 26.2: Model storage layer for SQLite
type MLModelStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewMLModelStorage creates a new ML model storage
func NewMLModelStorage(db *SQLite, logger *zap.SugaredLogger) *MLModelStorage {
	return &MLModelStorage{
		db:     db,
		logger: logger,
	}
}

// ModelMetadata contains metadata for a stored model
// TASK 26.2: Model metadata structure
// TASK 37: Enhanced with status, file_path, and lifecycle tracking
type ModelMetadata struct {
	Name                string
	Version             string
	ModelType           string
	Algorithm           string // TASK 37: zscore, iqr, isolation_forest
	Status              string // TASK 37: active, retired, training
	FilePath            string // TASK 37: Path to serialized model file (optional)
	TrainedAt           time.Time
	TrainingStartedAt   *time.Time // TASK 37: When training began
	TrainingCompletedAt *time.Time // TASK 37: When training finished
	TrainingSamples     *int       // TASK 37: Number of samples used for training
	Hyperparameters     string     // TASK 37: JSON hyperparameters
	Metrics             string     // JSON string (performance metrics: precision, recall, F1)
	CreatedAt           time.Time  // TASK 37: Creation timestamp
}

// SaveModel saves a model to the database
// TASK 26.2: Persist model with version, type, data, and metrics
// TASK 37: Enhanced to support file_path, status, and lifecycle tracking
func (mms *MLModelStorage) SaveModel(ctx context.Context, name, version, modelType string, modelData []byte, config string, metrics string) error {
	if len(modelData) == 0 {
		return fmt.Errorf("model data cannot be empty")
	}
	// Use SaveModelWithMetadata with default values for backwards compatibility
	return mms.SaveModelWithMetadata(ctx, name, version, modelType, "", modelData, config, metrics, "", "training", nil, nil, nil, "")
}

// SaveModelWithMetadata saves a model with enhanced metadata (TASK 37)
// Supports both BLOB storage (modelData) and file-based storage (filePath)
func (mms *MLModelStorage) SaveModelWithMetadata(ctx context.Context, name, version, modelType, algorithm string, modelData []byte, config, metrics, filePath, status string, trainingStartedAt, trainingCompletedAt *time.Time, trainingSamples *int, hyperparameters string) error {
	if name == "" {
		return fmt.Errorf("model name cannot be empty")
	}
	if version == "" {
		return fmt.Errorf("model version cannot be empty")
	}
	if modelType == "" {
		return fmt.Errorf("model type cannot be empty")
	}
	if len(modelData) == 0 && filePath == "" {
		return fmt.Errorf("model data or file_path must be provided")
	}

	// TASK 37: Determine algorithm from modelType if not provided
	if algorithm == "" {
		algorithm = modelType // Use modelType as fallback
	}

	// TASK 37: Default status if not provided
	if status == "" {
		status = "training"
	}

	query := `
		INSERT INTO ml_models (name, version, model_type, algorithm, model_data, file_path, status, config, 
		                       trained_at, training_started_at, training_completed_at, training_samples, 
		                       hyperparameters, metrics, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	trainedAt := time.Now().UTC()
	now := time.Now().UTC()

	// Handle nullable fields
	var modelDataPtr interface{}
	if len(modelData) > 0 {
		modelDataPtr = modelData
	}

	var filePathPtr interface{}
	if filePath != "" {
		filePathPtr = filePath
	}

	var trainingStartedPtr, trainingCompletedPtr interface{}
	if trainingStartedAt != nil {
		trainingStartedPtr = trainingStartedAt.Format(time.RFC3339)
	}
	if trainingCompletedAt != nil {
		trainingCompletedPtr = trainingCompletedAt.Format(time.RFC3339)
	}

	var trainingSamplesPtr interface{}
	if trainingSamples != nil {
		trainingSamplesPtr = *trainingSamples
	}

	var hyperparamsPtr interface{}
	if hyperparameters != "" {
		hyperparamsPtr = hyperparameters
	}

	_, err := mms.db.DB.ExecContext(ctx, query,
		name,
		version,
		modelType,
		algorithm,
		modelDataPtr,
		filePathPtr,
		status,
		config,
		trainedAt.Format(time.RFC3339),
		trainingStartedPtr,
		trainingCompletedPtr,
		trainingSamplesPtr,
		hyperparamsPtr,
		metrics,
		now.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to save model: %w", err)
	}

	mms.logger.Infof("Saved ML model: %s v%s (%s, status: %s)", name, version, modelType, status)
	return nil
}

// LoadModel loads a specific model version from the database
// TASK 26.2: Retrieve model by name and version
// TASK 37: Enhanced to support file_path loading
func (mms *MLModelStorage) LoadModel(ctx context.Context, name, version string) (string, []byte, error) {
	query := `
		SELECT model_type, model_data, file_path
		FROM ml_models
		WHERE name = ? AND version = ?
	`

	var modelType string
	var modelData []byte
	var filePath sql.NullString

	err := mms.db.ReadDB.QueryRowContext(ctx, query, name, version).Scan(&modelType, &modelData, &filePath)
	if err == sql.ErrNoRows {
		return "", nil, fmt.Errorf("model %s v%s not found", name, version)
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to load model: %w", err)
	}

	// TASK 37: If model_data is empty but file_path is provided, load from file
	if len(modelData) == 0 && filePath.Valid && filePath.String != "" {
		fileData, err := os.ReadFile(filePath.String)
		if err != nil {
			return "", nil, fmt.Errorf("failed to load model from file %s: %w", filePath.String, err)
		}
		modelData = fileData
	}

	return modelType, modelData, nil
}

// LoadLatestModel loads the latest version of a model
// TASK 26.2: Retrieve latest version by name
func (mms *MLModelStorage) LoadLatestModel(ctx context.Context, name string) (string, string, []byte, error) {
	// Get all versions for this model
	versions, err := mms.ListVersions(ctx, name)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to list versions: %w", err)
	}

	if len(versions) == 0 {
		return "", "", nil, fmt.Errorf("no versions found for model %s", name)
	}

	// Sort versions to get latest (handled by ListVersions)
	latestVersion := versions[0] // ListVersions returns sorted (newest first)

	modelType, modelData, err := mms.LoadModel(ctx, name, latestVersion)
	if err != nil {
		return "", "", nil, err
	}

	return latestVersion, modelType, modelData, nil
}

// GetLatestVersion returns the latest version string for a model (implements ModelStorage interface)
// TASK 26.3: For versioning interface
// Uses a 30-second timeout context for the database query
func (mms *MLModelStorage) GetLatestVersion(modelName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	versions, err := mms.ListVersions(ctx, modelName)
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions found for model %s", modelName)
	}
	return versions[0], nil // ListVersions returns sorted (newest first)
}

// ListVersions lists all versions of a model ordered by version (newest first)
// TASK 26.2: List all versions for a model
func (mms *MLModelStorage) ListVersions(ctx context.Context, name string) ([]string, error) {
	query := `
		SELECT version
		FROM ml_models
		WHERE name = ?
		ORDER BY 
			CAST(SUBSTR(version, 1, INSTR(version || '.', '.') - 1) AS INTEGER) DESC,
			CAST(SUBSTR(SUBSTR(version, INSTR(version, '.') + 1), 1, INSTR(SUBSTR(version, INSTR(version, '.') + 1) || '.', '.') - 1) AS INTEGER) DESC,
			CAST(SUBSTR(version, INSTR(version || '.', '.', INSTR(version || '.', '.') + 1) + 1) AS INTEGER) DESC
	`

	rows, err := mms.db.ReadDB.QueryContext(ctx, query, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query versions: %w", err)
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}
		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating versions: %w", err)
	}

	return versions, nil
}

// ListModels lists all models with their metadata
// TASK 26.2: List all models with metadata
func (mms *MLModelStorage) ListModels(ctx context.Context, name string) ([]ModelMetadata, error) {
	query := `
		SELECT name, version, model_type, trained_at, metrics
		FROM ml_models
		WHERE name = ?
		ORDER BY trained_at DESC
	`

	rows, err := mms.db.ReadDB.QueryContext(ctx, query, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query models: %w", err)
	}
	defer rows.Close()

	var models []ModelMetadata
	for rows.Next() {
		var model ModelMetadata
		var trainedAtStr string
		var metricsJSON sql.NullString

		err := rows.Scan(
			&model.Name,
			&model.Version,
			&model.ModelType,
			&trainedAtStr,
			&metricsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan model: %w", err)
		}

		model.TrainedAt, _ = time.Parse(time.RFC3339, trainedAtStr)
		if metricsJSON.Valid {
			model.Metrics = metricsJSON.String
		}

		models = append(models, model)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating models: %w", err)
	}

	return models, nil
}

// DeployModel activates a specific model version for deployment
// TASK 26.5: Deploy model version and deactivate previous deployments
func (mms *MLModelStorage) DeployModel(ctx context.Context, name, version, deployedBy string) error {
	return mms.db.WithTransaction(func(tx *sql.Tx) error {
		// First, deactivate all existing deployments for this model
		deactivateQuery := `
			UPDATE ml_model_deployments
			SET is_active = 0
			WHERE model_name = ? AND is_active = 1
		`
		_, err := tx.ExecContext(ctx, deactivateQuery, name)
		if err != nil {
			return fmt.Errorf("failed to deactivate previous deployments: %w", err)
		}

		// Insert new deployment record
		deployQuery := `
			INSERT INTO ml_model_deployments (model_name, model_version, deployed_at, deployed_by, is_active)
			VALUES (?, ?, ?, ?, 1)
		`
		_, err = tx.ExecContext(ctx, deployQuery,
			name,
			version,
			time.Now().UTC().Format(time.RFC3339),
			deployedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to deploy model: %w", err)
		}

		mms.logger.Infof("Deployed ML model: %s v%s (deployed by: %s)", name, version, deployedBy)
		return nil
	})
}

// GetActiveModel retrieves the currently active (deployed) model
// TASK 26.5: Get active model version via deployment table join
func (mms *MLModelStorage) GetActiveModel(ctx context.Context, name string) (string, string, []byte, error) {
	query := `
		SELECT m.model_version, m.model_type, m.model_data
		FROM ml_models m
		INNER JOIN ml_model_deployments d ON m.name = d.model_name AND m.version = d.model_version
		WHERE m.name = ? AND d.is_active = 1
		ORDER BY d.deployed_at DESC
		LIMIT 1
	`

	var version string
	var modelType string
	var modelData []byte

	err := mms.db.ReadDB.QueryRowContext(ctx, query, name).Scan(&version, &modelType, &modelData)
	if err == sql.ErrNoRows {
		return "", "", nil, fmt.Errorf("no active deployment found for model %s", name)
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get active model: %w", err)
	}

	return version, modelType, modelData, nil
}

// GetDeploymentHistory retrieves deployment history for a model
// TASK 26.5: Get deployment history ordered by deployed_at
func (mms *MLModelStorage) GetDeploymentHistory(ctx context.Context, name string, limit int) ([]DeploymentRecord, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}

	query := `
		SELECT model_name, model_version, deployed_at, deployed_by, is_active
		FROM ml_model_deployments
		WHERE model_name = ?
		ORDER BY deployed_at DESC
		LIMIT ?
	`

	rows, err := mms.db.ReadDB.QueryContext(ctx, query, name, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query deployment history: %w", err)
	}
	defer rows.Close()

	var records []DeploymentRecord
	for rows.Next() {
		var record DeploymentRecord
		var deployedAtStr string
		var deployedBy sql.NullString

		err := rows.Scan(
			&record.ModelName,
			&record.ModelVersion,
			&deployedAtStr,
			&deployedBy,
			&record.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan deployment record: %w", err)
		}

		record.DeployedAt, _ = time.Parse(time.RFC3339, deployedAtStr)
		if deployedBy.Valid {
			record.DeployedBy = deployedBy.String
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating deployment records: %w", err)
	}

	return records, nil
}

// DeploymentRecord represents a model deployment record
// TASK 26.5: Deployment tracking structure
type DeploymentRecord struct {
	ModelName    string
	ModelVersion string
	DeployedAt   time.Time
	DeployedBy   string
	IsActive     bool
}

// GetActiveModels returns all models with status='active' (TASK 37)
func (mms *MLModelStorage) GetActiveModels(ctx context.Context) ([]ModelMetadata, error) {
	query := `
		SELECT name, version, model_type, algorithm, status, file_path, trained_at, 
		       training_started_at, training_completed_at, training_samples, 
		       hyperparameters, metrics, created_at
		FROM ml_models
		WHERE status = 'active'
		ORDER BY name, created_at DESC
	`

	return mms.queryModels(ctx, query)
}

// GetActiveModelsByAlgorithm returns active models filtered by algorithm (TASK 37)
func (mms *MLModelStorage) GetActiveModelsByAlgorithm(ctx context.Context, algorithm string) ([]ModelMetadata, error) {
	query := `
		SELECT name, version, model_type, algorithm, status, file_path, trained_at, 
		       training_started_at, training_completed_at, training_samples, 
		       hyperparameters, metrics, created_at
		FROM ml_models
		WHERE status = 'active' AND algorithm = ?
		ORDER BY name, created_at DESC
	`

	return mms.queryModelsWithParam(ctx, query, algorithm)
}

// UpdateModelStatus updates the status of a model (TASK 37)
func (mms *MLModelStorage) UpdateModelStatus(ctx context.Context, name, version, status string) error {
	if name == "" || version == "" || status == "" {
		return fmt.Errorf("name, version, and status cannot be empty")
	}

	validStatuses := map[string]bool{
		"active":   true,
		"retired":  true,
		"training": true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("invalid status: %s (must be 'active', 'retired', or 'training')", status)
	}

	query := `
		UPDATE ml_models
		SET status = ?
		WHERE name = ? AND version = ?
	`

	result, err := mms.db.DB.ExecContext(ctx, query, status, name, version)
	if err != nil {
		return fmt.Errorf("failed to update model status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("model %s v%s not found", name, version)
	}

	mms.logger.Infof("Updated model %s v%s status to %s", name, version, status)
	return nil
}

// ActivateModel marks a model as active and retires previous active versions (TASK 37)
func (mms *MLModelStorage) ActivateModel(ctx context.Context, name, version string) error {
	return mms.db.WithTransaction(func(tx *sql.Tx) error {
		// First, retire all existing active versions of this model
		retireQuery := `
			UPDATE ml_models
			SET status = 'retired'
			WHERE name = ? AND status = 'active'
		`
		_, err := tx.ExecContext(ctx, retireQuery, name)
		if err != nil {
			return fmt.Errorf("failed to retire previous models: %w", err)
		}

		// Activate the new version
		activateQuery := `
			UPDATE ml_models
			SET status = 'active'
			WHERE name = ? AND version = ?
		`
		result, err := tx.ExecContext(ctx, activateQuery, name, version)
		if err != nil {
			return fmt.Errorf("failed to activate model: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("model %s v%s not found", name, version)
		}

		mms.logger.Infof("Activated model %s v%s and retired previous versions", name, version)
		return nil
	})
}

// RollbackModel rolls back to a previous version (TASK 37.3)
func (mms *MLModelStorage) RollbackModel(ctx context.Context, name, targetVersion string) error {
	// Validate target version exists
	_, _, err := mms.LoadModel(ctx, name, targetVersion)
	if err != nil {
		return fmt.Errorf("target version %s v%s not found: %w", name, targetVersion, err)
	}

	// Activate the target version (which will retire current active)
	return mms.ActivateModel(ctx, name, targetVersion)
}

// PruneOldVersions keeps only the last N versions of a model (TASK 37.3)
// Deletes older versions and their files (soft delete: sets status to 'retired')
func (mms *MLModelStorage) PruneOldVersions(ctx context.Context, name string, keepVersions int) error {
	if keepVersions < 1 {
		return fmt.Errorf("keepVersions must be at least 1")
	}

	// Get all versions sorted by version number (descending)
	versions, err := mms.ListVersions(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	if len(versions) <= keepVersions {
		return nil // Nothing to prune
	}

	// Versions are already sorted descending by ListVersions
	// Keep the first keepVersions, retire the rest
	versionsToRetire := versions[keepVersions:]

	for _, version := range versionsToRetire {
		if err := mms.UpdateModelStatus(ctx, name, version, "retired"); err != nil {
			mms.logger.Warnf("Failed to retire old version %s v%s: %v", name, version, err)
			// Continue with other versions
		} else {
			mms.logger.Infof("Retired old version %s v%s", name, version)
		}
	}

	return nil
}

// GetModelVersions returns all versions of a model with metadata (TASK 37.3)
func (mms *MLModelStorage) GetModelVersions(ctx context.Context, name string) ([]ModelMetadata, error) {
	query := `
		SELECT name, version, model_type, algorithm, status, file_path, trained_at, 
		       training_started_at, training_completed_at, training_samples, 
		       hyperparameters, metrics, created_at
		FROM ml_models
		WHERE name = ?
		ORDER BY created_at DESC
	`

	return mms.queryModelsWithParam(ctx, query, name)
}

// queryModels is a helper to query models with full metadata (TASK 37)
func (mms *MLModelStorage) queryModels(ctx context.Context, query string) ([]ModelMetadata, error) {
	rows, err := mms.db.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query models: %w", err)
	}
	defer rows.Close()

	return mms.scanModelRows(rows)
}

// queryModelsWithParam is a helper to query models with a parameter (TASK 37)
func (mms *MLModelStorage) queryModelsWithParam(ctx context.Context, query string, param interface{}) ([]ModelMetadata, error) {
	rows, err := mms.db.ReadDB.QueryContext(ctx, query, param)
	if err != nil {
		return nil, fmt.Errorf("failed to query models: %w", err)
	}
	defer rows.Close()

	return mms.scanModelRows(rows)
}

// scanModelRows scans model rows into ModelMetadata structs (TASK 37)
func (mms *MLModelStorage) scanModelRows(rows *sql.Rows) ([]ModelMetadata, error) {
	var models []ModelMetadata
	for rows.Next() {
		var model ModelMetadata
		var trainedAtStr, createdAtStr string
		var trainingStartedAt, trainingCompletedAt sql.NullString
		var trainingSamples sql.NullInt64
		var filePath, algorithm, status, hyperparameters, metrics sql.NullString

		err := rows.Scan(
			&model.Name,
			&model.Version,
			&model.ModelType,
			&algorithm,
			&status,
			&filePath,
			&trainedAtStr,
			&trainingStartedAt,
			&trainingCompletedAt,
			&trainingSamples,
			&hyperparameters,
			&metrics,
			&createdAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan model: %w", err)
		}

		// Parse timestamps
		if trainedAt, err := time.Parse(time.RFC3339, trainedAtStr); err == nil {
			model.TrainedAt = trainedAt
		}
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			model.CreatedAt = createdAt
		}
		if trainingStartedAt.Valid {
			if t, err := time.Parse(time.RFC3339, trainingStartedAt.String); err == nil {
				model.TrainingStartedAt = &t
			}
		}
		if trainingCompletedAt.Valid {
			if t, err := time.Parse(time.RFC3339, trainingCompletedAt.String); err == nil {
				model.TrainingCompletedAt = &t
			}
		}

		// Parse nullable fields
		if algorithm.Valid {
			model.Algorithm = algorithm.String
		}
		if status.Valid {
			model.Status = status.String
		}
		if filePath.Valid {
			model.FilePath = filePath.String
		}
		if trainingSamples.Valid {
			samples := int(trainingSamples.Int64)
			model.TrainingSamples = &samples
		}
		if hyperparameters.Valid {
			model.Hyperparameters = hyperparameters.String
		}
		if metrics.Valid {
			model.Metrics = metrics.String
		}

		models = append(models, model)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating models: %w", err)
	}

	return models, nil
}
