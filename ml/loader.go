package ml

import (
	"context"
	"fmt"
	"sync"

	"cerberus/storage"

	"go.uber.org/zap"
)

// StorageModelStorageAdapter adapts storage.MLModelStorage to ml.ModelStorage interface
// TASK 37.4: Adapter to bridge context-aware storage with context-free interface
type StorageModelStorageAdapter struct {
	Storage *storage.MLModelStorage
}

// GetLatestVersion implements ml.ModelStorage interface
func (a *StorageModelStorageAdapter) GetLatestVersion(modelName string) (string, error) {
	return a.Storage.GetLatestVersion(modelName)
}

// ListVersions implements ml.ModelStorage interface
func (a *StorageModelStorageAdapter) ListVersions(modelName string) ([]string, error) {
	ctx := context.Background()
	return a.Storage.ListVersions(ctx, modelName)
}

// ModelLoader handles automatic loading of persisted models on startup
// TASK 37.4: Automatic model loading from storage
type ModelLoader struct {
	storage        *storage.MLModelStorage
	persistence    *ModelPersistence
	logger         *zap.SugaredLogger
	loadedModels   map[string]AnomalyDetector // Map of algorithm -> loaded detector
	loadedModelsMu sync.RWMutex
}

// NewModelLoader creates a new model loader
// TASK 37.4: Initialize loader with storage and persistence
func NewModelLoader(modelStorage *storage.MLModelStorage, persistence *ModelPersistence, logger *zap.SugaredLogger) *ModelLoader {
	return &ModelLoader{
		storage:      modelStorage,
		persistence:  persistence,
		logger:       logger,
		loadedModels: make(map[string]AnomalyDetector),
	}
}

// LoadActiveModels loads all active models from storage and returns them
// TASK 37.4: Load active models on startup with graceful degradation
func (ml *ModelLoader) LoadActiveModels(ctx context.Context) (map[string]AnomalyDetector, error) {
	if ml.storage == nil {
		ml.logger.Warn("Model storage not available, skipping model loading")
		return make(map[string]AnomalyDetector), nil
	}

	// Get all active models from storage
	metadataList, err := ml.storage.GetActiveModels(ctx)
	if err != nil {
		ml.logger.Warnf("Failed to get active models from storage: %v. Continuing without persisted models.", err)
		return make(map[string]AnomalyDetector), nil // Graceful degradation
	}

	if len(metadataList) == 0 {
		ml.logger.Info("No active models found in storage, starting with fresh detectors")
		return make(map[string]AnomalyDetector), nil
	}

	ml.loadedModelsMu.Lock()
	defer ml.loadedModelsMu.Unlock()

	loadedCount := 0
	failedCount := 0

	// Load each active model
	for _, metadata := range metadataList {
		// Determine algorithm name (use algorithm field or derive from model_type)
		algorithm := metadata.Algorithm
		if algorithm == "" {
			algorithm = metadata.ModelType // Fallback to model_type
		}

		// Load model (try file_path first, then model_data)
		var detector AnomalyDetector
		var loadErr error

		if metadata.FilePath != "" {
			// Load from file
			detector, loadErr = ml.persistence.LoadModelFromFile(metadata.FilePath, metadata.ModelType)
		} else {
			// Load from database BLOB
			_, modelData, err := ml.storage.LoadModel(ctx, metadata.Name, metadata.Version)
			if err != nil {
				loadErr = fmt.Errorf("failed to load model data from database: %w", err)
			} else {
				detector, loadErr = ml.persistence.serializer.Deserialize(modelData, metadata.ModelType)
			}
		}

		if loadErr != nil {
			ml.logger.Errorf("Failed to load model %s v%s (%s): %v. Continuing without this model.",
				metadata.Name, metadata.Version, algorithm, loadErr)
			failedCount++
			continue // Graceful degradation: continue loading other models
		}

		if detector == nil {
			ml.logger.Errorf("Model %s v%s loaded but detector is nil", metadata.Name, metadata.Version)
			failedCount++
			continue
		}

		// Register detector (keep only the latest version per algorithm)
		// If multiple models exist for same algorithm, keep the most recent one
		if existing, exists := ml.loadedModels[algorithm]; exists {
			ml.logger.Debugf("Replacing existing %s detector with newer model %s v%s",
				algorithm, metadata.Name, metadata.Version)
			_ = existing // Discard old detector
		}

		ml.loadedModels[algorithm] = detector
		loadedCount++

		ml.logger.Infof("Loaded active model: %s v%s (%s)", metadata.Name, metadata.Version, algorithm)
	}

	ml.logger.Infof("Model loading complete: %d loaded, %d failed", loadedCount, failedCount)

	// Return copy of loaded models
	result := make(map[string]AnomalyDetector, len(ml.loadedModels))
	for k, v := range ml.loadedModels {
		result[k] = v
	}

	return result, nil
}

// GetLoadedModel returns a loaded model by algorithm name
// TASK 37.4: Get loaded model for use in detection
func (ml *ModelLoader) GetLoadedModel(algorithm string) (AnomalyDetector, bool) {
	ml.loadedModelsMu.RLock()
	defer ml.loadedModelsMu.RUnlock()

	detector, exists := ml.loadedModels[algorithm]
	return detector, exists
}

// RegisterDetector registers a detector (used when models are loaded or created)
// TASK 37.4: Register newly loaded or trained models
func (ml *ModelLoader) RegisterDetector(algorithm string, detector AnomalyDetector) {
	ml.loadedModelsMu.Lock()
	defer ml.loadedModelsMu.Unlock()

	ml.loadedModels[algorithm] = detector
	ml.logger.Debugf("Registered detector: %s", algorithm)
}

// LoadOrTrainDetector loads a persisted model for an algorithm, or returns nil if not found
// TASK 37.4: Compatibility method for ensemble_engine.go
// This method attempts to load a model, but does NOT create a new detector (caller should create fallback)
func (ml *ModelLoader) LoadOrTrainDetector(ctx context.Context, algorithm string) (AnomalyDetector, error) {
	if ml.storage == nil {
		return nil, fmt.Errorf("model storage not available")
	}

	// Get active models for this algorithm
	activeModels, err := ml.storage.GetActiveModelsByAlgorithm(ctx, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get active models: %w", err)
	}

	if len(activeModels) == 0 {
		return nil, fmt.Errorf("no active models found for algorithm %s", algorithm)
	}

	// Use the first active model (most recent by created_at DESC)
	metadata := activeModels[0]

	// Load model (try file_path first, then model_data)
	var detector AnomalyDetector

	if metadata.FilePath != "" {
		// Load from file
		detector, err = ml.persistence.LoadModelFromFile(metadata.FilePath, metadata.ModelType)
	} else {
		// Load from database BLOB
		_, modelData, err := ml.storage.LoadModel(ctx, metadata.Name, metadata.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to load model data: %w", err)
		}
		detector, err = ml.persistence.serializer.Deserialize(modelData, metadata.ModelType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to deserialize model: %w", err)
	}

	// Register loaded detector
	ml.RegisterDetector(algorithm, detector)

	ml.logger.Infof("Loaded persisted model for algorithm %s: %s v%s", algorithm, metadata.Name, metadata.Version)
	return detector, nil
}
