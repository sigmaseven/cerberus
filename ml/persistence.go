package ml

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
)

// ModelSerializer handles serialization and deserialization of ML models
// TASK 26.1: Model serialization using encoding/gob
type ModelSerializer struct {
	mu sync.RWMutex
}

// NewModelSerializer creates a new model serializer
func NewModelSerializer() *ModelSerializer {
	// Register concrete types with gob for serialization
	gob.Register(&ZScoreDetector{})
	gob.Register(&IQRDetector{})
	gob.Register(&IsolationForest{})
	gob.Register(&FeatureStats{})
	gob.Register(&IsolationTree{})
	gob.Register(&IsolationNode{})

	return &ModelSerializer{}
}

// Serialize converts an AnomalyDetector to binary format using encoding/gob
// TASK 26.1: Serialize detector structs (ZScore, IQR, IsolationForest) to binary
func (ms *ModelSerializer) Serialize(detector AnomalyDetector) ([]byte, error) {
	if detector == nil {
		return nil, fmt.Errorf("detector cannot be nil")
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	// Thread-safe serialization: acquire RLock before reading detector state
	// The detector's internal mutex should be held by caller during serialization
	switch d := detector.(type) {
	case *ZScoreDetector:
		d.mu.RLock()
		defer d.mu.RUnlock()
		if err := encoder.Encode(d); err != nil {
			return nil, fmt.Errorf("failed to encode ZScoreDetector: %w", err)
		}
	case *IQRDetector:
		d.mu.RLock()
		defer d.mu.RUnlock()
		if err := encoder.Encode(d); err != nil {
			return nil, fmt.Errorf("failed to encode IQRDetector: %w", err)
		}
	case *IsolationForest:
		// IsolationForest may not have mutex, serialize as-is
		if err := encoder.Encode(d); err != nil {
			return nil, fmt.Errorf("failed to encode IsolationForest: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported detector type: %T", detector)
	}

	return buf.Bytes(), nil
}

// Deserialize converts binary data back to an AnomalyDetector
// TASK 26.1: Deserialize gob binary to detector interface
func (ms *ModelSerializer) Deserialize(data []byte, modelType string) (AnomalyDetector, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("model data cannot be empty")
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	decoder := gob.NewDecoder(bytes.NewReader(data))

	switch modelType {
	case "zscore":
		detector := &ZScoreDetector{}
		if err := decoder.Decode(detector); err != nil {
			return nil, fmt.Errorf("failed to decode ZScoreDetector: %w", err)
		}
		// Ensure featureStats map is initialized if empty
		if detector.featureStats == nil {
			detector.featureStats = make(map[string]*FeatureStats)
		}
		return detector, nil

	case "iqr":
		detector := &IQRDetector{}
		if err := decoder.Decode(detector); err != nil {
			return nil, fmt.Errorf("failed to decode IQRDetector: %w", err)
		}
		// Ensure featureValues map is initialized if empty
		if detector.featureValues == nil {
			detector.featureValues = make(map[string][]float64)
		}
		return detector, nil

	case "isolation_forest":
		detector := &IsolationForest{}
		if err := decoder.Decode(detector); err != nil {
			return nil, fmt.Errorf("failed to decode IsolationForest: %w", err)
		}
		// Ensure trees slice is initialized if empty
		if detector.trees == nil {
			detector.trees = make([]*IsolationTree, 0)
		}
		if detector.features == nil {
			detector.features = make([]string, 0)
		}
		return detector, nil

	default:
		return nil, fmt.Errorf("unsupported model type: %s", modelType)
	}
}

// ModelMetadata contains training metadata for a model
// TASK 26.3: Store training metadata with models
// TASK 37: Enhanced with file-based storage support
type ModelMetadata struct {
	DatasetSize      int                    `json:"dataset_size"`
	TrainingDuration float64                `json:"training_duration_ms"` // in milliseconds
	Threshold        float64                `json:"threshold,omitempty"`
	Hyperparameters  map[string]interface{} `json:"hyperparameters,omitempty"`
	Precision        float64                `json:"precision,omitempty"`
	Recall           float64                `json:"recall,omitempty"`
	F1Score          float64                `json:"f1_score,omitempty"`
}

// ModelPersistence handles model serialization, file-based storage, and loading
// TASK 37.1: Enhanced persistence manager with file-based storage
// Uses ModelStorage interface from ml/versioning.go for version queries
type ModelPersistence struct {
	serializer *ModelSerializer
	storage    ModelStorage // Interface for version queries (optional, from ml/versioning.go)
	modelDir   string       // Directory for storing model files
	logger     *zap.SugaredLogger
	mu         sync.RWMutex
}

// NewModelPersistence creates a new model persistence manager (TASK 37.1)
func NewModelPersistence(modelDir string, storage ModelStorage, logger *zap.SugaredLogger) (*ModelPersistence, error) {
	if modelDir == "" {
		return nil, fmt.Errorf("model directory cannot be empty")
	}

	// Create model directory if it doesn't exist
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create model directory: %w", err)
	}

	return &ModelPersistence{
		serializer: NewModelSerializer(),
		storage:    storage,
		modelDir:   modelDir,
		logger:     logger,
	}, nil
}

// SaveModelToFile saves a model to disk with gzip compression (TASK 37.1)
func (mp *ModelPersistence) SaveModelToFile(detector AnomalyDetector, name, version string) (string, error) {
	if detector == nil {
		return "", fmt.Errorf("detector cannot be nil")
	}
	if name == "" || version == "" {
		return "", fmt.Errorf("model name and version cannot be empty")
	}

	// Determine model type
	var modelType string
	switch detector.(type) {
	case *ZScoreDetector:
		modelType = "zscore"
	case *IQRDetector:
		modelType = "iqr"
	case *IsolationForest:
		modelType = "isolation_forest"
	default:
		return "", fmt.Errorf("unsupported detector type: %T", detector)
	}

	// Serialize model
	modelData, err := mp.serializer.Serialize(detector)
	if err != nil {
		return "", fmt.Errorf("failed to serialize model: %w", err)
	}

	// Create file path
	fileName := fmt.Sprintf("%s_v%s_%s.gob.gz", name, version, modelType)
	filePath := filepath.Join(mp.modelDir, fileName)

	// Compress and write to file
	mp.mu.Lock()
	defer mp.mu.Unlock()

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create model file: %w", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	if _, err := gzipWriter.Write(modelData); err != nil {
		return "", fmt.Errorf("failed to write compressed model data: %w", err)
	}

	if err := gzipWriter.Flush(); err != nil {
		return "", fmt.Errorf("failed to flush compressed data: %w", err)
	}

	mp.logger.Infof("Saved model to file: %s (compressed size: %d bytes)", filePath, len(modelData))
	return filePath, nil
}

// LoadModelFromFile loads a model from disk (TASK 37.1)
func (mp *ModelPersistence) LoadModelFromFile(filePath, modelType string) (AnomalyDetector, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}
	if modelType == "" {
		return nil, fmt.Errorf("model type cannot be empty")
	}

	mp.mu.RLock()
	defer mp.mu.RUnlock()

	// Read and decompress file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open model file: %w", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(gzipReader); err != nil {
		return nil, fmt.Errorf("failed to read compressed model data: %w", err)
	}

	// Deserialize model
	detector, err := mp.serializer.Deserialize(buf.Bytes(), modelType)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize model: %w", err)
	}

	mp.logger.Infof("Loaded model from file: %s", filePath)
	return detector, nil
}

// SaveModelMetadataToJSON saves model metadata as JSON (TASK 37.1)
func (mp *ModelPersistence) SaveModelMetadataToJSON(metadata *ModelMetadata, name, version string) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("metadata cannot be nil")
	}

	// Create metadata file path
	fileName := fmt.Sprintf("%s_v%s_metadata.json", name, version)
	filePath := filepath.Join(mp.modelDir, fileName)

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return "", fmt.Errorf("failed to write metadata file: %w", err)
	}

	mp.logger.Debugf("Saved model metadata to: %s", filePath)
	return filePath, nil
}
