package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupMLModelsTestDB creates an in-memory SQLite database for ML models tests
func setupMLModelsTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create ML models table
	schema := `
	CREATE TABLE IF NOT EXISTS ml_models (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		model_type TEXT NOT NULL,
		model_data BLOB,
		file_path TEXT,
		status TEXT NOT NULL DEFAULT 'training',
		algorithm TEXT,
		config TEXT,
		trained_at DATETIME NOT NULL,
		training_started_at DATETIME,
		training_completed_at DATETIME,
		training_samples INTEGER,
		hyperparameters TEXT,
		metrics TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(name, version)
	);
	CREATE INDEX IF NOT EXISTS idx_ml_models_name ON ml_models(name);
	CREATE INDEX IF NOT EXISTS idx_ml_models_version ON ml_models(name, version);
	CREATE INDEX IF NOT EXISTS idx_ml_models_status ON ml_models(status);
	CREATE INDEX IF NOT EXISTS idx_ml_models_algorithm ON ml_models(algorithm);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	return sqlite
}

// TestMLModelStorage_SaveModel tests model saving with BLOB storage
func TestMLModelStorage_SaveModel(t *testing.T) {
	sqlite := setupMLModelsTestDB(t)
	defer sqlite.DB.Close()

	storage := NewMLModelStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	tests := []struct {
		name      string
		modelName string
		version   string
		modelType string
		modelData []byte
		expectErr bool
	}{
		{
			name:      "Valid model with small BLOB",
			modelName: "test-model",
			version:   "1.0.0",
			modelType: "zscore",
			modelData: []byte("small model data"),
			expectErr: false,
		},
		{
			name:      "Valid model with large BLOB",
			modelName: "large-model",
			version:   "1.0.0",
			modelType: "iqr",
			modelData: make([]byte, 1024*1024), // 1MB
			expectErr: false,
		},
		{
			name:      "Duplicate model version",
			modelName: "test-model",
			version:   "1.0.0",
			modelType: "zscore",
			modelData: []byte("duplicate"),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.SaveModel(ctx, tt.modelName, tt.version, tt.modelType, tt.modelData, "{}", "{}")
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify model was saved
				modelType, modelBytes, err := storage.LoadModel(ctx, tt.modelName, tt.version)
				require.NoError(t, err)
				assert.Equal(t, tt.modelType, modelType)
				assert.Equal(t, tt.modelData, modelBytes)
			}
		})
	}
}

// TestMLModelStorage_ModelVersioning tests model versioning
func TestMLModelStorage_ModelVersioning(t *testing.T) {
	sqlite := setupMLModelsTestDB(t)
	defer sqlite.DB.Close()

	storage := NewMLModelStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	modelName := "versioned-model"

	// Save multiple versions
	versions := []string{"1.0.0", "1.1.0", "2.0.0"}
	for _, version := range versions {
		err := storage.SaveModel(ctx, modelName, version, "zscore", []byte("model data"), "{}", "{}")
		require.NoError(t, err)
	}

	// Get all versions
	allVersions, err := storage.GetModelVersions(ctx, modelName)
	require.NoError(t, err)
	assert.Len(t, allVersions, len(versions))

	// Verify versions are retrieved
	versionSet := make(map[string]bool)
	for _, metadata := range allVersions {
		versionSet[metadata.Version] = true
		assert.Equal(t, modelName, metadata.Name)
	}
	for _, version := range versions {
		assert.True(t, versionSet[version], "Version %s should be in list", version)
	}
}

// TestMLModelStorage_LargeBLOBStorage tests storing large model binaries
func TestMLModelStorage_LargeBLOBStorage(t *testing.T) {
	sqlite := setupMLModelsTestDB(t)
	defer sqlite.DB.Close()

	storage := NewMLModelStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Test with various sizes
	sizes := []int{1024, 1024 * 100, 1024 * 1024, 1024 * 1024 * 10} // 1KB, 100KB, 1MB, 10MB

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d_bytes", size), func(t *testing.T) {
			modelData := make([]byte, size)
			rand.Read(modelData) // Fill with random data

			modelName := fmt.Sprintf("large-model-%d", size)
			err := storage.SaveModel(ctx, modelName, "1.0.0", "isolation_forest", modelData, "{}", "{}")
			require.NoError(t, err)

			// Verify model data was stored
			_, modelBytes, err := storage.LoadModel(ctx, modelName, "1.0.0")
			require.NoError(t, err)
			assert.Equal(t, size, len(modelBytes))
			assert.Equal(t, modelData, modelBytes)
		})
	}
}

// TestMLModelStorage_ModelActivation tests model activation/deactivation
func TestMLModelStorage_ModelActivation(t *testing.T) {
	sqlite := setupMLModelsTestDB(t)
	defer sqlite.DB.Close()

	storage := NewMLModelStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	modelName := "activation-test"
	err := storage.SaveModel(ctx, modelName, "1.0.0", "zscore", []byte("data"), "{}", "{}")
	require.NoError(t, err)

	// Get active model (should be none initially)
	_, _, _, err = storage.GetActiveModel(ctx, modelName)
	require.Error(t, err) // Should fail, no active model yet

	// Activate model
	err = storage.ActivateModel(ctx, modelName, "1.0.0")
	require.NoError(t, err)

	// Get active model (should succeed now)
	version, modelType, modelBytes, err := storage.GetActiveModel(ctx, modelName)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", version)
	assert.Equal(t, "zscore", modelType)
	assert.NotNil(t, modelBytes)
}

// TestMLModelStorage_ConcurrentModelSaves tests concurrent model saves
func TestMLModelStorage_ConcurrentModelSaves(t *testing.T) {
	sqlite := setupMLModelsTestDB(t)
	defer sqlite.DB.Close()

	storage := NewMLModelStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	const numGoroutines = 10
	const modelsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*modelsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < modelsPerGoroutine; j++ {
				modelName := fmt.Sprintf("concurrent-model-%d", goroutineID)
				version := fmt.Sprintf("1.0.%d", j)
				err := storage.SaveModel(ctx, modelName, version, "zscore", []byte("data"), "{}", "{}")
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Verify no errors occurred
	for err := range errors {
		require.NoError(t, err)
	}

	// Verify models were saved
	query := `SELECT COUNT(*) FROM ml_models`
	var count int
	err := sqlite.DB.QueryRow(query).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*modelsPerGoroutine, count)
}
