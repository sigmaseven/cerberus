package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupMLMetricsTestDB creates an in-memory SQLite database for ML metrics tests
func setupMLMetricsTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)
	_ = storage

	return sqlite
}

// TestSQLiteMLModelMetricsStorage_RecordFeedback tests feedback recording
func TestSQLiteMLModelMetricsStorage_RecordFeedback(t *testing.T) {
	sqlite := setupMLMetricsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name             string
		alertID          string
		investigationID  string
		predictedScore   float64
		predictedAnomaly bool
		actualAnomaly    bool
		confusionEntry   string
		expectErr        bool
	}{
		{
			name:             "True positive feedback",
			alertID:          "alert-1",
			investigationID:  "inv-1",
			predictedScore:   0.95,
			predictedAnomaly: true,
			actualAnomaly:    true,
			confusionEntry:   "tp",
			expectErr:        false,
		},
		{
			name:             "False positive feedback",
			alertID:          "alert-2",
			investigationID:  "inv-2",
			predictedScore:   0.85,
			predictedAnomaly: true,
			actualAnomaly:    false,
			confusionEntry:   "fp",
			expectErr:        false,
		},
		{
			name:             "True negative feedback",
			alertID:          "alert-3",
			investigationID:  "inv-3",
			predictedScore:   0.15,
			predictedAnomaly: false,
			actualAnomaly:    false,
			confusionEntry:   "tn",
			expectErr:        false,
		},
		{
			name:             "False negative feedback",
			alertID:          "alert-4",
			investigationID:  "inv-4",
			predictedScore:   0.25,
			predictedAnomaly: false,
			actualAnomaly:    true,
			confusionEntry:   "fn",
			expectErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.RecordFeedback(ctx, tt.alertID, tt.investigationID, tt.predictedScore, tt.predictedAnomaly, tt.actualAnomaly, tt.confusionEntry, time.Now())
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify feedback was recorded
				query := `SELECT COUNT(*) FROM ml_feedback WHERE alert_id = ?`
				var count int
				err = sqlite.DB.QueryRow(query, tt.alertID).Scan(&count)
				require.NoError(t, err)
				assert.Equal(t, 1, count)
			}
		})
	}
}

// TestSQLiteMLModelMetricsStorage_CalculateMetrics tests metrics calculation
func TestSQLiteMLModelMetricsStorage_CalculateMetrics(t *testing.T) {
	sqlite := setupMLMetricsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Record feedback for metrics calculation
	modelName := "test-model"
	timestamp := time.Now()

	// Record various feedback types
	feedback := []struct {
		predictedAnomaly, actualAnomaly bool
		confusionEntry                  string
	}{
		{true, true, "tp"},   // True positive
		{true, true, "tp"},   // True positive
		{true, false, "fp"},  // False positive
		{false, false, "tn"}, // True negative
		{false, false, "tn"}, // True negative
		{false, true, "fn"},  // False negative
	}

	for i, f := range feedback {
		err := storage.RecordFeedback(ctx, "alert-"+string(rune(i)), "inv-"+string(rune(i)), 0.5, f.predictedAnomaly, f.actualAnomaly, f.confusionEntry, timestamp)
		require.NoError(t, err)
	}

	// Get confusion matrix and store metrics
	windowDuration := 24 * time.Hour
	matrix, err := storage.GetConfusionMatrix(ctx, modelName, windowDuration)
	require.NoError(t, err)

	// Store calculated metrics
	metrics := &ModelMetrics{
		ModelID:        modelName,
		Timestamp:      timestamp,
		WindowDuration: windowDuration,
		TruePositives:  matrix.TP,
		FalsePositives: matrix.FP,
		TrueNegatives:  matrix.TN,
		FalseNegatives: matrix.FN,
	}
	if matrix.TP+matrix.FP > 0 {
		metrics.Precision = float64(matrix.TP) / float64(matrix.TP+matrix.FP)
	}
	if matrix.TP+matrix.FN > 0 {
		metrics.Recall = float64(matrix.TP) / float64(matrix.TP+matrix.FN)
	}
	if metrics.Precision+metrics.Recall > 0 {
		metrics.F1Score = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall)
	}
	total := matrix.TP + matrix.TN + matrix.FP + matrix.FN
	if total > 0 {
		metrics.Accuracy = float64(matrix.TP+matrix.TN) / float64(total)
	}

	err = storage.StoreMetrics(ctx, metrics)
	require.NoError(t, err)

	// Verify metrics were stored
	query := `SELECT true_positives, false_positives, true_negatives, false_negatives, precision, recall, f1_score
	          FROM ml_model_metrics WHERE model_name = ? AND timestamp = ?`
	var tp, fp, tn, fn int64
	var precision, recall, f1 sql.NullFloat64
	err = sqlite.DB.QueryRow(query, modelName, timestamp).Scan(&tp, &fp, &tn, &fn, &precision, &recall, &f1)
	require.NoError(t, err)

	assert.Equal(t, int64(2), tp) // Two true positives
	assert.Equal(t, int64(1), fp) // One false positive
	assert.Equal(t, int64(2), tn) // Two true negatives
	assert.Equal(t, int64(1), fn) // One false negative
	assert.True(t, precision.Valid)
	assert.True(t, recall.Valid)
	assert.True(t, f1.Valid)
}

// TestSQLiteMLModelMetricsStorage_TimeSeriesQueries tests time series queries
func TestSQLiteMLModelMetricsStorage_TimeSeriesQueries(t *testing.T) {
	sqlite := setupMLMetricsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	modelName := "time-series-model"

	// Record metrics at different times
	baseTime := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 10; i++ {
		timestamp := baseTime.Add(time.Duration(i) * time.Hour)
		err := storage.RecordFeedback(ctx, "alert-"+string(rune(i)), "inv-"+string(rune(i)), 0.5, true, true, "tp", timestamp)
		require.NoError(t, err)
	}

	// Get confusion matrix for a time window
	windowDuration := 24 * time.Hour
	matrix, err := storage.GetConfusionMatrix(ctx, modelName, windowDuration)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, matrix.TP, int64(0))

	// Query metrics by time range
	startTime := baseTime.Add(-1 * time.Hour)
	endTime := baseTime.Add(25 * time.Hour)
	query := `SELECT COUNT(*) FROM ml_model_metrics WHERE model_name = ? AND timestamp BETWEEN ? AND ?`
	var count int
	err = sqlite.DB.QueryRow(query, modelName, startTime, endTime).Scan(&count)
	require.NoError(t, err)
	assert.Greater(t, count, 0)
}

// TestSQLiteMLModelMetricsStorage_AggregationQueries tests aggregation queries
func TestSQLiteMLModelMetricsStorage_AggregationQueries(t *testing.T) {
	sqlite := setupMLMetricsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	modelName := "aggregation-model"
	timestamp := time.Now()

	// Record multiple feedback entries
	for i := 0; i < 20; i++ {
		err := storage.RecordFeedback(ctx, "alert-"+string(rune(i)), "inv-"+string(rune(i)), 0.5, true, i%2 == 0, "tp", timestamp)
		require.NoError(t, err)
	}

	// Get confusion matrix and store metrics
	windowDuration := 24 * time.Hour
	matrix, err := storage.GetConfusionMatrix(ctx, modelName, windowDuration)
	require.NoError(t, err)

	// Store metrics
	metrics := &ModelMetrics{
		ModelID:        modelName,
		Timestamp:      timestamp,
		WindowDuration: windowDuration,
		TruePositives:  matrix.TP,
		FalsePositives: matrix.FP,
		TrueNegatives:  matrix.TN,
		FalseNegatives: matrix.FN,
	}
	err = storage.StoreMetrics(ctx, metrics)
	require.NoError(t, err)

	// Test SUM aggregation
	query := `SELECT SUM(true_positives + false_positives + true_negatives + false_negatives) 
	          FROM ml_model_metrics WHERE model_name = ?`
	var total int
	err = sqlite.DB.QueryRow(query, modelName).Scan(&total)
	require.NoError(t, err)
	assert.Equal(t, 20, total)

	// Test AVG aggregation
	query = `SELECT AVG(precision) FROM ml_model_metrics WHERE model_name = ?`
	var avgPrecision sql.NullFloat64
	err = sqlite.DB.QueryRow(query, modelName).Scan(&avgPrecision)
	require.NoError(t, err)
	assert.True(t, avgPrecision.Valid)

	// Test COUNT aggregation
	query = `SELECT COUNT(*) FROM ml_model_metrics WHERE model_name = ?`
	var count int
	err = sqlite.DB.QueryRow(query, modelName).Scan(&count)
	require.NoError(t, err)
	assert.Greater(t, count, 0)
}

// TestSQLiteMLModelMetricsStorage_ConcurrentOperations tests concurrent metric insertions
func TestSQLiteMLModelMetricsStorage_ConcurrentOperations(t *testing.T) {
	sqlite := setupMLMetricsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteMLModelMetricsStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	const numGoroutines = 10
	const feedbackPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*feedbackPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < feedbackPerGoroutine; j++ {
				alertID := fmt.Sprintf("alert-%d-%d", goroutineID, j)
				invID := fmt.Sprintf("inv-%d-%d", goroutineID, j)
				err := storage.RecordFeedback(ctx, alertID, invID, 0.5, true, true, "tp", time.Now())
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

	// Verify all feedback was recorded
	query := `SELECT COUNT(*) FROM ml_feedback`
	var count int
	err = sqlite.DB.QueryRow(query).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*feedbackPerGoroutine, count)
}
