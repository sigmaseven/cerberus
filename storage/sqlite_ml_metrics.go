package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SQLiteMLModelMetricsStorage implements MLModelMetricsStorageInterface using SQLite
// TASK 29: ML feedback loop metrics storage
type SQLiteMLModelMetricsStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteMLModelMetricsStorage creates a new SQLite-based ML metrics storage
func NewSQLiteMLModelMetricsStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLiteMLModelMetricsStorage, error) {
	storage := &SQLiteMLModelMetricsStorage{
		db:     db,
		logger: logger,
	}

	if err := storage.ensureTables(); err != nil {
		return nil, fmt.Errorf("failed to ensure ML metrics tables: %w", err)
	}

	return storage, nil
}

// ensureTables creates the ML metrics tables if they don't exist
func (s *SQLiteMLModelMetricsStorage) ensureTables() error {
	// Feedback table for storing analyst feedback
	feedbackQuery := `
	CREATE TABLE IF NOT EXISTS ml_feedback (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		alert_id TEXT NOT NULL,
		investigation_id TEXT NOT NULL,
		model_name TEXT NOT NULL,
		predicted_score REAL NOT NULL,
		predicted_anomaly INTEGER NOT NULL,
		actual_anomaly INTEGER NOT NULL,
		confusion_entry TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ml_feedback_model ON ml_feedback(model_name, timestamp);
	CREATE INDEX IF NOT EXISTS idx_ml_feedback_investigation ON ml_feedback(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_ml_feedback_alert ON ml_feedback(alert_id);
	CREATE INDEX IF NOT EXISTS idx_ml_feedback_timestamp ON ml_feedback(timestamp DESC);
	`

	// Metrics table for storing calculated metrics
	metricsQuery := `
	CREATE TABLE IF NOT EXISTS ml_model_metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		model_name TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		window_duration_seconds INTEGER NOT NULL,
		true_positives INTEGER NOT NULL DEFAULT 0,
		true_negatives INTEGER NOT NULL DEFAULT 0,
		false_positives INTEGER NOT NULL DEFAULT 0,
		false_negatives INTEGER NOT NULL DEFAULT 0,
		precision REAL,
		recall REAL,
		f1_score REAL,
		false_positive_rate REAL,
		false_negative_rate REAL,
		accuracy REAL,
		drift_score REAL,
		drift_detected INTEGER NOT NULL DEFAULT 0,
		metrics_data TEXT -- JSON for additional metrics
	);
	CREATE INDEX IF NOT EXISTS idx_ml_metrics_model ON ml_model_metrics(model_name, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_ml_metrics_timestamp ON ml_model_metrics(timestamp DESC);
	`

	if _, err := s.db.DB.Exec(feedbackQuery); err != nil {
		return fmt.Errorf("failed to create ml_feedback table: %w", err)
	}

	if _, err := s.db.DB.Exec(metricsQuery); err != nil {
		return fmt.Errorf("failed to create ml_model_metrics table: %w", err)
	}

	s.logger.Info("ML metrics tables ensured in SQLite")
	return nil
}

// RecordFeedback records analyst feedback for an alert
// TASK 29.1: Store feedback in database
func (s *SQLiteMLModelMetricsStorage) RecordFeedback(ctx context.Context, alertID, investigationID string, predictedScore float64, predictedAnomaly, actualAnomaly bool, confusionEntry string, timestamp time.Time) error {
	// Extract model name from alert or use default
	modelName := "ensemble" // Default model name, could be extracted from alert metadata

	query := `
		INSERT INTO ml_feedback (
			alert_id, investigation_id, model_name, predicted_score,
			predicted_anomaly, actual_anomaly, confusion_entry, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	predictedInt := 0
	if predictedAnomaly {
		predictedInt = 1
	}
	actualInt := 0
	if actualAnomaly {
		actualInt = 1
	}

	_, err := s.db.DB.ExecContext(ctx, query,
		alertID,
		investigationID,
		modelName,
		predictedScore,
		predictedInt,
		actualInt,
		confusionEntry,
		timestamp,
	)

	if err != nil {
		return fmt.Errorf("failed to record feedback: %w", err)
	}

	s.logger.Debugf("Recorded ML feedback: alert=%s, confusion=%s", alertID, confusionEntry)
	return nil
}

// GetConfusionMatrix retrieves confusion matrix for a model over a time window
// TASK 29.2: Calculate confusion matrix from feedback
func (s *SQLiteMLModelMetricsStorage) GetConfusionMatrix(ctx context.Context, modelName string, windowDuration time.Duration) (*ConfusionMatrix, error) {
	windowStart := time.Now().Add(-windowDuration)

	query := `
		SELECT
			SUM(CASE WHEN confusion_entry = 'TP' THEN 1 ELSE 0 END) as tp,
			SUM(CASE WHEN confusion_entry = 'TN' THEN 1 ELSE 0 END) as tn,
			SUM(CASE WHEN confusion_entry = 'FP' THEN 1 ELSE 0 END) as fp,
			SUM(CASE WHEN confusion_entry = 'FN' THEN 1 ELSE 0 END) as fn
		FROM ml_feedback
		WHERE model_name = ? AND timestamp >= ?
	`

	var tp, tn, fp, fn sql.NullInt64
	err := s.db.ReadDB.QueryRowContext(ctx, query, modelName, windowStart).Scan(&tp, &tn, &fp, &fn)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get confusion matrix: %w", err)
	}

	matrix := &ConfusionMatrix{
		TP: getInt64Value(tp),
		TN: getInt64Value(tn),
		FP: getInt64Value(fp),
		FN: getInt64Value(fn),
	}

	return matrix, nil
}

// GetAverageMetrics retrieves average metrics for a model over a time window
// TASK 29.3: Get baseline and current metrics for drift detection
func (s *SQLiteMLModelMetricsStorage) GetAverageMetrics(ctx context.Context, modelName string, windowDuration, aggregationPeriod time.Duration) (*ModelMetricsSummary, error) {
	windowStart := time.Now().Add(-windowDuration)

	query := `
		SELECT
			AVG(precision) as avg_precision,
			AVG(recall) as avg_recall,
			AVG(f1_score) as avg_f1,
			AVG(accuracy) as avg_accuracy
		FROM ml_model_metrics
		WHERE model_name = ? AND timestamp >= ? AND timestamp <= ?
	`

	windowEnd := time.Now()
	if aggregationPeriod > 0 {
		windowEnd = windowStart.Add(aggregationPeriod)
	}

	var precision, recall, f1, accuracy sql.NullFloat64
	err := s.db.ReadDB.QueryRowContext(ctx, query, modelName, windowStart, windowEnd).Scan(&precision, &recall, &f1, &accuracy)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get average metrics: %w", err)
	}

	if !precision.Valid {
		// No metrics found, calculate from confusion matrix
		return s.calculateMetricsFromConfusionMatrix(ctx, modelName, windowDuration)
	}

	return &ModelMetricsSummary{
		Precision: getFloat64Value(precision),
		Recall:    getFloat64Value(recall),
		F1Score:   getFloat64Value(f1),
		Accuracy:  getFloat64Value(accuracy),
	}, nil
}

// calculateMetricsFromConfusionMatrix calculates metrics from confusion matrix if no stored metrics exist
func (s *SQLiteMLModelMetricsStorage) calculateMetricsFromConfusionMatrix(ctx context.Context, modelName string, windowDuration time.Duration) (*ModelMetricsSummary, error) {
	matrix, err := s.GetConfusionMatrix(ctx, modelName, windowDuration)
	if err != nil {
		return nil, err
	}

	total := matrix.TP + matrix.TN + matrix.FP + matrix.FN
	if total == 0 {
		return &ModelMetricsSummary{}, nil // No data
	}

	var precision, recall, f1, accuracy float64

	// Calculate precision
	if matrix.TP+matrix.FP > 0 {
		precision = float64(matrix.TP) / float64(matrix.TP+matrix.FP)
	}

	// Calculate recall
	if matrix.TP+matrix.FN > 0 {
		recall = float64(matrix.TP) / float64(matrix.TP+matrix.FN)
	}

	// Calculate F1
	if precision+recall > 0 {
		f1 = 2 * (precision * recall) / (precision + recall)
	}

	// Calculate accuracy
	accuracy = float64(matrix.TP+matrix.TN) / float64(total)

	return &ModelMetricsSummary{
		Precision: precision,
		Recall:    recall,
		F1Score:   f1,
		Accuracy:  accuracy,
	}, nil
}

// StoreMetrics stores calculated metrics
// TASK 29.2: Persist calculated metrics
func (s *SQLiteMLModelMetricsStorage) StoreMetrics(ctx context.Context, metrics *ModelMetrics) error {
	// Serialize additional metrics data if needed
	metricsData, _ := json.Marshal(map[string]interface{}{})

	query := `
		INSERT INTO ml_model_metrics (
			model_name, timestamp, window_duration_seconds,
			true_positives, true_negatives, false_positives, false_negatives,
			precision, recall, f1_score, false_positive_rate, false_negative_rate, accuracy,
			drift_score, drift_detected, metrics_data
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	driftDetected := 0
	if metrics.DriftDetected {
		driftDetected = 1
	}

	_, err := s.db.DB.ExecContext(ctx, query,
		metrics.ModelID,
		metrics.Timestamp,
		int64(metrics.WindowDuration.Seconds()),
		metrics.TruePositives,
		metrics.TrueNegatives,
		metrics.FalsePositives,
		metrics.FalseNegatives,
		metrics.Precision,
		metrics.Recall,
		metrics.F1Score,
		metrics.FalsePositiveRate,
		metrics.FalseNegativeRate,
		metrics.Accuracy,
		metrics.DriftScore,
		driftDetected,
		string(metricsData),
	)

	if err != nil {
		return fmt.Errorf("failed to store metrics: %w", err)
	}

	s.logger.Debugf("Stored ML metrics: model=%s, precision=%.3f, recall=%.3f", metrics.ModelID, metrics.Precision, metrics.Recall)
	return nil
}

// Helper functions

func getInt64Value(n sql.NullInt64) int64 {
	if n.Valid {
		return n.Int64
	}
	return 0
}

func getFloat64Value(n sql.NullFloat64) float64 {
	if n.Valid {
		return n.Float64
	}
	return 0.0
}
