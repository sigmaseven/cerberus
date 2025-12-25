package ml

import (
	"context"
	"fmt"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"go.uber.org/zap"
)

// FeedbackCollector collects analyst feedback from investigations
// TASK 29: ML analyst feedback loop
type FeedbackCollector struct {
	investigationStorage storage.InvestigationStorageInterface
	metricsStorage       storage.MLModelMetricsStorageInterface
	logger               *zap.SugaredLogger
	// TASK 138: Removed unused mu sync.RWMutex field
}

// NewFeedbackCollector creates a new feedback collector
func NewFeedbackCollector(
	investigationStorage storage.InvestigationStorageInterface,
	metricsStorage storage.MLModelMetricsStorageInterface,
	logger *zap.SugaredLogger,
) *FeedbackCollector {
	return &FeedbackCollector{
		investigationStorage: investigationStorage,
		metricsStorage:       metricsStorage,
		logger:               logger,
	}
}

// RecordFeedback records analyst feedback from a closed investigation
// TASK 29.1: Feedback collection from closed investigations
func (fc *FeedbackCollector) RecordFeedback(ctx context.Context, investigationID string, alertID string, predictedAnomaly bool, predictedScore float64) error {
	// Get investigation to check MLFeedback
	investigation, err := fc.investigationStorage.GetInvestigation(investigationID)
	if err != nil {
		return fmt.Errorf("failed to get investigation: %w", err)
	}

	// Skip if no ML feedback or not marked for training
	if investigation.MLFeedback == nil || !investigation.MLFeedback.UseForTraining {
		return nil // Not an error, just no feedback to record
	}

	// Determine actual label from verdict
	actualAnomaly := investigation.Verdict == core.InvestigationVerdictTruePositive

	// Calculate confusion matrix entry
	confusionEntry := calculateConfusionEntry(predictedAnomaly, actualAnomaly)

	// Record feedback metrics
	err = fc.metricsStorage.RecordFeedback(ctx, alertID, investigationID, predictedScore, predictedAnomaly, actualAnomaly, confusionEntry, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record feedback: %w", err)
	}

	fc.logger.Infow("Recorded ML feedback",
		"investigation_id", investigationID,
		"alert_id", alertID,
		"predicted", predictedAnomaly,
		"actual", actualAnomaly,
		"confusion_entry", confusionEntry)

	return nil
}

// calculateConfusionEntry determines the confusion matrix entry type
func calculateConfusionEntry(predicted, actual bool) string {
	if predicted && actual {
		return "TP" // True Positive
	}
	if predicted && !actual {
		return "FP" // False Positive
	}
	if !predicted && actual {
		return "FN" // False Negative
	}
	return "TN" // True Negative
}

// ModelPerformanceTracker tracks model performance metrics over time
// TASK 29.2: Precision/recall calculation
type ModelPerformanceTracker struct {
	metricsStorage storage.MLModelMetricsStorageInterface
	logger         *zap.SugaredLogger
}

// NewModelPerformanceTracker creates a new performance tracker
func NewModelPerformanceTracker(
	metricsStorage storage.MLModelMetricsStorageInterface,
	logger *zap.SugaredLogger,
) *ModelPerformanceTracker {
	return &ModelPerformanceTracker{
		metricsStorage: metricsStorage,
		logger:         logger,
	}
}

// CalculateMetrics calculates precision, recall, F1, and other metrics for a model
// TASK 29.2: Precision/recall calculation every hour
func (mpt *ModelPerformanceTracker) CalculateMetrics(ctx context.Context, modelName string, windowDuration time.Duration) (*ModelMetrics, error) {
	// Get confusion matrix for time window
	confusionMatrix, err := mpt.metricsStorage.GetConfusionMatrix(ctx, modelName, windowDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to get confusion matrix: %w", err)
	}

	// Calculate derived metrics
	metrics := &ModelMetrics{
		ModelID:        modelName,
		Timestamp:      time.Now(),
		WindowDuration: windowDuration,
		TruePositives:  confusionMatrix.TP,
		TrueNegatives:  confusionMatrix.TN,
		FalsePositives: confusionMatrix.FP,
		FalseNegatives: confusionMatrix.FN,
	}

	// Calculate precision
	if confusionMatrix.TP+confusionMatrix.FP > 0 {
		metrics.Precision = float64(confusionMatrix.TP) / float64(confusionMatrix.TP+confusionMatrix.FP)
	}

	// Calculate recall (sensitivity)
	if confusionMatrix.TP+confusionMatrix.FN > 0 {
		metrics.Recall = float64(confusionMatrix.TP) / float64(confusionMatrix.TP+confusionMatrix.FN)
	}

	// Calculate F1 score
	if metrics.Precision+metrics.Recall > 0 {
		metrics.F1Score = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall)
	}

	// Calculate false positive rate
	if confusionMatrix.FP+confusionMatrix.TN > 0 {
		metrics.FalsePositiveRate = float64(confusionMatrix.FP) / float64(confusionMatrix.FP+confusionMatrix.TN)
	}

	// Calculate false negative rate
	if confusionMatrix.FN+confusionMatrix.TP > 0 {
		metrics.FalseNegativeRate = float64(confusionMatrix.FN) / float64(confusionMatrix.FN+confusionMatrix.TP)
	}

	// Calculate accuracy
	total := confusionMatrix.TP + confusionMatrix.TN + confusionMatrix.FP + confusionMatrix.FN
	if total > 0 {
		metrics.Accuracy = float64(confusionMatrix.TP+confusionMatrix.TN) / float64(total)
	}

	// Store metrics (convert to storage.ModelMetrics)
	storageMetrics := &storage.ModelMetrics{
		ModelID:           metrics.ModelID,
		Timestamp:         metrics.Timestamp,
		WindowDuration:    metrics.WindowDuration,
		TruePositives:     metrics.TruePositives,
		TrueNegatives:     metrics.TrueNegatives,
		FalsePositives:    metrics.FalsePositives,
		FalseNegatives:    metrics.FalseNegatives,
		Precision:         metrics.Precision,
		Recall:            metrics.Recall,
		F1Score:           metrics.F1Score,
		FalsePositiveRate: metrics.FalsePositiveRate,
		FalseNegativeRate: metrics.FalseNegativeRate,
		Accuracy:          metrics.Accuracy,
		DriftScore:        metrics.DriftScore,
		DriftDetected:     metrics.DriftDetected,
	}

	err = mpt.metricsStorage.StoreMetrics(ctx, storageMetrics)
	if err != nil {
		mpt.logger.Warnf("Failed to store metrics: %v", err)
		// Continue even if storage fails
	}

	mpt.logger.Infow("Calculated model metrics",
		"model", modelName,
		"precision", metrics.Precision,
		"recall", metrics.Recall,
		"f1", metrics.F1Score,
		"accuracy", metrics.Accuracy)

	return metrics, nil
}

// ModelMetrics represents performance metrics for an ML model
// TASK 29.2: Model performance metrics structure
type ModelMetrics struct {
	ModelID           string
	Timestamp         time.Time
	WindowDuration    time.Duration
	TruePositives     int64
	TrueNegatives     int64
	FalsePositives    int64
	FalseNegatives    int64
	Precision         float64
	Recall            float64
	F1Score           float64
	FalsePositiveRate float64
	FalseNegativeRate float64
	Accuracy          float64
	DriftScore        float64
	DriftDetected     bool
}

// DriftDetector detects model performance drift
// TASK 29.3: Model drift detection
type DriftDetector struct {
	metricsStorage storage.MLModelMetricsStorageInterface
	logger         *zap.SugaredLogger
	driftThreshold float64 // Default: 0.10 (10% degradation)
}

// NewDriftDetector creates a new drift detector
func NewDriftDetector(
	metricsStorage storage.MLModelMetricsStorageInterface,
	logger *zap.SugaredLogger,
	driftThreshold float64,
) *DriftDetector {
	if driftThreshold <= 0 {
		driftThreshold = 0.10 // Default 10% degradation threshold
	}
	return &DriftDetector{
		metricsStorage: metricsStorage,
		logger:         logger,
		driftThreshold: driftThreshold,
	}
}

// DetectDrift compares current metrics to baseline and detects degradation
// TASK 29.3: Model drift detection using precision/recall degradation
func (dd *DriftDetector) DetectDrift(ctx context.Context, modelName string) (bool, float64, error) {
	// Get baseline metrics (e.g., from 30 days ago)
	baselineWindow := 30 * 24 * time.Hour
	baselineMetrics, err := dd.metricsStorage.GetAverageMetrics(ctx, modelName, baselineWindow, 30*24*time.Hour)
	if err != nil {
		return false, 0, fmt.Errorf("failed to get baseline metrics: %w", err)
	}

	// Get current metrics (last 24 hours)
	currentWindow := 24 * time.Hour
	currentMetrics, err := dd.metricsStorage.GetAverageMetrics(ctx, modelName, currentWindow, currentWindow)
	if err != nil {
		return false, 0, fmt.Errorf("failed to get current metrics: %w", err)
	}

	// Calculate drift score as average degradation in precision and recall
	precisionDrift := (baselineMetrics.Precision - currentMetrics.Precision) / baselineMetrics.Precision
	recallDrift := (baselineMetrics.Recall - currentMetrics.Recall) / baselineMetrics.Recall
	driftScore := (precisionDrift + recallDrift) / 2.0

	driftDetected := driftScore > dd.driftThreshold

	if driftDetected {
		dd.logger.Warnw("Model drift detected",
			"model", modelName,
			"drift_score", driftScore,
			"baseline_precision", baselineMetrics.Precision,
			"current_precision", currentMetrics.Precision,
			"baseline_recall", baselineMetrics.Recall,
			"current_recall", currentMetrics.Recall)
	}

	return driftDetected, driftScore, nil
}

// RetrainingTrigger automatically triggers retraining when drift is detected
// TASK 29.4: Automatic retraining on drift detection
type RetrainingTrigger struct {
	detector      AnomalyDetector
	driftDetector *DriftDetector
	logger        *zap.SugaredLogger
	checkInterval time.Duration // Default: 1 hour
}

// NewRetrainingTrigger creates a new retraining trigger
func NewRetrainingTrigger(
	detector AnomalyDetector,
	driftDetector *DriftDetector,
	logger *zap.SugaredLogger,
) *RetrainingTrigger {
	return &RetrainingTrigger{
		detector:      detector,
		driftDetector: driftDetector,
		logger:        logger,
		checkInterval: 1 * time.Hour,
	}
}

// StartMonitoring starts the drift monitoring loop
// TASK 29.4: Automatic retraining on drift detection
func (rt *RetrainingTrigger) StartMonitoring(ctx context.Context, modelName string) {
	ticker := time.NewTicker(rt.checkInterval)
	defer ticker.Stop()

	rt.logger.Infow("Started drift monitoring", "model", modelName, "interval", rt.checkInterval)

	for {
		select {
		case <-ctx.Done():
			rt.logger.Info("Stopped drift monitoring")
			return
		case <-ticker.C:
			driftDetected, driftScore, err := rt.driftDetector.DetectDrift(ctx, modelName)
			if err != nil {
				rt.logger.Errorf("Failed to detect drift: %v", err)
				continue
			}

			if driftDetected {
				rt.logger.Infow("Drift detected, triggering retraining",
					"model", modelName,
					"drift_score", driftScore)

				// Trigger retraining
				if trainable, ok := rt.detector.(TrainableDetector); ok {
					if err := trainable.ForceRetrain(ctx); err != nil {
						rt.logger.Errorf("Failed to trigger retraining: %v", err)
					} else {
						rt.logger.Info("Retraining triggered successfully")
					}
				} else {
					rt.logger.Warn("Detector does not support retraining")
				}
			}
		}
	}
}

// TrainableDetector is an interface for detectors that support retraining
type TrainableDetector interface {
	AnomalyDetector
	ForceRetrain(ctx context.Context) error
}
