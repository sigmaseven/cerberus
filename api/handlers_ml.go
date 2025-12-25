package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/ml"
)

const (
	// MinSampleCountThreshold is the minimum number of samples required for training
	MinSampleCountThreshold = 100
	// MaxTrainingIntervalHours is the maximum training interval in hours
	MaxTrainingIntervalHours = 24
	// TrainingIntervalCheckHours is the duration to check for training intervals
	TrainingIntervalCheckHours = 24 * time.Hour
)

// MLAnomalyDetector interface for ML anomaly detection
type MLAnomalyDetector interface {
	ProcessEvent(ctx context.Context, event *core.Event) (interface{}, error)
	GetStatus() ml.TrainingPipelineStatus
	ForceTraining(ctx context.Context) error
	Reset() error
}

// MLConfigManager interface for ML configuration
type MLConfigManager interface {
	GetMLConfig() (*MLAPIConfig, error)
	UpdateMLConfig(config *MLAPIConfig) error
}

// MLAPIConfig holds ML API configuration
type MLAPIConfig struct {
	Enabled          bool               `json:"enabled"`
	BatchSize        int                `json:"batch_size"`
	TrainingInterval string             `json:"training_interval"`
	RetrainThreshold int                `json:"retrain_threshold"`
	ValidationRatio  float64            `json:"validation_ratio"`
	EnableContinuous bool               `json:"enable_continuous"`
	DriftDetection   bool               `json:"drift_detection"`
	MinConfidence    float64            `json:"min_confidence"`
	Algorithms       []string           `json:"algorithms"`
	VotingStrategy   string             `json:"voting_strategy"`
	Weights          map[string]float64 `json:"weights"`
}

// MLAnomalyRequest represents a request for anomaly detection
type MLAnomalyRequest struct {
	EventID   string                 `json:"event_id,omitempty" validate:"omitempty,max=100"`
	EventData map[string]interface{} `json:"event_data" validate:"required"`
}

// MLAnomalyResponse represents the response from anomaly detection
type MLAnomalyResponse struct {
	EventID          string                       `json:"event_id"`
	IsAnomaly        bool                         `json:"is_anomaly"`
	Score            float64                      `json:"score"`
	Confidence       float64                      `json:"confidence"`
	Algorithm        string                       `json:"algorithm"`
	AlgorithmResults map[string]*ml.AnomalyResult `json:"algorithm_results"`
	VotingStrategy   string                       `json:"voting_strategy"`
	ConsensusLevel   float64                      `json:"consensus_level"`
	DetectedAt       time.Time                    `json:"detected_at"`
	ProcessingTime   time.Duration                `json:"processing_time"`
}

// MLHealthStatus represents the overall health status of the ML system
type MLHealthStatus struct {
	Status    string                 `json:"status"` // "healthy", "degraded", "unhealthy"
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]HealthCheck `json:"checks,omitempty"`
}

// HealthCheck represents an individual health check result
type HealthCheck struct {
	Status  string    `json:"status"` // "pass", "fail", "warn"
	Message string    `json:"message,omitempty"`
	Details string    `json:"details,omitempty"`
	Time    time.Time `json:"time"`
}

// MLDetailedHealthResponse represents detailed health information
type MLDetailedHealthResponse struct {
	Status             string                 `json:"status"`
	Message            string                 `json:"message,omitempty"`
	Timestamp          time.Time              `json:"timestamp"`
	Uptime             time.Duration          `json:"uptime"`
	Version            string                 `json:"version"`
	Checks             map[string]HealthCheck `json:"checks"`
	PerformanceMetrics MLPerformanceMetrics   `json:"performance_metrics"`
	SystemResources    MLSystemResources      `json:"system_resources"`
}

// MLPerformanceMetrics contains performance-related health metrics
type MLPerformanceMetrics struct {
	DetectionLatency LatencyStats    `json:"detection_latency"`
	TrainingDuration LatencyStats    `json:"training_duration"`
	Throughput       ThroughputStats `json:"throughput"`
	ErrorRates       ErrorRateStats  `json:"error_rates"`
	MemoryUsage      MemoryStats     `json:"memory_usage"`
}

// LatencyStats contains latency statistics
type LatencyStats struct {
	Average time.Duration `json:"average"`
	P95     time.Duration `json:"p95"`
	P99     time.Duration `json:"p99"`
	Max     time.Duration `json:"max"`
}

// ThroughputStats contains throughput statistics
type ThroughputStats struct {
	Current float64 `json:"current_per_second"`
	Average float64 `json:"average_per_second"`
	Peak    float64 `json:"peak_per_second"`
}

// ErrorRateStats contains error rate statistics
type ErrorRateStats struct {
	DetectionErrors float64 `json:"detection_errors_percent"`
	TrainingErrors  float64 `json:"training_errors_percent"`
	CacheErrors     float64 `json:"cache_errors_percent"`
}

// MemoryStats contains memory usage statistics
type MemoryStats struct {
	UsedMB      float64 `json:"used_mb"`
	AvailableMB float64 `json:"available_mb"`
	Utilization float64 `json:"utilization_percent"`
}

// MLSystemResources contains system resource information
type MLSystemResources struct {
	CPUUsage         float64 `json:"cpu_usage_percent"`
	MemoryUsage      float64 `json:"memory_usage_percent"`
	DiskUsage        float64 `json:"disk_usage_percent"`
	ActiveGoroutines int     `json:"active_goroutines"`
}

// MLStatusResponse represents ML system status
type MLStatusResponse struct {
	Enabled            bool                     `json:"enabled"`
	IsRunning          bool                     `json:"is_running"`
	SampleCount        int64                    `json:"sample_count"`
	BufferSize         int                      `json:"buffer_size"`
	LastTraining       time.Time                `json:"last_training"`
	PerformanceHistory []ml.TrainingPerformance `json:"performance_history"`
	Config             *MLAPIConfig             `json:"config"`
}

// TASK 138: Removed unused detectAnomaly handler (route was never registered)

// getMLStatus godoc
//
//	@Summary		Get ML system status
//	@Description	Returns current status and statistics of the ML anomaly detection system
//	@Tags			ml
//	@Produce		json
//	@Success		200	{object}	MLStatusResponse
//	@Failure		500	{object}	map[string]string
//	@Router			/api/v1/ml/status [get]
func (a *API) getMLStatus(w http.ResponseWriter, r *http.Request) {
	// If ML is disabled, return status indicating it's not enabled
	if a.mlManager == nil || a.mlManager.detector == nil {
		a.respondJSON(w, &MLStatusResponse{
			Enabled:            false,
			IsRunning:          false,
			SampleCount:        0,
			BufferSize:         0,
			LastTraining:       time.Time{},
			PerformanceHistory: nil,
			Config:             &MLAPIConfig{Enabled: false},
		}, http.StatusOK)
		return
	}

	status := a.mlManager.detector.GetStatus()

	// Get current config
	config, err := a.mlManager.configManager.GetMLConfig()
	if err != nil {
		a.logger.Warnw("Failed to get ML config", "error", err)
		config = &MLAPIConfig{Enabled: false}
	}

	response := &MLStatusResponse{
		Enabled:            true, // If we reach here, ML is enabled
		IsRunning:          status.IsRunning,
		SampleCount:        status.SampleCount,
		BufferSize:         status.BufferSize,
		LastTraining:       status.LastTraining,
		PerformanceHistory: status.PerformanceHistory,
		Config:             config,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// forceTraining godoc
//
//	@Summary		Force ML model training
//	@Description	Manually trigger ML model training with current data
//	@Tags			ml
//	@Produce		json
//	@Success		200	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Router			/api/v1/ml/train [post]
func (a *API) forceTraining(w http.ResponseWriter, r *http.Request) {
	if a.mlManager == nil || a.mlManager.detector == nil {
		a.respondJSON(w, map[string]string{"error": "ML system not initialized"}, http.StatusServiceUnavailable)
		return
	}

	start := time.Now()
	err := a.mlManager.detector.ForceTraining(r.Context())
	duration := time.Since(start)

	// Record metrics
	if a.mlManager.metrics != nil {
		a.mlManager.metrics.RecordTraining(duration, err != nil)
	}

	if err != nil {
		a.logger.Errorw("Forced training failed", "error", err)
		// Check if this is an insufficient data error
		if strings.Contains(err.Error(), "insufficient training samples") {
			a.respondJSON(w, map[string]string{"error": err.Error(), "code": "INSUFFICIENT_DATA"}, http.StatusUnprocessableEntity)
		} else {
			a.respondJSON(w, map[string]string{"error": "Training failed: " + err.Error()}, http.StatusInternalServerError)
		}
		return
	}

	a.respondJSON(w, map[string]string{"message": "Training completed successfully"}, http.StatusOK)
}

// getMLHealth godoc
//
//	@Summary		Get ML system health
//	@Description	Returns detailed health information about the ML anomaly detection system
//	@Tags			ml
//	@Produce		json
//	@Success		200	{object}	MLDetailedHealthResponse
//	@Failure		503	{object}	map[string]string
//	@Router			/api/v1/ml/health [get]
func (a *API) getMLHealth(w http.ResponseWriter, r *http.Request) {
	if a.mlManager == nil || a.mlManager.detector == nil {
		// Return disabled status instead of error
		timestamp := time.Now()
		response := &MLDetailedHealthResponse{
			Status:    "disabled",
			Message:   "ML system is not enabled",
			Timestamp: timestamp,
			Checks: map[string]HealthCheck{
				"ml_enabled": {
					Status:  "disabled",
					Message: "ML system is not enabled in configuration",
					Time:    timestamp,
				},
			},
			PerformanceMetrics: MLPerformanceMetrics{},
			SystemResources:    MLSystemResources{},
		}
		a.respondJSON(w, response, http.StatusOK)
		return
	}

	status := a.mlManager.detector.GetStatus()

	// Get performance metrics
	var perfMetrics MLPerformanceMetrics
	if a.mlManager.metrics != nil {
		avgLatency, p95Latency, throughput, errorRate := a.mlManager.metrics.GetPerformanceMetrics()
		perfMetrics = MLPerformanceMetrics{
			DetectionLatency: LatencyStats{
				Average: time.Duration(avgLatency * float64(time.Millisecond)),
				P95:     time.Duration(p95Latency * float64(time.Millisecond)),
				Max:     time.Duration(p95Latency * float64(time.Millisecond)), // Using p95 as approximation
			},
			TrainingDuration: LatencyStats{
				Average: time.Duration(avgLatency * float64(time.Millisecond)), // Approximation
				Max:     time.Duration(p95Latency * float64(time.Millisecond)),
			},
			Throughput: ThroughputStats{
				Current: throughput,
				Average: throughput,
				Peak:    throughput,
			},
			ErrorRates: ErrorRateStats{
				DetectionErrors: errorRate * 100,
			},
		}
	}

	// Get system resources (simplified for now)
	systemResources := MLSystemResources{
		MemoryUsage: 0, // TODO: Implement actual memory monitoring
		DiskUsage:   0,
	}

	// Determine overall health status
	overallStatus := "healthy"
	message := "ML system is operating normally"
	timestamp := time.Now()

	// Check for issues
	if !status.IsRunning {
		overallStatus = "degraded"
		message = "ML system is not running"
	} else if status.SampleCount < 100 {
		overallStatus = "warning"
		message = "ML system has insufficient training samples"
	}

	checks := map[string]HealthCheck{
		"ml_system": {
			Status:  overallStatus,
			Message: message,
			Time:    timestamp,
		},
		"training_pipeline": {
			Status: func() string {
				if status.IsRunning {
					return "healthy"
				}
				return "unhealthy"
			}(),
			Message: func() string {
				if status.IsRunning {
					return "Training pipeline is active"
				}
				return "Training pipeline is inactive"
			}(),
			Time: timestamp,
		},
		"model_performance": {
			Status: func() string {
				if status.SampleCount > 100 {
					return "healthy"
				}
				return "warning"
			}(),
			Message: fmt.Sprintf("Model trained on %d samples", status.SampleCount),
			Time:    timestamp,
		},
	}

	response := &MLDetailedHealthResponse{
		Status:             overallStatus,
		Message:            message,
		Timestamp:          timestamp,
		Checks:             checks,
		PerformanceMetrics: perfMetrics,
		SystemResources:    systemResources,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// getMLPerformanceHistory godoc
//
//	@Summary		Get ML performance history
//	@Description	Returns historical performance metrics for the ML anomaly detection system
//	@Tags			ml
//	@Produce		json
//	@Success		200	{array}	ml.TrainingPerformance
//	@Failure		503	{object}	map[string]string
//	@Router			/api/v1/ml/performance [get]
func (a *API) getMLPerformanceHistory(w http.ResponseWriter, r *http.Request) {
	if a.mlManager == nil || a.mlManager.detector == nil {
		// Return empty array instead of error when ML is disabled
		a.respondJSON(w, []interface{}{}, http.StatusOK)
		return
	}

	status := a.mlManager.detector.GetStatus()
	a.respondJSON(w, status.PerformanceHistory, http.StatusOK)
}

// TASK 138: Removed unused resetML handler (route was never registered)

// getMLConfig godoc
//
//	@Summary		Get ML configuration
//	@Description	Returns current ML system configuration
//	@Tags			ml
//	@Produce		json
//	@Success		200	{object}	MLAPIConfig
//	@Failure		500	{object}	map[string]string
//	@Router			/api/v1/ml/config [get]
func (a *API) getMLConfig(w http.ResponseWriter, r *http.Request) {
	if a.mlManager == nil || a.mlManager.configManager == nil {
		a.respondJSON(w, map[string]string{"error": "ML config manager not initialized"}, http.StatusServiceUnavailable)
		return
	}

	config, err := a.mlManager.configManager.GetMLConfig()
	if err != nil {
		a.logger.Errorw("Failed to get ML config", "error", err)
		a.respondJSON(w, map[string]string{"error": "Failed to get configuration"}, http.StatusInternalServerError)
		return
	}

	a.respondJSON(w, config, http.StatusOK)
}

// updateMLConfig godoc
//
//	@Summary		Update ML configuration
//	@Description	Update ML system configuration
//	@Tags			ml
//	@Accept			json
//	@Produce		json
//	@Param			config	body		MLAPIConfig	true	"ML configuration"
//	@Success		200		{object}	map[string]string
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/ml/config [put]
func (a *API) updateMLConfig(w http.ResponseWriter, r *http.Request) {
	if a.mlManager == nil || a.mlManager.configManager == nil {
		a.respondJSON(w, map[string]string{"error": "ML config manager not initialized"}, http.StatusServiceUnavailable)
		return
	}

	var config MLAPIConfig
	if err := a.decodeJSONBody(w, r, &config); err != nil {
		a.respondJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}

	// Validate numeric configuration values
	if err := validateMLConfig(&config); err != nil {
		a.respondJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}

	if err := a.mlManager.configManager.UpdateMLConfig(&config); err != nil {
		a.logger.Errorw("Failed to update ML config", "error", err)
		a.respondJSON(w, map[string]string{"error": "Failed to update configuration"}, http.StatusInternalServerError)
		return
	}

	a.logger.Infow("ML configuration updated", "config", config)
	a.respondJSON(w, map[string]string{"message": "Configuration updated successfully"}, http.StatusOK)
}

// validateMLConfig validates ML API configuration values
func validateMLConfig(config *MLAPIConfig) error {
	// Validate batch size
	if config.BatchSize <= 0 {
		return fmt.Errorf("batch_size must be positive")
	}
	if config.BatchSize > 100000 {
		return fmt.Errorf("batch_size too large: %d (max 100000)", config.BatchSize)
	}

	// Validate retrain threshold
	if config.RetrainThreshold <= 0 {
		return fmt.Errorf("retrain_threshold must be positive")
	}
	if config.RetrainThreshold > 1000000 {
		return fmt.Errorf("retrain_threshold too large: %d (max 1000000)", config.RetrainThreshold)
	}

	// Validate validation ratio
	if config.ValidationRatio < 0 || config.ValidationRatio > 1 {
		return fmt.Errorf("validation_ratio must be between 0 and 1")
	}

	// Validate min confidence
	if config.MinConfidence < 0 || config.MinConfidence > 1 {
		return fmt.Errorf("min_confidence must be between 0 and 1")
	}

	// Validate weights if provided
	if config.Weights != nil {
		for algo, weight := range config.Weights {
			if weight < 0 || weight > 1 {
				return fmt.Errorf("weight for algorithm %s must be between 0 and 1", algo)
			}
		}
	}

	// Validate voting strategy
	validStrategies := map[string]bool{
		"majority":  true,
		"unanimous": true,
		"weighted":  true,
		"average":   true,
	}
	if config.VotingStrategy != "" && !validStrategies[config.VotingStrategy] {
		return fmt.Errorf("invalid voting_strategy: %s (must be majority, unanimous, weighted, or average)", config.VotingStrategy)
	}

	return nil
}

// TASK 138: Removed unused health check helper functions (addHealthCheck, checkTrainingPipelineHealth,
// checkRecentTrainingHealth, checkSampleCountHealth) - never called by getMLHealth
