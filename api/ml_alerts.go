package api

import (
	"fmt"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/notify"
	"go.uber.org/zap"
)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	// AlertLevelInfo represents an informational alert
	AlertLevelInfo AlertLevel = "info"
	// AlertLevelWarning represents a warning alert
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelError    AlertLevel = "error"
	AlertLevelCritical AlertLevel = "critical"

	// DefaultHighLatencyThreshold is the default threshold for high latency alerts (1 second)
	DefaultHighLatencyThreshold = 1.0
	// DefaultHighErrorRateThreshold is the default threshold for high error rate alerts (5%)
	DefaultHighErrorRateThreshold = 5.0
	// DefaultLowThroughputThreshold is the default threshold for low throughput alerts (10 req/sec)
	DefaultLowThroughputThreshold = 10.0

	// DefaultLatencyAlertCooldown is the default cooldown period for latency alerts
	DefaultLatencyAlertCooldown = 5 * time.Minute
	// DefaultErrorRateAlertCooldown is the default cooldown period for error rate alerts
	DefaultErrorRateAlertCooldown = 10 * time.Minute
	// DefaultThroughputAlertCooldown is the default cooldown period for throughput alerts
	DefaultThroughputAlertCooldown = 15 * time.Minute

	// DefaultTrainingFailureThreshold is the default threshold for training failures
	DefaultTrainingFailureThreshold = 3.0

	// DefaultAlertChannelBufferSize is the default buffer size for alert channels
	DefaultAlertChannelBufferSize = 100
)

// MLAlert represents an ML system alert
type MLAlert struct {
	ID          string                 `json:"id"`
	Level       AlertLevel             `json:"level"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Component   string                 `json:"component"`
	Metric      string                 `json:"metric"`
	Value       float64                `json:"value"`
	Threshold   float64                `json:"threshold"`
	Timestamp   time.Time              `json:"timestamp"`
	Acked       bool                   `json:"acked"`
	AckedBy     string                 `json:"acked_by,omitempty"`
	AckedAt     *time.Time             `json:"acked_at,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"`
}

// AlertThreshold defines a threshold for triggering alerts
type AlertThreshold struct {
	Name        string        `json:"name"`
	Metric      string        `json:"metric"`
	Condition   string        `json:"condition"` // "gt", "lt", "eq", "ne"
	Value       float64       `json:"value"`
	Level       AlertLevel    `json:"level"`
	Description string        `json:"description"`
	Enabled     bool          `json:"enabled"`
	Cooldown    time.Duration `json:"cooldown"`
}

// MLAlertManager manages ML system alerts
type MLAlertManager struct {
	mu            sync.RWMutex
	alerts        map[string]*MLAlert
	thresholds    []AlertThreshold
	activeAlerts  map[string]*MLAlert
	lastTriggered map[string]time.Time
	logger        *zap.SugaredLogger
	alertChan     chan *MLAlert
	stopChan      chan struct{}
	notifier      *notify.Notifier
}

// NewMLAlertManager creates a new ML alert manager
func NewMLAlertManager(logger *zap.SugaredLogger, notifyConfigs []notify.NotificationConfig) *MLAlertManager {
	manager := &MLAlertManager{
		alerts:        make(map[string]*MLAlert),
		activeAlerts:  make(map[string]*MLAlert),
		lastTriggered: make(map[string]time.Time),
		logger:        logger,
		alertChan:     make(chan *MLAlert, DefaultAlertChannelBufferSize),
		stopChan:      make(chan struct{}),
		notifier:      notify.NewNotifier(notifyConfigs, logger),
	}

	// Set up default thresholds
	manager.thresholds = []AlertThreshold{
		{
			Name:        "high_detection_latency",
			Metric:      "detection_latency_p95",
			Condition:   "gt",
			Value:       DefaultHighLatencyThreshold,
			Level:       AlertLevelWarning,
			Description: "95th percentile detection latency is too high",
			Enabled:     true,
			Cooldown:    DefaultLatencyAlertCooldown,
		},
		{
			Name:        "high_error_rate",
			Metric:      "error_rate_percent",
			Condition:   "gt",
			Value:       DefaultHighErrorRateThreshold,
			Level:       AlertLevelError,
			Description: "ML error rate is too high",
			Enabled:     true,
			Cooldown:    DefaultErrorRateAlertCooldown,
		},
		{
			Name:        "low_throughput",
			Metric:      "throughput_per_second",
			Condition:   "lt",
			Value:       DefaultLowThroughputThreshold,
			Level:       AlertLevelWarning,
			Description: "ML detection throughput is too low",
			Enabled:     true,
			Cooldown:    DefaultThroughputAlertCooldown,
		},
		{
			Name:        "training_failure",
			Metric:      "training_errors_total",
			Condition:   "gt",
			Value:       DefaultTrainingFailureThreshold,
			Level:       AlertLevelError,
			Description: "Multiple training failures detected",
			Enabled:     true,
			Cooldown:    30 * time.Minute,
		},
		{
			Name:        "memory_usage_high",
			Metric:      "memory_usage_percent",
			Condition:   "gt",
			Value:       80.0, // 80%
			Level:       AlertLevelCritical,
			Description: "ML system memory usage is critically high",
			Enabled:     true,
			Cooldown:    5 * time.Minute,
		},
	}

	go manager.alertProcessor()

	return manager
}

// CheckThresholds evaluates metrics against alert thresholds
func (m *MLAlertManager) CheckThresholds(metrics map[string]float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, threshold := range m.thresholds {
		if !threshold.Enabled {
			continue
		}

		value, exists := metrics[threshold.Metric]
		if !exists {
			continue
		}

		// Check cooldown
		lastTriggered, hasLastTriggered := m.lastTriggered[threshold.Name]
		if hasLastTriggered && time.Since(lastTriggered) < threshold.Cooldown {
			continue
		}

		// Check condition
		shouldTrigger := false
		switch threshold.Condition {
		case "gt":
			shouldTrigger = value > threshold.Value
		case "lt":
			shouldTrigger = value < threshold.Value
		case "eq":
			shouldTrigger = value == threshold.Value
		case "ne":
			shouldTrigger = value != threshold.Value
		}

		if shouldTrigger {
			alert := &MLAlert{
				ID:        fmt.Sprintf("%s_%d", threshold.Name, time.Now().Unix()),
				Level:     threshold.Level,
				Title:     fmt.Sprintf("ML Alert: %s", threshold.Name),
				Message:   fmt.Sprintf("%s (%.2f %s)", threshold.Description, value, getMetricUnit(threshold.Metric)),
				Component: "ml_system",
				Metric:    threshold.Metric,
				Value:     value,
				Threshold: threshold.Value,
				Timestamp: time.Now(),
				Labels: map[string]string{
					"alert_name": threshold.Name,
					"metric":     threshold.Metric,
				},
			}

			m.activeAlerts[alert.ID] = alert
			m.lastTriggered[threshold.Name] = time.Now()

			// Send alert asynchronously
			select {
			case m.alertChan <- alert:
			default:
				m.logger.Warnw("Alert channel full, dropping alert", "alert_id", alert.ID)
			}
		}
	}
}

// GetActiveAlerts returns all currently active alerts
func (m *MLAlertManager) GetActiveAlerts() []*MLAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alerts := make([]*MLAlert, 0, len(m.activeAlerts))
	for _, alert := range m.activeAlerts {
		alerts = append(alerts, alert)
	}

	return alerts
}

// AcknowledgeAlert acknowledges an alert
func (m *MLAlertManager) AcknowledgeAlert(alertID, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	now := time.Now()
	alert.Acked = true
	alert.AckedBy = user
	alert.AckedAt = &now

	return nil
}

// ResolveAlert resolves an alert
func (m *MLAlertManager) ResolveAlert(alertID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	now := time.Now()
	alert.Resolved = true
	alert.ResolvedAt = &now

	// Move to resolved alerts
	m.alerts[alertID] = alert
	delete(m.activeAlerts, alertID)

	return nil
}

// GetThresholds returns all configured thresholds
func (m *MLAlertManager) GetThresholds() []AlertThreshold {
	m.mu.RLock()
	defer m.mu.RUnlock()

	thresholds := make([]AlertThreshold, len(m.thresholds))
	copy(thresholds, m.thresholds)

	return thresholds
}

// UpdateThreshold updates a threshold configuration
func (m *MLAlertManager) UpdateThreshold(name string, threshold AlertThreshold) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, t := range m.thresholds {
		if t.Name == name {
			m.thresholds[i] = threshold
			return nil
		}
	}

	return fmt.Errorf("threshold not found: %s", name)
}

// alertProcessor processes alerts from the channel
func (m *MLAlertManager) alertProcessor() {
	for {
		select {
		case alert := <-m.alertChan:
			m.processAlert(alert)
		case <-m.stopChan:
			return
		}
	}
}

// processAlert handles alert processing (logging, notifications, etc.)
func (m *MLAlertManager) processAlert(alert *MLAlert) {
	// Log the alert
	logFields := []interface{}{
		"alert_id", alert.ID,
		"level", string(alert.Level),
		"title", alert.Title,
		"message", alert.Message,
		"component", alert.Component,
		"metric", alert.Metric,
		"value", alert.Value,
		"threshold", alert.Threshold,
	}

	switch alert.Level {
	case AlertLevelCritical:
		m.logger.Errorw("CRITICAL ML ALERT", logFields...)
	case AlertLevelError:
		m.logger.Errorw("ERROR ML ALERT", logFields...)
	case AlertLevelWarning:
		m.logger.Warnw("WARNING ML ALERT", logFields...)
	default:
		m.logger.Infow("INFO ML ALERT", logFields...)
	}

	// Send notifications through configured channels
	if m.notifier != nil {
		coreAlert := m.convertToCoreAlert(alert)
		if err := m.notifier.NotifyAlert(coreAlert); err != nil {
			m.logger.Errorw("Failed to send ML alert notifications",
				"alert_id", alert.ID,
				"error", err)
		}
	}
}

// convertToCoreAlert converts an MLAlert to a core.Alert for notification purposes
func (m *MLAlertManager) convertToCoreAlert(mlAlert *MLAlert) *core.Alert {
	// Map ML alert levels to core alert severity
	severity := "medium" // default
	switch mlAlert.Level {
	case AlertLevelCritical:
		severity = "critical"
	case AlertLevelError:
		severity = "high"
	case AlertLevelWarning:
		severity = "medium"
	case AlertLevelInfo:
		severity = "low"
	}

	// Create a synthetic event for the alert
	event := &core.Event{
		EventID:   mlAlert.ID,
		Timestamp: mlAlert.Timestamp,
		Fields: map[string]interface{}{
			"event_type": "ml_system_alert",
			"source_ip":  "internal",
			"component":  mlAlert.Component,
			"metric":     mlAlert.Metric,
			"value":      mlAlert.Value,
			"threshold":  mlAlert.Threshold,
			"message":    mlAlert.Message,
		},
	}

	// Map alert status
	status := core.AlertStatusPending
	if mlAlert.Resolved {
		status = core.AlertStatusResolved
	} else if mlAlert.Acked {
		status = core.AlertStatusAcknowledged
	}

	return &core.Alert{
		AlertID:         mlAlert.ID,
		RuleID:          fmt.Sprintf("ml_%s", mlAlert.Component),
		RuleName:        mlAlert.Title,
		RuleDescription: mlAlert.Message,
		Severity:        severity,
		Status:          status,
		Timestamp:       mlAlert.Timestamp,
		Event:           event,
	}
}

// getMetricUnit returns the unit for a metric
func getMetricUnit(metric string) string {
	switch metric {
	case "detection_latency_p95", "average_latency":
		return "seconds"
	case "throughput_per_second":
		return "ops/sec"
	case "error_rate_percent", "memory_usage_percent":
		return "%"
	case "training_errors_total", "detection_errors_total":
		return "count"
	default:
		return "value"
	}
}

// Stop stops the alert manager
func (m *MLAlertManager) Stop() {
	close(m.stopChan)
}
