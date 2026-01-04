package detect

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"

	"go.uber.org/zap"
)

// AlertBroadcaster defines the interface for broadcasting alerts to external systems.
// This allows the detector to notify subscribers (e.g., WebSocket clients) when alerts are generated.
// TASK 158: Real-time alert broadcasting for WebSocket integration.
type AlertBroadcaster interface {
	BroadcastAlert(alert *core.Alert)
}

// Detector runs the rule engine on events
// BLOCKING-1 FIX: Added performanceCollector for rule performance tracking
// PARALLEL DETECTION: Uses worker pool for parallel event processing
type Detector struct {
	engine               *RuleEngine
	inputEventCh         <-chan *core.Event
	outputEventCh        chan<- *core.Event
	alertCh              chan<- *core.Alert
	actionExec           *ActionExecutor
	actionCh             chan func()
	actionWorkerCount    int
	detectionWorkerCount int                // Number of parallel detection workers
	detectionWorkCh      chan *core.Event   // Internal channel for distributing work to detection workers
	wg                   sync.WaitGroup
	logger               *zap.SugaredLogger
	stopCh               chan struct{}         // Signal channel for graceful shutdown
	performanceCollector *PerformanceCollector // BLOCKING-1: Performance tracking

	// IOC Detection components
	iocMatcher    *IOCMatcher        // Real-time IOC matching
	iocAlertGen   *IOCAlertGenerator // IOC alert generation
	iocEnricher   *IOCEnricher       // SIGMA alert enrichment with IOC context

	// WebSocket broadcasting
	alertBroadcaster AlertBroadcaster // TASK 158: Real-time alert broadcasting

	// Alert deduplication
	fingerprinter *core.AlertFingerprinter // Generates fingerprints for alert deduplication
}

// NewDetector creates a new Detector with the given configuration.
// TASK 137: Returns error if action executor initialization fails.
// BLOCKING-1 FIX: Now accepts storage parameter for performance tracking initialization
// PARALLEL DETECTION: Configures worker pool based on DetectionWorkerCount config
func NewDetector(engine *RuleEngine, inputEventCh <-chan *core.Event, outputEventCh chan<- *core.Event, alertCh chan<- *core.Alert, cfg *config.Config, logger *zap.SugaredLogger) (*Detector, error) {
	// Build circuit breaker config from YAML configuration
	cbConfig := core.CircuitBreakerConfig{
		MaxFailures:         uint32(cfg.Engine.CircuitBreaker.MaxFailures),
		Timeout:             time.Duration(cfg.Engine.CircuitBreaker.TimeoutSeconds) * time.Second,
		MaxHalfOpenRequests: uint32(cfg.Engine.CircuitBreaker.MaxHalfOpenRequests),
	}

	actionExec, err := NewActionExecutorWithCircuitBreaker(time.Duration(cfg.Engine.ActionTimeout)*time.Second, logger, cbConfig, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create action executor: %w", err)
	}

	// Initialize fingerprinter for alert deduplication
	fingerprintConfig := core.DefaultFingerprintConfig()
	fingerprinter := core.NewAlertFingerprinterWithLogger(fingerprintConfig, logger)

	// PARALLEL DETECTION: Configure worker count with sensible defaults
	detectionWorkerCount := cfg.Engine.DetectionWorkerCount
	if detectionWorkerCount <= 0 {
		detectionWorkerCount = 4 // Default to 4 workers for parallel detection
	}

	// Detection work channel buffer: enough to keep all workers busy without excessive memory
	detectionWorkChSize := detectionWorkerCount * 100

	return &Detector{
		engine:               engine,
		inputEventCh:         inputEventCh,
		outputEventCh:        outputEventCh,
		alertCh:              alertCh,
		actionExec:           actionExec,
		actionCh:             make(chan func(), 100), // buffer for action tasks
		actionWorkerCount:    cfg.Engine.ActionWorkerCount,
		detectionWorkerCount: detectionWorkerCount,
		detectionWorkCh:      make(chan *core.Event, detectionWorkChSize),
		logger:               logger,
		stopCh:               make(chan struct{}), // Initialize stop channel for graceful shutdown
		performanceCollector: nil,                 // BLOCKING-1: Will be set via SetPerformanceCollector if storage available
		fingerprinter:        fingerprinter,       // Alert deduplication fingerprinting
	}, nil
}

// SetPerformanceCollector sets the performance collector for rule performance tracking
// BLOCKING-1 FIX: Allows injection of performance collector after creation
// This is called from bootstrap after storage is initialized
func (d *Detector) SetPerformanceCollector(collector *PerformanceCollector) {
	d.performanceCollector = collector
}

// SetIOCComponents sets the IOC detection components
// This is called from bootstrap after IOC storage is initialized
func (d *Detector) SetIOCComponents(matcher *IOCMatcher, alertGen *IOCAlertGenerator, enricher *IOCEnricher) {
	d.iocMatcher = matcher
	d.iocAlertGen = alertGen
	d.iocEnricher = enricher
	if matcher != nil {
		d.logger.Info("IOC detection components initialized")
	}
}

// SetHealthRecorder sets the health recorder for correlation rule health metrics.
// TASK 225.3: Health dashboard integration
// This is called from bootstrap after the health service is initialized.
func (d *Detector) SetHealthRecorder(recorder HealthRecorder) {
	if d.engine != nil {
		d.engine.SetHealthRecorder(recorder)
	}
}

// SetAlertBroadcaster sets the alert broadcaster for real-time alert notifications.
// TASK 158: WebSocket integration for real-time alerts.
// This is called from bootstrap after the WebSocket hub is initialized.
func (d *Detector) SetAlertBroadcaster(broadcaster AlertBroadcaster) {
	d.alertBroadcaster = broadcaster
	if broadcaster != nil {
		d.logger.Info("Alert broadcaster initialized for real-time notifications")
	}
}

// Start starts the detector
// PARALLEL DETECTION: Launches distributor + N detection workers + action workers
func (d *Detector) Start() {
	// Start the distributor that reads from input channel and distributes to workers
	d.wg.Add(1)
	go d.runDistributor()

	// Start detection workers - each processes events in parallel
	for i := 0; i < d.detectionWorkerCount; i++ {
		d.wg.Add(1)
		go d.detectionWorker(i)
	}

	// Start action workers
	for i := 0; i < d.actionWorkerCount; i++ {
		d.wg.Add(1)
		go d.actionWorker()
	}

	d.logger.Infow("Detector started with parallel detection",
		"detection_workers", d.detectionWorkerCount,
		"action_workers", d.actionWorkerCount,
		"detection_queue_size", cap(d.detectionWorkCh))
}

// actionWorker processes action tasks
func (d *Detector) actionWorker() {
	defer d.wg.Done()
	for task := range d.actionCh {
		task()
	}
}

// processRuleMatches processes matching rules and sends alerts
// ruleType should be one of core.RuleTypeSigma, core.RuleTypeCorrelation, etc.
func (d *Detector) processRuleMatches(rules []core.AlertableRule, event *core.Event, ruleType string) {
	for _, rule := range rules {
		// Build metadata from rule
		metadata := &core.AlertMetadata{
			RuleName:        rule.GetName(),
			RuleDescription: rule.GetDescription(),
			RuleType:        ruleType,
			ConfidenceScore: 75, // Default confidence for rule matches
		}

		// Try to get additional metadata if rule is a core.Rule
		if sigmaRule, ok := rule.(core.Rule); ok {
			metadata.Category = core.DeriveCategory(sigmaRule.LogsourceCategory, sigmaRule.LogsourceProduct, sigmaRule.Tags)
			metadata.MitreTechniques = sigmaRule.MitreTechniques
			// Derive source from logsource product
			if sigmaRule.LogsourceProduct != "" {
				metadata.Source = sigmaRule.LogsourceProduct
			}
		}

		alert, err := core.NewAlertWithMetadata(rule.GetID(), event.EventID, rule.GetSeverity(), event, metadata)
		if err != nil {
			d.logger.Errorf("Failed to create alert for rule %s: %v", rule.GetID(), err)
			continue
		}

		// Generate fingerprint for alert deduplication
		// The fingerprint is based on stable event fields (not event_id) to detect duplicate alerts
		if d.fingerprinter != nil {
			alert.Fingerprint = d.fingerprinter.GenerateFingerprint(alert)
		}

		metrics.AlertsGenerated.WithLabelValues(alert.Severity).Inc()
		select {
		case d.alertCh <- alert:
			// Capture rule and alert in closure to avoid race conditions
			ruleCapture := rule
			alertCapture := alert

			// TASK 158: Broadcast alert to WebSocket clients for real-time updates
			if d.alertBroadcaster != nil {
				d.alertBroadcaster.BroadcastAlert(alertCapture)
			}

			// Execute actions asynchronously via worker pool
			select {
			case d.actionCh <- func() {
				defer func() {
					if r := recover(); r != nil {
						d.logger.Errorf("Panic in action execution: %v", r)
					}
				}()
				// Create context with timeout for action execution
				// This ensures actions complete within reasonable time
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := d.actionExec.ExecuteActions(ctx, ruleCapture, alertCapture); err != nil {
					d.logger.Errorf("Action execution failed: %v", err)
				}
			}:
			default:
				d.logger.Warn("Action queue full, dropping action")
			}
		default:
			d.logger.Warnf("Dropped alert for rule %s due to full alert channel", rule.GetID())
		}
	}
}

// runDistributor reads events from input channel and distributes to detection workers
// PARALLEL DETECTION: This goroutine handles event distribution without processing
func (d *Detector) runDistributor() {
	defer d.wg.Done()
	defer close(d.detectionWorkCh) // Signal workers to stop when distributor exits
	defer close(d.actionCh)        // Close action channel when distributor exits

	d.logger.Info("Detection distributor started - distributing events to workers")

	eventCount := 0
	for {
		select {
		case <-d.stopCh:
			d.logger.Infof("DETECTOR: Distributor stop signal received after distributing %d events", eventCount)
			return
		case event, ok := <-d.inputEventCh:
			if !ok {
				d.logger.Warnf("DETECTOR: Distributor stopped after distributing %d events (input channel closed)", eventCount)
				return
			}

			eventCount++

			// Update queue depth metric before sending
			metrics.DetectionQueueDepth.Set(float64(len(d.detectionWorkCh)))

			// Try to send to detection workers, drop if queue is full
			select {
			case d.detectionWorkCh <- event:
				// Event queued for processing
			default:
				// Queue full - drop event and log warning
				metrics.DetectionQueueDropped.Inc()
				d.logger.Warnf("DETECTOR: Dropped event %s due to full detection queue (depth=%d)",
					event.EventID, cap(d.detectionWorkCh))
			}
		}
	}
}

// detectionWorker processes events in parallel with other workers
// PARALLEL DETECTION: Each worker evaluates rules independently
func (d *Detector) detectionWorker(workerID int) {
	defer d.wg.Done()

	workerIDStr := fmt.Sprintf("%d", workerID)
	d.logger.Infof("Detection worker %d started", workerID)

	eventCount := 0
	for event := range d.detectionWorkCh {
		eventCount++
		start := time.Now()

		// OBSERVABILITY: Log every event received for debugging detection pipeline
		d.logger.Debugf("DETECTOR[%d]: Processing event %d: ID=%s, Type=%s",
			workerID, eventCount, event.EventID, event.EventType)

		// Evaluate SIGMA and correlation rules
		matchingRules := d.engine.Evaluate(event)
		matchingCorrelationRules := d.engine.EvaluateCorrelation(event)
		duration := time.Since(start)

		// Update metrics
		metrics.EventProcessingDuration.Observe(duration.Seconds())
		metrics.DetectionWorkerEventsProcessed.WithLabelValues(workerIDStr).Inc()
		metrics.DetectionWorkerProcessingDuration.WithLabelValues(workerIDStr).Observe(duration.Seconds())

		// BLOCKING-1 FIX: Record rule evaluation performance
		if d.performanceCollector != nil {
			durationMs := duration.Seconds() * 1000.0
			loadedRules := d.engine.GetLoadedRules()
			if len(loadedRules) > 0 {
				perRuleDuration := durationMs / float64(len(loadedRules))
				for _, rule := range loadedRules {
					matched := false
					for _, matchedRule := range matchingRules {
						if matchedRule.GetID() == rule.ID {
							matched = true
							break
						}
					}
					d.performanceCollector.RecordEvaluation(rule.ID, perRuleDuration, matched)
				}
			}
		}

		// OBSERVABILITY: Log rule evaluation results
		if len(matchingRules) > 0 || len(matchingCorrelationRules) > 0 {
			d.logger.Infof("DETECTOR[%d]: Event %s - %d standard matches, %d correlation matches (duration=%v)",
				workerID, event.EventID, len(matchingRules), len(matchingCorrelationRules), duration)
		}

		if len(matchingRules) > 0 {
			for _, rule := range matchingRules {
				d.logger.Debugf("DETECTOR[%d]: Rule match: %s (severity=%s)", workerID, rule.GetID(), rule.GetSeverity())
			}
		}

		if len(matchingCorrelationRules) > 0 {
			for _, rule := range matchingCorrelationRules {
				d.logger.Debugf("DETECTOR[%d]: Correlation match: %s (severity=%s)", workerID, rule.GetID(), rule.GetSeverity())
			}
		}

		// Process matches and generate alerts
		d.processRuleMatches(matchingRules, event, core.RuleTypeSigma)
		d.processRuleMatches(matchingCorrelationRules, event, core.RuleTypeCorrelation)

		// IOC Detection: Check event against IOC database
		if d.iocMatcher != nil && d.iocMatcher.IsEnabled() {
			ctx := context.Background()
			iocMatches, err := d.iocMatcher.Match(ctx, event.Fields)
			if err != nil {
				d.logger.Errorf("IOC matching failed: %v", err)
			} else if len(iocMatches) > 0 {
				d.logger.Infof("DETECTOR[%d]: Event %s matched %d IOCs", workerID, event.EventID, len(iocMatches))

				// Generate standalone IOC alert
				if d.iocAlertGen != nil {
					iocAlert := d.iocAlertGen.GenerateAlert(ctx, event, iocMatches)
					if iocAlert != nil {
						select {
						case d.alertCh <- iocAlert:
							metrics.AlertsGenerated.WithLabelValues(iocAlert.Severity).Inc()
							d.logger.Debugf("DETECTOR[%d]: IOC alert generated for event %s", workerID, event.EventID)
						default:
							d.logger.Warnf("DETECTOR[%d]: Dropped IOC alert for event %s due to full alert channel", workerID, event.EventID)
						}
					}
				}

				// Enrich any SIGMA/correlation alerts with IOC context
				if d.iocEnricher != nil {
					d.iocEnricher.EnrichAlertWithEvent(ctx, nil) // TODO: Track generated alerts for enrichment
				}
			}
		}

		// Forward event to storage
		select {
		case d.outputEventCh <- event:
			d.logger.Debugf("DETECTOR[%d]: Event %s forwarded to storage", workerID, event.EventID)
		default:
			d.logger.Warnf("DETECTOR[%d]: Dropped event %s due to full output channel", workerID, event.EventID)
		}
	}

	d.logger.Infof("Detection worker %d stopped after processing %d events", workerID, eventCount)
}

// ReloadRules reloads detection rules dynamically without restart
// PRODUCTION: Enables hot-reload of rules created/updated via API
// ERROR HANDLING: Returns error instead of silent failure for proper error propagation
func (d *Detector) ReloadRules(rules []core.Rule) error {
	if d.engine == nil {
		return fmt.Errorf("cannot reload rules: engine is nil")
	}
	d.engine.ReloadRules(rules)
	d.logger.Infof("DETECTOR: Reloaded %d rules into detection engine", len(rules))
	return nil
}

// ReloadCorrelationRules reloads correlation rules dynamically without restart
// PRODUCTION: Enables hot-reload of correlation rules created/updated via API
// ERROR HANDLING: Returns error instead of silent failure for proper error propagation
func (d *Detector) ReloadCorrelationRules(rules []core.CorrelationRule) error {
	if d.engine == nil {
		return fmt.Errorf("cannot reload correlation rules: engine is nil")
	}
	d.engine.ReloadCorrelationRules(rules)
	d.logger.Infof("DETECTOR: Reloaded %d correlation rules into detection engine", len(rules))
	return nil
}

// Stop stops the detector gracefully
// It signals the run() goroutine to stop, waits for all goroutines to finish,
// then cleans up the engine and action executor resources.
// BLOCKING-1 FIX: Added timeout to WaitGroup.Wait() to prevent indefinite blocking
// CRITICAL-1 FIX: Added collector.Flush() call before shutdown
func (d *Detector) Stop() {
	// Signal the run() goroutine to stop by closing the stop channel
	// This allows graceful shutdown even if inputEventCh is never closed
	close(d.stopCh)

	// Wait for all detector goroutines (run + actionWorkers) to finish with timeout
	// BLOCKING-1 FIX: Use timeout pattern to prevent goroutine leak
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		d.logger.Info("Detector stopped successfully")
	case <-time.After(30 * time.Second):
		d.logger.Warn("Detector shutdown timed out after 30s - some goroutines may still be running")
	}

	// CRITICAL-1 FIX: Flush pending performance stats before shutdown
	if d.performanceCollector != nil {
		if err := d.performanceCollector.Flush(); err != nil {
			d.logger.Warnf("Failed to flush performance stats during shutdown: %v", err)
		} else {
			d.logger.Info("Performance stats flushed successfully")
		}
	}

	// Stop the rule engine (cancels correlation cleanup goroutines)
	d.engine.Stop()

	// Stop the action executor cleanup goroutine
	d.actionExec.Stop()
}
