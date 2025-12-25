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

// Detector runs the rule engine on events
// BLOCKING-1 FIX: Added performanceCollector for rule performance tracking
type Detector struct {
	engine               *RuleEngine
	inputEventCh         <-chan *core.Event
	outputEventCh        chan<- *core.Event
	alertCh              chan<- *core.Alert
	actionExec           *ActionExecutor
	actionCh             chan func()
	actionWorkerCount    int
	wg                   sync.WaitGroup
	logger               *zap.SugaredLogger
	stopCh               chan struct{}               // Signal channel for graceful shutdown
	performanceCollector *PerformanceCollector       // BLOCKING-1: Performance tracking
}

// NewDetector creates a new Detector with the given configuration.
// TASK 137: Returns error if action executor initialization fails.
// BLOCKING-1 FIX: Now accepts storage parameter for performance tracking initialization
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

	return &Detector{
		engine:               engine,
		inputEventCh:         inputEventCh,
		outputEventCh:        outputEventCh,
		alertCh:              alertCh,
		actionExec:           actionExec,
		actionCh:             make(chan func(), 100), // buffer for action tasks
		actionWorkerCount:    cfg.Engine.ActionWorkerCount,
		logger:               logger,
		stopCh:               make(chan struct{}), // Initialize stop channel for graceful shutdown
		performanceCollector: nil,                 // BLOCKING-1: Will be set via SetPerformanceCollector if storage available
	}, nil
}

// SetPerformanceCollector sets the performance collector for rule performance tracking
// BLOCKING-1 FIX: Allows injection of performance collector after creation
// This is called from bootstrap after storage is initialized
func (d *Detector) SetPerformanceCollector(collector *PerformanceCollector) {
	d.performanceCollector = collector
}

// Start starts the detector
func (d *Detector) Start() {
	d.wg.Add(1)
	go d.run()
	// Start action workers
	for i := 0; i < d.actionWorkerCount; i++ {
		d.wg.Add(1)
		go d.actionWorker()
	}
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
		metrics.AlertsGenerated.WithLabelValues(alert.Severity).Inc()
		select {
		case d.alertCh <- alert:
			// Execute actions asynchronously via worker pool
			// Capture rule and alert in closure to avoid race conditions
			ruleCapture := rule
			alertCapture := alert
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

// run processes events
func (d *Detector) run() {
	defer d.wg.Done()
	defer close(d.actionCh)

	// OBSERVABILITY: Log detector startup with channel info for debugging
	d.logger.Infof("Detector started - waiting for events on input channel")

	eventCount := 0
	for {
		select {
		case <-d.stopCh:
			// Graceful shutdown requested
			d.logger.Infof("DETECTOR: Stop signal received after processing %d events", eventCount)
			return
		case event, ok := <-d.inputEventCh:
			if !ok {
				// Input channel closed
				d.logger.Warnf("DETECTOR: Stopped after processing %d events (input channel closed)", eventCount)
				return
			}

			eventCount++

			// OBSERVABILITY: Log every event received for debugging detection pipeline
			d.logger.Infof("DETECTOR: Processing event %d: ID=%s, Type=%s, Timestamp=%v",
				eventCount, event.EventID, event.EventType, event.Timestamp)

			start := time.Now()
			matchingRules := d.engine.Evaluate(event)
			matchingCorrelationRules := d.engine.EvaluateCorrelation(event)
			duration := time.Since(start)
			metrics.EventProcessingDuration.Observe(duration.Seconds())

			// BLOCKING-1 FIX: Record rule evaluation performance
			if d.performanceCollector != nil {
				durationMs := duration.Seconds() * 1000.0
				// Record each rule evaluation
				for _, rule := range d.engine.GetLoadedRules() {
					matched := false
					for _, matchedRule := range matchingRules {
						if matchedRule.GetID() == rule.ID {
							matched = true
							break
						}
					}
					d.performanceCollector.RecordEvaluation(rule.ID, durationMs/float64(len(d.engine.GetLoadedRules())), matched)
				}
			}

			// OBSERVABILITY: Log rule evaluation results
			d.logger.Infof("DETECTOR: Event %s evaluated - %d standard rule matches, %d correlation matches (duration=%v)",
				event.EventID, len(matchingRules), len(matchingCorrelationRules), duration)

			if len(matchingRules) > 0 {
				d.logger.Infof("DETECTOR: Event %s matched %d standard rules", event.EventID, len(matchingRules))
				for _, rule := range matchingRules {
					d.logger.Infof("DETECTOR: - Rule match: %s (severity=%s)", rule.GetID(), rule.GetSeverity())
				}
			}

			if len(matchingCorrelationRules) > 0 {
				d.logger.Infof("DETECTOR: Event %s matched %d correlation rules", event.EventID, len(matchingCorrelationRules))
				for _, rule := range matchingCorrelationRules {
					d.logger.Infof("DETECTOR: - Correlation rule match: %s (severity=%s)", rule.GetID(), rule.GetSeverity())
				}
			}

			d.processRuleMatches(matchingRules, event, core.RuleTypeSigma)
			d.processRuleMatches(matchingCorrelationRules, event, core.RuleTypeCorrelation)

			// Forward event to storage
			select {
			case d.outputEventCh <- event:
				d.logger.Debugf("DETECTOR: Event %s forwarded to storage", event.EventID)
			default:
				d.logger.Warnf("DETECTOR: Dropped event %s due to full output channel", event.EventID)
			}
		}
	}
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
