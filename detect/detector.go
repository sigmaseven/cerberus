package detect

import (
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"
	"go.uber.org/zap"
)

// Detector runs the rule engine on events
type Detector struct {
	engine            *RuleEngine
	inputEventCh      <-chan *core.Event
	outputEventCh     chan<- *core.Event
	alertCh           chan<- *core.Alert
	actionExec        *ActionExecutor
	actionCh          chan func()
	actionWorkerCount int
	wg                sync.WaitGroup
	logger            *zap.SugaredLogger
}

// NewDetector creates a new detector
func NewDetector(engine *RuleEngine, inputEventCh <-chan *core.Event, outputEventCh chan<- *core.Event, alertCh chan<- *core.Alert, cfg *config.Config, logger *zap.SugaredLogger) *Detector {
	return &Detector{
		engine:            engine,
		inputEventCh:      inputEventCh,
		outputEventCh:     outputEventCh,
		alertCh:           alertCh,
		actionExec:        NewActionExecutor(time.Duration(cfg.Engine.ActionTimeout)*time.Second, logger),
		actionCh:          make(chan func(), 100), // buffer for action tasks
		actionWorkerCount: cfg.Engine.ActionWorkerCount,
		logger:            logger,
	}
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
func (d *Detector) processRuleMatches(rules []core.AlertableRule, event *core.Event) {
	for _, rule := range rules {
		alert := core.NewAlert(rule.GetID(), event.EventID, rule.GetSeverity(), event)
		metrics.AlertsGenerated.WithLabelValues(alert.Severity).Inc()
		select {
		case d.alertCh <- alert:
			// Execute actions asynchronously via worker pool
			select {
			case d.actionCh <- func() {
				defer func() {
					if r := recover(); r != nil {
						d.logger.Errorf("Panic in action execution: %v", r)
					}
				}()
				if err := d.actionExec.ExecuteActions(rule, alert); err != nil {
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
	for event := range d.inputEventCh {
		start := time.Now()
		matchingRules := d.engine.Evaluate(event)
		matchingCorrelationRules := d.engine.EvaluateCorrelation(event)
		metrics.EventProcessingDuration.Observe(time.Since(start).Seconds())
		d.processRuleMatches(matchingRules, event)
		d.processRuleMatches(matchingCorrelationRules, event)
		// Forward event to storage
		select {
		case d.outputEventCh <- event:
		default:
			d.logger.Warnf("Dropped event %s due to full output channel", event.EventID)
		}
	}
}

// Stop stops the detector
func (d *Detector) Stop() {
	d.wg.Wait()
	d.engine.Stop() // Stop correlation state cleanup goroutine
}
