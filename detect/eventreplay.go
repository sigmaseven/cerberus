package detect

import (
	"context"
	"fmt"
	"time"

	"cerberus/core"
	"cerberus/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// EventReplay handles event replay functionality
type EventReplay struct {
	eventStorage *storage.EventStorage
	ruleEngine   *RuleEngine
	alertCh      chan<- *core.Alert
	logger       *zap.SugaredLogger
}

// NewEventReplay creates a new event replay handler
func NewEventReplay(eventStorage *storage.EventStorage, ruleEngine *RuleEngine, alertCh chan<- *core.Alert, logger *zap.SugaredLogger) *EventReplay {
	return &EventReplay{
		eventStorage: eventStorage,
		ruleEngine:   ruleEngine,
		alertCh:      alertCh,
		logger:       logger,
	}
}

// ReplayEvents replays events from a time range
func (er *EventReplay) ReplayEvents(startTime, endTime time.Time) error {
	ctx := context.Background()

	// Query events in the time range
	filter := bson.M{
		"timestamp": bson.M{
			"$gte": startTime,
			"$lte": endTime,
		},
	}

	opts := options.Find().SetSort(bson.M{"timestamp": 1})
	cursor, err := er.eventStorage.EventsColl.Find(ctx, filter, opts)
	if err != nil {
		return fmt.Errorf("failed to query events for replay: %w", err)
	}
	defer cursor.Close(ctx)

	var events []*core.Event
	if err = cursor.All(ctx, &events); err != nil {
		return fmt.Errorf("failed to decode events for replay: %w", err)
	}

	er.logger.Infof("Replaying %d events from %s to %s", len(events), startTime, endTime)

	// Reset correlation state to prevent interference from previous runs
	er.ruleEngine.ResetCorrelationState()

	// Process events through the rule engine
	for _, event := range events {
		matchingRules := er.ruleEngine.Evaluate(event)
		matchingCorrelationRules := er.ruleEngine.EvaluateCorrelation(event)

		for _, rule := range matchingRules {
			alert := core.NewAlert(rule.GetID(), event.EventID, rule.GetSeverity(), event)
			select {
			case er.alertCh <- alert:
			default:
				er.logger.Warnf("Alert channel full during replay")
			}
		}

		for _, rule := range matchingCorrelationRules {
			alert := core.NewAlert(rule.GetID(), event.EventID, rule.GetSeverity(), event)
			select {
			case er.alertCh <- alert:
			default:
				er.logger.Warnf("Alert channel full during replay")
			}
		}
	}

	er.logger.Infof("Event replay completed")
	return nil
}
