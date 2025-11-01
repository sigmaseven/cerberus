package detect

import (
	"testing"

	"cerberus/core"
	"cerberus/storage"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewEventReplay(t *testing.T) {
	eventStorage := &storage.EventStorage{}
	ruleEngine := &RuleEngine{}
	alertCh := make(chan *core.Alert)
	logger := zap.NewNop().Sugar()

	er := NewEventReplay(eventStorage, ruleEngine, alertCh, logger)

	assert.NotNil(t, er)
	assert.Equal(t, eventStorage, er.eventStorage)
	assert.Equal(t, ruleEngine, er.ruleEngine)
	assert.NotNil(t, er.alertCh)
	assert.NotNil(t, er.logger)
}
