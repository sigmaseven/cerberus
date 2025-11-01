package core

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAlert(t *testing.T) {
	ruleID := "test-rule"
	eventID := "test-event"
	severity := "high"
	event := (*Event)(nil)

	alert := NewAlert(ruleID, eventID, severity, event)

	assert.NotEmpty(t, alert.AlertID)
	_, err := uuid.Parse(alert.AlertID)
	assert.NoError(t, err)

	assert.Equal(t, ruleID, alert.RuleID)
	assert.Equal(t, eventID, alert.EventID)
	assert.Equal(t, severity, alert.Severity)
	assert.Equal(t, "New", alert.Status)
	assert.Nil(t, alert.Event)

	assert.WithinDuration(t, time.Now().UTC(), alert.Timestamp, time.Second)
}
