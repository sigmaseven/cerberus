package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEvent(t *testing.T) {
	event := NewEvent()
	assert.NotNil(t, event)
	assert.NotEmpty(t, event.EventID)
	assert.NotZero(t, event.Timestamp)
	assert.NotNil(t, event.Fields)
}

func TestEventFields(t *testing.T) {
	event := NewEvent()
	event.EventType = "test"
	event.Severity = "info"
	event.Fields["key"] = "value"

	assert.Equal(t, "test", event.EventType)
	assert.Equal(t, "info", event.Severity)
	assert.Equal(t, "value", event.Fields["key"])
}
