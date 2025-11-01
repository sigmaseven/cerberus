package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricsRegistration(t *testing.T) {
	// This is a basic test to ensure no panic on import
	// Since metrics are global, we can't easily test registration without mocking

	// Just assert that the variables are not nil
	assert.NotNil(t, EventsIngested)
	assert.NotNil(t, AlertsGenerated)
	assert.NotNil(t, ActionsExecuted)
	assert.NotNil(t, EventProcessingDuration)
	assert.NotNil(t, DeadLetterInsertFailures)
}
