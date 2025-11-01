package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRule_GetID(t *testing.T) {
	rule := Rule{ID: "test-id"}
	assert.Equal(t, "test-id", rule.GetID())
}

func TestRule_GetSeverity(t *testing.T) {
	rule := Rule{Severity: "High"}
	assert.Equal(t, "High", rule.GetSeverity())
}

func TestRule_GetActions(t *testing.T) {
	actions := []Action{{ID: "action1", Type: "webhook"}}
	rule := Rule{Actions: actions}
	assert.Equal(t, actions, rule.GetActions())
}

func TestCorrelationRule_GetID(t *testing.T) {
	rule := CorrelationRule{ID: "corr-test-id"}
	assert.Equal(t, "corr-test-id", rule.GetID())
}

func TestCorrelationRule_GetSeverity(t *testing.T) {
	rule := CorrelationRule{Severity: "Critical"}
	assert.Equal(t, "Critical", rule.GetSeverity())
}

func TestCorrelationRule_GetActions(t *testing.T) {
	actions := []Action{{ID: "action2", Type: "email"}}
	rule := CorrelationRule{Actions: actions}
	assert.Equal(t, actions, rule.GetActions())
}
