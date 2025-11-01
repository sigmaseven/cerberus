package ingest

import (
	"testing"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewCEFListener(t *testing.T) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event)

	listener := NewCEFListener("localhost", 515, 1000, eventCh, logger)

	assert.NotNil(t, listener)
	assert.NotNil(t, listener.BaseListener)
	assert.Equal(t, "localhost", listener.BaseListener.host)
	assert.Equal(t, 515, listener.BaseListener.port)
}
