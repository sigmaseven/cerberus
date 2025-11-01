package ingest

import (
	"cerberus/core"
	"go.uber.org/zap"
)

// CEFListener listens for CEF messages over TCP and UDP
type CEFListener struct {
	*BaseListener
}

// NewCEFListener creates a new CEF listener
func NewCEFListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger) *CEFListener {
	return &CEFListener{
		BaseListener: NewBaseListener(host, port, rateLimit, eventCh, logger),
	}
}

// Start starts the CEF listener on TCP and UDP
func (c *CEFListener) Start() error {
	// Start TCP listener
	go c.BaseListener.StartTCP(ParseCEF, "CEF")
	// Start UDP listener
	go c.BaseListener.StartUDP(ParseCEF, "CEF")
	return nil
}

// Stop stops the listener
func (c *CEFListener) Stop() {
	c.BaseListener.Stop()
}
