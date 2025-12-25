package ingest

import (
	"cerberus/config"
	"cerberus/core"
	"go.uber.org/zap"
)

// TASK 138: Removed unused udpBufferSize constant

// SyslogListener listens for Syslog messages over TCP/UDP
type SyslogListener struct {
	*BaseListener
}

// NewSyslogListener creates a new Syslog listener
func NewSyslogListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger) *SyslogListener {
	return &SyslogListener{
		BaseListener: NewBaseListener(host, port, rateLimit, eventCh, logger),
	}
}

// NewSyslogListenerWithConfig creates a new Syslog listener with config
func NewSyslogListenerWithConfig(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, cfg *config.Config) *SyslogListener {
	return &SyslogListener{
		BaseListener: NewBaseListenerWithConfig(host, port, rateLimit, eventCh, logger, cfg),
	}
}

// Start starts the Syslog listener on TCP and UDP
func (s *SyslogListener) Start() error {
	// Start TCP listener
	go s.BaseListener.StartTCP(ParseSyslog, "Syslog")
	// Start UDP listener
	go s.BaseListener.StartUDP(ParseSyslog, "Syslog")
	return nil
}

// Stop stops the listener
func (s *SyslogListener) Stop() {
	s.BaseListener.Stop()
}
