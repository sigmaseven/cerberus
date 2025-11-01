package ingest

import (
	"cerberus/core"
	"go.uber.org/zap"
)

const (
	udpBufferSize = 65536
)

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
