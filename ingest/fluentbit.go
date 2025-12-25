package ingest

import (
	"cerberus/config"
	"cerberus/core"

	"go.uber.org/zap"
)

// FluentBitListener implements the Fluent Bit Forward protocol listener
// Fluent Bit uses the same Forward protocol as Fluentd, so we simply extend FluentdListener
type FluentBitListener struct {
	*FluentdListener
}

// NewFluentBitListener creates a new Fluent Bit listener
func NewFluentBitListener(host string, port int, rateLimit int, eventCh chan<- *core.Event, logger *zap.SugaredLogger, cfg *config.Config) *FluentBitListener {
	// Create base Fluentd listener with Fluent Bit config
	var fluentdListener *FluentdListener
	if cfg != nil {
		// Create a modified config that uses Fluent Bit settings
		// Map FluentBit config to Fluentd config structure
		fluentdCfg := *cfg
		fluentdCfg.Listeners.Fluentd.Port = cfg.Listeners.FluentBit.Port
		fluentdCfg.Listeners.Fluentd.Host = cfg.Listeners.FluentBit.Host
		fluentdCfg.Listeners.Fluentd.TLS = cfg.Listeners.FluentBit.TLS
		fluentdCfg.Listeners.Fluentd.CertFile = cfg.Listeners.FluentBit.CertFile
		fluentdCfg.Listeners.Fluentd.KeyFile = cfg.Listeners.FluentBit.KeyFile
		// FluentBit typically doesn't use auth/ack, so leave defaults
		fluentdCfg.Listeners.Fluentd.SharedKey = ""
		fluentdCfg.Listeners.Fluentd.RequireACK = false
		fluentdCfg.Listeners.Fluentd.ChunkSizeLimit = 8388608 // 8MB default
		fluentdListener = NewFluentdListener(host, port, rateLimit, eventCh, logger, &fluentdCfg)
	} else {
		fluentdListener = NewFluentdListener(host, port, rateLimit, eventCh, logger, nil)
	}

	fbl := &FluentBitListener{
		FluentdListener: fluentdListener,
	}

	// Override event source
	fbl.logger.Info("Fluent Bit listener initialized (using Fluentd Forward protocol)")

	return fbl
}

// createEvent overrides the parent method to set event_source to "fluentbit"
func (fbl *FluentBitListener) createEvent(tag string, timeVal interface{}, record map[string]interface{}, sourceIP string) *core.Event {
	event := fbl.FluentdListener.createEvent(tag, timeVal, record, sourceIP)
	if event.Fields == nil {
		event.Fields = make(map[string]interface{})
	}
	event.Fields["event_source"] = "fluentbit"
	event.SourceFormat = "fluentbit"
	return event
}

// Start starts the Fluent Bit listener
func (fbl *FluentBitListener) Start() error {
	fbl.logger.Infof("Starting Fluent Bit listener...")
	return fbl.FluentdListener.Start()
}

// Stop stops the Fluent Bit listener
func (fbl *FluentBitListener) Stop() error {
	fbl.logger.Info("Stopping Fluent Bit listener...")
	return fbl.FluentdListener.Stop()
}
