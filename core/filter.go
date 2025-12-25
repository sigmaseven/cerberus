package core

import (
	"crypto/rand"
	"math/big"
	"sync"

	"cerberus/config"
	"go.uber.org/zap"
)

// EventFilter filters and samples events based on configured rules
// Optimization #9: Drop low-value events before detection (1.5-2x gain for noisy sources)
type EventFilter struct {
	enabled          bool
	samplingRate     float64
	dropTypes        map[string]bool // Set of event types to drop completely
	sampleTypes      map[string]bool // Set of event types to sample
	whitelistSources map[string]bool // Set of source IPs to never filter
	logger           *zap.SugaredLogger
	mu               sync.RWMutex // Protects config updates
}

// NewEventFilter creates a new event filter
func NewEventFilter(cfg *config.Config, logger *zap.SugaredLogger) *EventFilter {
	if !cfg.Filtering.Enabled {
		logger.Info("Event filtering is disabled")
		return &EventFilter{enabled: false}
	}

	// Build lookup maps for fast filtering
	dropTypes := make(map[string]bool)
	for _, eventType := range cfg.Filtering.DropEventTypes {
		dropTypes[eventType] = true
	}

	sampleTypes := make(map[string]bool)
	for _, eventType := range cfg.Filtering.SampleEventTypes {
		sampleTypes[eventType] = true
	}

	whitelistSources := make(map[string]bool)
	for _, sourceIP := range cfg.Filtering.WhitelistSources {
		whitelistSources[sourceIP] = true
	}

	logger.Infof("Event filtering enabled: drop_types=%d, sample_types=%d, sampling_rate=%.2f, whitelist=%d",
		len(dropTypes), len(sampleTypes), cfg.Filtering.SamplingRate, len(whitelistSources))

	return &EventFilter{
		enabled:          true,
		samplingRate:     cfg.Filtering.SamplingRate,
		dropTypes:        dropTypes,
		sampleTypes:      sampleTypes,
		whitelistSources: whitelistSources,
		logger:           logger,
	}
}

// ShouldProcess returns true if the event should be processed, false if it should be dropped
func (f *EventFilter) ShouldProcess(event *Event) bool {
	if !f.enabled {
		return true // Filtering disabled, process all events
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Extract source_ip from Fields (if present)
	var sourceIP string
	if event.Fields != nil {
		if ip, ok := event.Fields["source_ip"].(string); ok {
			sourceIP = ip
		}
	}

	// Whitelist check - never filter whitelisted sources
	if sourceIP != "" && f.whitelistSources[sourceIP] {
		return true
	}

	// Extract event_type from Fields (if present)
	var eventType string
	if event.Fields != nil {
		if et, ok := event.Fields["event_type"].(string); ok {
			eventType = et
		}
	}

	// Drop check - completely drop these event types
	if eventType != "" && f.dropTypes[eventType] {
		return false
	}

	// Sample check - sample these event types at configured rate
	if eventType != "" && f.sampleTypes[eventType] {
		// Use cryptographically secure random sampling: keep event if random number < sampling rate
		return secureRandomFloat64() < f.samplingRate
	}

	// Default: process the event (not in drop or sample lists)
	return true
}

// secureRandomFloat64 generates a cryptographically secure random float64 between 0 and 1
func secureRandomFloat64() float64 {
	// Generate a random 64-bit integer using crypto/rand
	max := big.NewInt(1 << 53) // Use 53 bits for mantissa precision
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback to a conservative value if crypto fails
		// This ensures sampling continues to work even in rare error cases
		return 0.5
	}

	// Convert to float64 in range [0, 1)
	return float64(n.Int64()) / float64(max.Int64())
}

// UpdateConfig updates the filter configuration (thread-safe)
func (f *EventFilter) UpdateConfig(cfg *config.Config) {
	if !cfg.Filtering.Enabled {
		f.enabled = false
		f.logger.Info("Event filtering disabled via config update")
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Rebuild lookup maps
	dropTypes := make(map[string]bool)
	for _, eventType := range cfg.Filtering.DropEventTypes {
		dropTypes[eventType] = true
	}

	sampleTypes := make(map[string]bool)
	for _, eventType := range cfg.Filtering.SampleEventTypes {
		sampleTypes[eventType] = true
	}

	whitelistSources := make(map[string]bool)
	for _, sourceIP := range cfg.Filtering.WhitelistSources {
		whitelistSources[sourceIP] = true
	}

	f.enabled = true
	f.samplingRate = cfg.Filtering.SamplingRate
	f.dropTypes = dropTypes
	f.sampleTypes = sampleTypes
	f.whitelistSources = whitelistSources

	f.logger.Infof("Event filter config updated: drop_types=%d, sample_types=%d, sampling_rate=%.2f, whitelist=%d",
		len(dropTypes), len(sampleTypes), f.samplingRate, len(whitelistSources))
}
