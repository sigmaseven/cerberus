package ingest

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"
	"cerberus/util/goroutine"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Sentinel errors for ListenerManager operations
// These are used by API handlers to determine appropriate HTTP status codes
var (
	ErrListenerNotFound       = errors.New("listener not found")
	ErrListenerRunning        = errors.New("listener is running")
	ErrListenerNotRunning     = errors.New("listener is not running")
	ErrListenerAlreadyRunning = errors.New("listener is already running")
	ErrMaxListenersReached    = errors.New("maximum listener limit reached")
	ErrPortConflict           = errors.New("port already in use")
)

// ManagedListener represents an active listener instance
type ManagedListener struct {
	Config       *storage.DynamicListener
	Listener     interface{} // Actual listener instance (*SyslogListener, *CEFListener, *JSONListener)
	StopCh       chan struct{}
	Status       string
	EventCounter int64
	ErrorCounter int64
	StartTime    time.Time
	mu           sync.RWMutex
}

// ListenerManager manages dynamic listeners
type ListenerManager struct {
	listeners           map[string]*ManagedListener // ID -> ManagedListener
	storage             storage.DynamicListenerStorageInterface
	fieldMappingStorage storage.FieldMappingStorage
	rawEventCh          chan *core.Event
	config              *config.Config
	logger              *zap.SugaredLogger
	mu                  sync.RWMutex
	statsTicker         *time.Ticker
	stopCh              chan struct{}
	wg                  sync.WaitGroup // Track goroutine lifecycle
	maxListeners        int
	restoreEnabled      bool
	dlq                 *DLQ                  // TASK 7.3: DLQ for malformed events
	defaultNormalizer   *core.FieldNormalizer // Default SIGMA field normalizer
}

// NewListenerManager creates a new listener manager
// BLOCKING-3 FIX: Accept DLQ as constructor parameter to avoid race condition
// DLQ must be set before goroutines start (stats collector accesses it)
func NewListenerManager(
	storage storage.DynamicListenerStorageInterface,
	fieldMappingStorage storage.FieldMappingStorage,
	rawEventCh chan *core.Event,
	cfg *config.Config,
	logger *zap.SugaredLogger,
	dlq *DLQ,
) *ListenerManager {
	lm := &ListenerManager{
		listeners:           make(map[string]*ManagedListener),
		storage:             storage,
		fieldMappingStorage: fieldMappingStorage,
		rawEventCh:          rawEventCh,
		config:              cfg,
		logger:              logger,
		stopCh:              make(chan struct{}),
		maxListeners:        100, // Default max
		restoreEnabled:      true,
		dlq:                 dlq, // BLOCKING-3 FIX: Set DLQ before goroutines start
	}

	// Start statistics collector (may access dlq field)
	lm.startStatisticsCollector()

	return lm
}

// SetDLQ sets the DLQ instance for the listener manager
// TASK 7.3: Add DLQ support to listener manager
// DEPRECATED: Use constructor parameter instead to avoid race conditions
// Kept for backwards compatibility with existing code
func (lm *ListenerManager) SetDLQ(dlq *DLQ) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.dlq = dlq
}

// SetDefaultFieldNormalizer sets the default SIGMA field normalizer
// This normalizer is used for all listeners that use the "sigma" field mapping
// Call this after loading sigma_field_mappings.yaml at startup
func (lm *ListenerManager) SetDefaultFieldNormalizer(normalizer *core.FieldNormalizer) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.defaultNormalizer = normalizer
	lm.logger.Info("Default SIGMA field normalizer configured for ingestion-time normalization")
}

// CreateListener creates a new dynamic listener
func (lm *ListenerManager) CreateListener(config *storage.DynamicListener) (*storage.DynamicListener, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check max listeners limit
	if len(lm.listeners) >= lm.maxListeners {
		return nil, fmt.Errorf("maximum listener limit reached (%d)", lm.maxListeners)
	}

	// Generate ID if not provided
	if config.ID == "" {
		config.ID = uuid.New().String()
	}

	// Validate configuration
	if err := lm.validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Check port conflict (skip for port 0 as it means dynamic assignment)
	if config.Port != 0 {
		conflict, err := lm.storage.CheckPortConflict(config.Host, config.Port, config.Protocol, "")
		if err != nil {
			return nil, fmt.Errorf("failed to check port conflict: %w", err)
		}
		if conflict {
			return nil, fmt.Errorf("port %d (%s) is already in use on host %s", config.Port, config.Protocol, config.Host)
		}
	}

	// Check if port is available on system
	if !lm.isPortAvailable(config.Host, config.Port, config.Protocol) {
		return nil, fmt.Errorf("port %d is not available on the system", config.Port)
	}

	// Set initial status
	config.Status = "stopped"

	// Set default field mapping if not provided
	if config.FieldMapping == "" {
		config.FieldMapping = "sigma" // Default to no normalization
	}

	// Validate field mapping exists
	if lm.fieldMappingStorage != nil {
		_, err := lm.fieldMappingStorage.Get(config.FieldMapping)
		if err != nil {
			lm.logger.Warnf("Field mapping '%s' not found, using default 'sigma': %v", config.FieldMapping, err)
			config.FieldMapping = "sigma"
		}
	}

	// Save to database
	if err := lm.storage.CreateListener(config); err != nil {
		return nil, fmt.Errorf("failed to save listener: %w", err)
	}

	lm.logger.Infof("Created dynamic listener: %s (%s:%d %s) with field mapping: %s", config.Name, config.Host, config.Port, config.Protocol, config.FieldMapping)

	return config, nil
}

// StartListener starts a dynamic listener
func (lm *ListenerManager) StartListener(id string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already running
	if ml, exists := lm.listeners[id]; exists {
		if ml.Status == "running" {
			return ErrListenerAlreadyRunning
		}
	}

	// Get listener config from database
	config, err := lm.storage.GetListener(id)
	if err != nil {
		return fmt.Errorf("failed to get listener config: %w", err)
	}
	if config == nil {
		return ErrListenerNotFound
	}

	// Check port availability
	if !lm.isPortAvailable(config.Host, config.Port, config.Protocol) {
		return fmt.Errorf("port %d is not available", config.Port)
	}

	// Load field mapping and create normalizer
	// All events are normalized to SIGMA standard field names at ingestion time
	var normalizer *core.FieldNormalizer
	fieldMapping := config.FieldMapping
	if fieldMapping == "" {
		fieldMapping = "sigma" // Default
	}

	if fieldMapping == "sigma" {
		// Use the default SIGMA normalizer (loaded from sigma_field_mappings.yaml)
		normalizer = lm.defaultNormalizer
		if normalizer != nil {
			lm.logger.Infof("Using default SIGMA field normalizer for listener '%s'", config.Name)
		} else {
			lm.logger.Warnf("No default SIGMA normalizer configured - fields will not be normalized")
		}
	} else if lm.fieldMappingStorage != nil {
		// Load custom field mapping from storage
		mapping, err := lm.fieldMappingStorage.Get(fieldMapping)
		if err != nil {
			lm.logger.Warnf("Failed to load field mapping '%s', falling back to 'sigma': %v", fieldMapping, err)
			normalizer = lm.defaultNormalizer
		} else {
			// Create a normalizer with this custom mapping
			mappings := &core.FieldMappings{
				Mappings: map[string]map[string]string{
					fieldMapping: mapping.Mappings,
				},
			}
			normalizer = core.NewFieldNormalizer(mappings)
			lm.logger.Infof("Loaded custom field mapping '%s' with %d field mappings", fieldMapping, len(mapping.Mappings))
		}
	}

	// TASK 7.3: Get DLQ from manager (if available)
	dlq := lm.dlq
	protocol := config.Type

	// Create listener instance based on type (use WithConfig versions for performance optimizations)
	var listener interface{}
	stopCh := make(chan struct{})

	switch config.Type {
	case "syslog":
		l := NewSyslogListenerWithConfig(config.Host, config.Port, lm.config.Engine.RateLimit, lm.rawEventCh, lm.logger, lm.config)
		// Set normalizer if we have one
		if normalizer != nil {
			l.BaseListener.fieldNormalizer = normalizer
		}
		// TASK 7.3: Set DLQ and protocol for malformed event capture
		if dlq != nil {
			l.BaseListener.SetDLQ(dlq, protocol)
		}
		l.BaseListener.SetMetadata(id, config.Name, config.Source, fieldMapping)
		listener = l
	case "cef":
		l := NewCEFListenerWithConfig(config.Host, config.Port, lm.config.Engine.RateLimit, lm.rawEventCh, lm.logger, lm.config)
		// Set normalizer if we have one
		if normalizer != nil {
			l.BaseListener.fieldNormalizer = normalizer
		}
		// TASK 7.3: Set DLQ and protocol for malformed event capture
		if dlq != nil {
			l.BaseListener.SetDLQ(dlq, protocol)
		}
		l.BaseListener.SetMetadata(id, config.Name, config.Source, fieldMapping)
		listener = l
	case "json":
		l := NewJSONListenerWithConfig(config.Host, config.Port, config.TLS, config.CertFile, config.KeyFile, lm.config.Engine.RateLimit, int64(lm.config.Security.JSONBodyLimit), lm.rawEventCh, lm.logger, lm.config)
		// Set normalizer if we have one
		if normalizer != nil {
			l.BaseListener.fieldNormalizer = normalizer
		}
		// TASK 7.3: Set DLQ and protocol for malformed event capture
		if dlq != nil {
			l.BaseListener.SetDLQ(dlq, protocol)
		}
		l.BaseListener.SetMetadata(id, config.Name, config.Source, fieldMapping)
		listener = l
	default:
		return fmt.Errorf("unsupported listener type: %s", config.Type)
	}

	// Start the listener
	if err := lm.startListenerInstance(listener, config, stopCh); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	// Create managed listener
	ml := &ManagedListener{
		Config:    config,
		Listener:  listener,
		StopCh:    stopCh,
		Status:    "running",
		StartTime: time.Now(),
	}

	lm.listeners[id] = ml

	// Update database
	if err := lm.storage.UpdateListenerStatus(id, "running"); err != nil {
		lm.logger.Warnf("Failed to update listener status in database: %v", err)
	}
	if err := lm.storage.SetStartedAt(id, time.Now()); err != nil {
		lm.logger.Warnf("Failed to set started_at: %v", err)
	}

	lm.logger.Infof("Started dynamic listener: %s (%s:%d %s)", config.Name, config.Host, config.Port, config.Protocol)

	return nil
}

// StopListener stops a dynamic listener
func (lm *ListenerManager) StopListener(id string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	ml, exists := lm.listeners[id]
	if !exists {
		return ErrListenerNotRunning
	}

	// Stop the listener
	close(ml.StopCh)
	ml.Status = "stopped"

	// Update database
	if err := lm.storage.UpdateListenerStatus(id, "stopped"); err != nil {
		lm.logger.Warnf("Failed to update listener status in database: %v", err)
	}
	if err := lm.storage.SetStoppedAt(id, time.Now()); err != nil {
		lm.logger.Warnf("Failed to set stopped_at: %v", err)
	}

	// Remove from active listeners
	delete(lm.listeners, id)

	lm.logger.Infof("Stopped dynamic listener: %s", ml.Config.Name)

	return nil
}

// DeleteListener deletes a dynamic listener (must be stopped first)
func (lm *ListenerManager) DeleteListener(id string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if running
	if _, exists := lm.listeners[id]; exists {
		return ErrListenerRunning
	}

	// Delete from database
	if err := lm.storage.DeleteListener(id); err != nil {
		return fmt.Errorf("failed to delete listener: %w", err)
	}

	lm.logger.Infof("Deleted dynamic listener: %s", id)

	return nil
}

// GetListener gets a listener by ID
func (lm *ListenerManager) GetListener(id string) (*storage.DynamicListener, error) {
	// Get from database
	listener, err := lm.storage.GetListener(id)
	if err != nil {
		return nil, err
	}
	if listener == nil {
		return nil, ErrListenerNotFound
	}

	// Add runtime statistics if running
	lm.mu.RLock()
	if ml, exists := lm.listeners[id]; exists {
		ml.mu.RLock()
		listener.EventsReceived = ml.EventCounter
		listener.ErrorCount = ml.ErrorCounter
		if ml.EventCounter > 0 {
			uptime := time.Since(ml.StartTime).Minutes()
			if uptime > 0 {
				listener.EventsPerMinute = float64(ml.EventCounter) / uptime
			}
		}
		ml.mu.RUnlock()
	}
	lm.mu.RUnlock()

	return listener, nil
}

// ListListeners lists all dynamic listeners
func (lm *ListenerManager) ListListeners() ([]*storage.DynamicListener, error) {
	listeners, err := lm.storage.GetAllListeners()
	if err != nil {
		return nil, err
	}

	// Add runtime statistics
	lm.mu.RLock()
	for _, listener := range listeners {
		if ml, exists := lm.listeners[listener.ID]; exists {
			ml.mu.RLock()
			listener.EventsReceived = ml.EventCounter
			listener.ErrorCount = ml.ErrorCounter
			if ml.EventCounter > 0 {
				uptime := time.Since(ml.StartTime).Minutes()
				if uptime > 0 {
					listener.EventsPerMinute = float64(ml.EventCounter) / uptime
				}
			}
			ml.mu.RUnlock()
		}
	}
	lm.mu.RUnlock()

	return listeners, nil
}

// UpdateListener updates a listener configuration
func (lm *ListenerManager) UpdateListener(id string, updates *storage.DynamicListener) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if listener is running
	if _, exists := lm.listeners[id]; exists {
		return ErrListenerRunning
	}

	// Validate configuration
	if err := lm.validateConfig(updates); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Check port conflict (excluding this listener, skip for port 0 as it means dynamic assignment)
	if updates.Port != 0 {
		conflict, err := lm.storage.CheckPortConflict(updates.Host, updates.Port, updates.Protocol, id)
		if err != nil {
			return fmt.Errorf("failed to check port conflict: %w", err)
		}
		if conflict {
			return fmt.Errorf("port %d (%s) is already in use", updates.Port, updates.Protocol)
		}
	}

	// Update in database
	updates.ID = id
	if err := lm.storage.UpdateListener(id, updates); err != nil {
		return fmt.Errorf("failed to update listener: %w", err)
	}

	lm.logger.Infof("Updated dynamic listener: %s", id)

	return nil
}

// GetStatistics gets real-time statistics for a listener
func (lm *ListenerManager) GetStatistics(id string) (*storage.ListenerStats, error) {
	lm.mu.RLock()
	ml, exists := lm.listeners[id]
	lm.mu.RUnlock()

	if !exists {
		return nil, ErrListenerNotRunning
	}

	ml.mu.RLock()
	defer ml.mu.RUnlock()

	uptime := time.Since(ml.StartTime)
	var eventsPerMinute float64
	if uptime.Minutes() > 0 {
		eventsPerMinute = float64(ml.EventCounter) / uptime.Minutes()
	}

	var errorRate float64
	if ml.EventCounter > 0 {
		errorRate = (float64(ml.ErrorCounter) / float64(ml.EventCounter)) * 100
	}

	stats := &storage.ListenerStats{
		EventsReceived:  ml.EventCounter,
		EventsPerMinute: eventsPerMinute,
		ErrorCount:      ml.ErrorCounter,
		ErrorRate:       errorRate,
		LastEvent:       ml.Config.LastEvent,
		UptimeDuration:  uptime.Minutes(),
	}

	return stats, nil
}

// RestoreListeners restores listeners that were running before shutdown
func (lm *ListenerManager) RestoreListeners() error {
	if !lm.restoreEnabled {
		return nil
	}

	lm.logger.Info("Restoring dynamic listeners...")

	// Get all listeners that were running
	listeners, err := lm.storage.GetListenersByStatus("running")
	if err != nil {
		return fmt.Errorf("failed to get running listeners: %w", err)
	}

	restored := 0
	for _, listener := range listeners {
		if err := lm.StartListener(listener.ID); err != nil {
			lm.logger.Errorf("Failed to restore listener %s: %v", listener.Name, err)
			// Mark as stopped
			lm.storage.UpdateListenerStatus(listener.ID, "stopped")
		} else {
			restored++
		}
	}

	lm.logger.Infof("Restored %d dynamic listeners", restored)

	return nil
}

// Shutdown stops all listeners and cleans up
func (lm *ListenerManager) Shutdown() {
	lm.logger.Info("Shutting down listener manager...")

	// Signal shutdown to stats collector
	close(lm.stopCh)

	// Wait for stats collector goroutine to complete
	lm.wg.Wait()

	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Stop all listeners
	for id, ml := range lm.listeners {
		close(ml.StopCh)
		ml.Status = "stopped"
		lm.storage.UpdateListenerStatus(id, "stopped")
		lm.storage.SetStoppedAt(id, time.Now())
	}

	lm.listeners = make(map[string]*ManagedListener)

	lm.logger.Info("Listener manager shut down")
}

// Helper methods

func (lm *ListenerManager) validateConfig(config *storage.DynamicListener) error {
	if config.Name == "" {
		return fmt.Errorf("name is required")
	}
	if config.Type == "" {
		return fmt.Errorf("type is required")
	}
	if config.Type != "syslog" && config.Type != "cef" && config.Type != "json" {
		return fmt.Errorf("invalid type: %s", config.Type)
	}
	if config.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}
	if config.Protocol != "udp" && config.Protocol != "tcp" && config.Protocol != "http" {
		return fmt.Errorf("invalid protocol: %s", config.Protocol)
	}
	if config.Host == "" {
		return fmt.Errorf("host is required")
	}
	if config.Port < 0 || config.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535 (0 for automatic assignment)")
	}
	if config.TLS && (config.CertFile == "" || config.KeyFile == "") {
		return fmt.Errorf("cert_file and key_file are required when TLS is enabled")
	}
	if config.Source == "" {
		return fmt.Errorf("source identifier is required")
	}

	return nil
}

func (lm *ListenerManager) isPortAvailable(host string, port int, protocol string) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	if protocol == "tcp" || protocol == "http" {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return false
		}
		_ = ln.Close()
		return true
	} else if protocol == "udp" {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return false
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	return false
}

// TASK 147: Added WaitGroup tracking to listener goroutines for proper lifecycle management
func (lm *ListenerManager) startListenerInstance(listener interface{}, config *storage.DynamicListener, stopCh chan struct{}) error {
	switch l := listener.(type) {
	case *SyslogListener:
		lm.wg.Add(1)
		go func() {
			defer lm.wg.Done()
			defer goroutine.Recover("listener-syslog", lm.logger)
			if err := l.Start(); err != nil {
				lm.logger.Errorf("Syslog listener error: %v", err)
			}
		}()
	case *CEFListener:
		lm.wg.Add(1)
		go func() {
			defer lm.wg.Done()
			defer goroutine.Recover("listener-cef", lm.logger)
			if err := l.Start(); err != nil {
				lm.logger.Errorf("CEF listener error: %v", err)
			}
		}()
	case *JSONListener:
		lm.wg.Add(1)
		go func() {
			defer lm.wg.Done()
			defer goroutine.Recover("listener-json", lm.logger)
			if err := l.Start(); err != nil {
				lm.logger.Errorf("JSON listener error: %v", err)
			}
		}()
	default:
		return fmt.Errorf("unsupported listener type")
	}

	return nil
}

// Statistics collector
// BLOCKING-3 FIX: Move ticker.Stop() to defer to prevent resource leak on panic
func (lm *ListenerManager) startStatisticsCollector() {
	lm.statsTicker = time.NewTicker(core.StatsCollectionInterval)

	lm.wg.Add(1)
	go func() {
		defer lm.wg.Done()
		defer goroutine.Recover("listener-stats-collector", lm.logger)
		// BLOCKING-3 FIX: Defer ticker cleanup immediately after goroutine starts
		// This ensures ticker is stopped even if panic occurs before stopCh receives signal
		defer lm.statsTicker.Stop()

		for {
			select {
			case <-lm.statsTicker.C:
				lm.collectStatistics()
			case <-lm.stopCh:
				// Ticker already stopped by defer
				return
			}
		}
	}()
}

func (lm *ListenerManager) collectStatistics() {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	for id, ml := range lm.listeners {
		ml.mu.RLock()
		stats := &storage.ListenerStats{
			EventsReceived: ml.EventCounter,
			ErrorCount:     ml.ErrorCounter,
			LastEvent:      ml.Config.LastEvent,
		}
		ml.mu.RUnlock()

		// Update in database
		if err := lm.storage.UpdateStatistics(id, stats); err != nil {
			lm.logger.Warnf("Failed to update statistics for listener %s: %v", id, err)
		}
	}
}

// IncrementEventCount increments the event counter for a listener
func (lm *ListenerManager) IncrementEventCount(id string) {
	lm.mu.RLock()
	ml, exists := lm.listeners[id]
	lm.mu.RUnlock()

	if exists {
		ml.mu.Lock()
		ml.EventCounter++
		ml.Config.LastEvent = time.Now()
		ml.mu.Unlock()
	}
}

// IncrementErrorCount increments the error counter for a listener
func (lm *ListenerManager) IncrementErrorCount(id string) {
	lm.mu.RLock()
	ml, exists := lm.listeners[id]
	lm.mu.RUnlock()

	if exists {
		ml.mu.Lock()
		ml.ErrorCounter++
		ml.mu.Unlock()
	}
}
