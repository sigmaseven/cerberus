package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/util/goroutine"
	"go.uber.org/zap"
)

// Correlation state limits to prevent memory exhaustion attacks
const (
	MaxGroupsPerRule          = 1000  // Maximum correlation groups per rule
	MaxDistinctValuesPerField = 10000 // Maximum distinct values tracked per field
	MaxEventsPerGroup         = 1000  // Maximum events stored per correlation group
	MaxMetricsPerGroup        = 1000  // Maximum metric values stored per group
)

// Statistics holds statistical data for a metric
type Statistics struct {
	Count  int
	Sum    float64
	Mean   float64
	StdDev float64
	Min    float64
	Max    float64
}

// CorrelationStateStore manages correlation state for all correlation types
type CorrelationStateStore interface {
	// Count-based tracking
	IncrementCount(ruleID, groupKey string, event *core.Event) int
	GetCount(ruleID, groupKey string) int

	// Value counting (distinct values)
	AddValue(ruleID, groupKey, field string, value interface{}) int
	GetValueCount(ruleID, groupKey, field string) int

	// Sequence tracking
	AddToSequence(ruleID, groupKey string, stageName string, event *core.Event) []string
	GetSequence(ruleID, groupKey string) []string
	GetSequenceEvents(ruleID, groupKey string) []*core.Event

	// Statistical tracking
	AddMetric(ruleID, groupKey string, value float64)
	GetStatistics(ruleID, groupKey string) Statistics

	// Event storage
	AddEvent(ruleID, groupKey string, event *core.Event)
	GetEvents(ruleID, groupKey string) []*core.Event

	// Cleanup and management
	CleanupExpired(ttl time.Duration)
	CleanupRule(ruleID string)
	Reset()
	Stop()

	// Statistics
	GetStats() CorrelationStoreStats
}

// CorrelationStoreStats provides statistics about the correlation store
type CorrelationStoreStats struct {
	TotalRules    int
	TotalGroups   int
	TotalEvents   int
	TotalMetrics  int
	MemoryUsageMB float64
}

// countEntry tracks event counts per group
type countEntry struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// valueSetEntry tracks distinct values per group
type valueSetEntry struct {
	values   map[string]bool
	lastSeen time.Time
}

// sequenceEntry tracks event sequences per group
type sequenceEntry struct {
	stages   []string
	events   []*core.Event
	lastSeen time.Time
}

// metricEntry tracks statistical metrics per group
type metricEntry struct {
	values   []float64
	lastSeen time.Time
}

// eventListEntry tracks lists of events per group
type eventListEntry struct {
	events   []*core.Event
	lastSeen time.Time
}

// correlationStateStoreImpl implements CorrelationStateStore
type correlationStateStoreImpl struct {
	// Separate maps for different correlation types
	counts    map[string]map[string]*countEntry               // ruleID -> groupKey -> count
	valueSets map[string]map[string]map[string]*valueSetEntry // ruleID -> groupKey -> field -> values
	sequences map[string]map[string]*sequenceEntry            // ruleID -> groupKey -> sequence
	metrics   map[string]map[string]*metricEntry              // ruleID -> groupKey -> metrics
	events    map[string]map[string]*eventListEntry           // ruleID -> groupKey -> events

	mu            sync.RWMutex
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWg     sync.WaitGroup // TASK 147: Track cleanup goroutine lifecycle
	logger        *zap.SugaredLogger
}

// NewCorrelationStateStore creates a new correlation state store
func NewCorrelationStateStore(logger *zap.SugaredLogger) CorrelationStateStore {
	store := &correlationStateStoreImpl{
		counts:    make(map[string]map[string]*countEntry),
		valueSets: make(map[string]map[string]map[string]*valueSetEntry),
		sequences: make(map[string]map[string]*sequenceEntry),
		metrics:   make(map[string]map[string]*metricEntry),
		events:    make(map[string]map[string]*eventListEntry),
		logger:    logger,
	}

	// Start periodic cleanup
	ctx, cancel := context.WithCancel(context.Background())
	store.cleanupCtx = ctx
	store.cleanupCancel = cancel
	store.startPeriodicCleanup(ctx)

	return store
}

// IncrementCount increments the count for a rule/group combination
func (s *correlationStateStoreImpl) IncrementCount(ruleID, groupKey string, event *core.Event) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.counts[ruleID] == nil {
		s.counts[ruleID] = make(map[string]*countEntry)
	}

	entry, exists := s.counts[ruleID][groupKey]
	if !exists {
		// Enforce per-rule group limit to prevent memory exhaustion
		if len(s.counts[ruleID]) >= MaxGroupsPerRule {
			if s.logger != nil {
				s.logger.Warnw("Correlation group limit reached for count tracking, ignoring new group",
					"rule_id", ruleID,
					"current_groups", len(s.counts[ruleID]),
					"limit", MaxGroupsPerRule)
			}
			return 0
		}

		entry = &countEntry{
			count:     0,
			firstSeen: event.Timestamp,
			lastSeen:  event.Timestamp,
		}
		s.counts[ruleID][groupKey] = entry
	}

	entry.count++
	entry.lastSeen = event.Timestamp
	return entry.count
}

// GetCount returns the current count for a rule/group combination
func (s *correlationStateStoreImpl) GetCount(ruleID, groupKey string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.counts[ruleID] == nil {
		return 0
	}
	if entry, exists := s.counts[ruleID][groupKey]; exists {
		return entry.count
	}
	return 0
}

// AddValue adds a value to the distinct value set
func (s *correlationStateStoreImpl) AddValue(ruleID, groupKey, field string, value interface{}) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.valueSets[ruleID] == nil {
		s.valueSets[ruleID] = make(map[string]map[string]*valueSetEntry)
	}

	// Enforce per-rule group limit to prevent memory exhaustion
	if s.valueSets[ruleID][groupKey] == nil {
		if len(s.valueSets[ruleID]) >= MaxGroupsPerRule {
			if s.logger != nil {
				s.logger.Warnw("Correlation group limit reached, ignoring new group",
					"rule_id", ruleID,
					"current_groups", len(s.valueSets[ruleID]),
					"limit", MaxGroupsPerRule)
			}
			return 0
		}
		s.valueSets[ruleID][groupKey] = make(map[string]*valueSetEntry)
	}

	entry, exists := s.valueSets[ruleID][groupKey][field]
	if !exists {
		entry = &valueSetEntry{
			values:   make(map[string]bool),
			lastSeen: time.Now(),
		}
		s.valueSets[ruleID][groupKey][field] = entry
	}

	// Convert value to string for storage
	valueStr := fmt.Sprintf("%v", value)

	// Enforce distinct value limit to prevent memory exhaustion
	if !entry.values[valueStr] && len(entry.values) >= MaxDistinctValuesPerField {
		if s.logger != nil {
			s.logger.Warnw("Distinct value limit reached for field, ignoring new value",
				"rule_id", ruleID,
				"group_key", groupKey,
				"field", field,
				"current_values", len(entry.values),
				"limit", MaxDistinctValuesPerField)
		}
		return len(entry.values)
	}

	entry.values[valueStr] = true
	entry.lastSeen = time.Now()

	return len(entry.values)
}

// GetValueCount returns the count of distinct values
func (s *correlationStateStoreImpl) GetValueCount(ruleID, groupKey, field string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.valueSets[ruleID] == nil || s.valueSets[ruleID][groupKey] == nil {
		return 0
	}
	if entry, exists := s.valueSets[ruleID][groupKey][field]; exists {
		return len(entry.values)
	}
	return 0
}

// AddToSequence adds a stage to the sequence
func (s *correlationStateStoreImpl) AddToSequence(ruleID, groupKey string, stageName string, event *core.Event) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sequences[ruleID] == nil {
		s.sequences[ruleID] = make(map[string]*sequenceEntry)
	}

	entry, exists := s.sequences[ruleID][groupKey]
	if !exists {
		entry = &sequenceEntry{
			stages:   make([]string, 0),
			events:   make([]*core.Event, 0),
			lastSeen: event.Timestamp,
		}
		s.sequences[ruleID][groupKey] = entry
	}

	entry.stages = append(entry.stages, stageName)
	entry.events = append(entry.events, event)
	entry.lastSeen = event.Timestamp

	return entry.stages
}

// GetSequence returns the current sequence of stages
func (s *correlationStateStoreImpl) GetSequence(ruleID, groupKey string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sequences[ruleID] == nil {
		return []string{}
	}
	if entry, exists := s.sequences[ruleID][groupKey]; exists {
		return entry.stages
	}
	return []string{}
}

// GetSequenceEvents returns the events in the sequence
func (s *correlationStateStoreImpl) GetSequenceEvents(ruleID, groupKey string) []*core.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sequences[ruleID] == nil {
		return []*core.Event{}
	}
	if entry, exists := s.sequences[ruleID][groupKey]; exists {
		return entry.events
	}
	return []*core.Event{}
}

// AddMetric adds a metric value for statistical analysis
func (s *correlationStateStoreImpl) AddMetric(ruleID, groupKey string, value float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metrics[ruleID] == nil {
		s.metrics[ruleID] = make(map[string]*metricEntry)
	}

	entry, exists := s.metrics[ruleID][groupKey]
	if !exists {
		entry = &metricEntry{
			values:   make([]float64, 0),
			lastSeen: time.Now(),
		}
		s.metrics[ruleID][groupKey] = entry
	}

	entry.values = append(entry.values, value)
	entry.lastSeen = time.Now()

	// Limit metric history to prevent memory issues (keep last 10000 values)
	if len(entry.values) > 10000 {
		entry.values = entry.values[len(entry.values)-10000:]
	}
}

// GetStatistics calculates statistics for the metrics
func (s *correlationStateStoreImpl) GetStatistics(ruleID, groupKey string) Statistics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Statistics{}

	if s.metrics[ruleID] == nil {
		return stats
	}
	entry, exists := s.metrics[ruleID][groupKey]
	if !exists || len(entry.values) == 0 {
		return stats
	}

	values := entry.values
	stats.Count = len(values)

	// Calculate sum, min, max
	stats.Sum = 0
	stats.Min = values[0]
	stats.Max = values[0]
	for _, v := range values {
		stats.Sum += v
		if v < stats.Min {
			stats.Min = v
		}
		if v > stats.Max {
			stats.Max = v
		}
	}

	// Calculate mean
	stats.Mean = stats.Sum / float64(stats.Count)

	// Calculate standard deviation
	variance := 0.0
	for _, v := range values {
		diff := v - stats.Mean
		variance += diff * diff
	}
	variance /= float64(stats.Count)
	stats.StdDev = math.Sqrt(variance)

	return stats
}

// AddEvent adds an event to the event list
func (s *correlationStateStoreImpl) AddEvent(ruleID, groupKey string, event *core.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.events[ruleID] == nil {
		s.events[ruleID] = make(map[string]*eventListEntry)
	}

	entry, exists := s.events[ruleID][groupKey]
	if !exists {
		// Enforce per-rule group limit to prevent memory exhaustion
		if len(s.events[ruleID]) >= MaxGroupsPerRule {
			if s.logger != nil {
				s.logger.Warnw("Correlation group limit reached for event tracking, ignoring new group",
					"rule_id", ruleID,
					"current_groups", len(s.events[ruleID]),
					"limit", MaxGroupsPerRule)
			}
			return
		}

		entry = &eventListEntry{
			events:   make([]*core.Event, 0),
			lastSeen: event.Timestamp,
		}
		s.events[ruleID][groupKey] = entry
	}

	entry.events = append(entry.events, event)
	entry.lastSeen = event.Timestamp

	// Limit event history to prevent memory issues (keep last MaxEventsPerGroup events)
	if len(entry.events) > MaxEventsPerGroup {
		entry.events = entry.events[len(entry.events)-MaxEventsPerGroup:]
	}
}

// GetEvents returns the events for a rule/group combination
func (s *correlationStateStoreImpl) GetEvents(ruleID, groupKey string) []*core.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.events[ruleID] == nil {
		return []*core.Event{}
	}
	if entry, exists := s.events[ruleID][groupKey]; exists {
		return entry.events
	}
	return []*core.Event{}
}

// CleanupExpired removes expired entries based on TTL
func (s *correlationStateStoreImpl) CleanupExpired(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-ttl)

	// Cleanup counts
	for ruleID, groups := range s.counts {
		for groupKey, entry := range groups {
			if entry.lastSeen.Before(cutoff) {
				delete(groups, groupKey)
			}
		}
		if len(groups) == 0 {
			delete(s.counts, ruleID)
		}
	}

	// Cleanup value sets
	for ruleID, groups := range s.valueSets {
		for groupKey, fields := range groups {
			for field, entry := range fields {
				if entry.lastSeen.Before(cutoff) {
					delete(fields, field)
				}
			}
			if len(fields) == 0 {
				delete(groups, groupKey)
			}
		}
		if len(groups) == 0 {
			delete(s.valueSets, ruleID)
		}
	}

	// Cleanup sequences
	for ruleID, groups := range s.sequences {
		for groupKey, entry := range groups {
			if entry.lastSeen.Before(cutoff) {
				delete(groups, groupKey)
			}
		}
		if len(groups) == 0 {
			delete(s.sequences, ruleID)
		}
	}

	// Cleanup metrics
	for ruleID, groups := range s.metrics {
		for groupKey, entry := range groups {
			if entry.lastSeen.Before(cutoff) {
				delete(groups, groupKey)
			}
		}
		if len(groups) == 0 {
			delete(s.metrics, ruleID)
		}
	}

	// Cleanup events
	for ruleID, groups := range s.events {
		for groupKey, entry := range groups {
			if entry.lastSeen.Before(cutoff) {
				delete(groups, groupKey)
			}
		}
		if len(groups) == 0 {
			delete(s.events, ruleID)
		}
	}
}

// CleanupRule removes all state for a specific rule
func (s *correlationStateStoreImpl) CleanupRule(ruleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.counts, ruleID)
	delete(s.valueSets, ruleID)
	delete(s.sequences, ruleID)
	delete(s.metrics, ruleID)
	delete(s.events, ruleID)
}

// Reset clears all correlation state
func (s *correlationStateStoreImpl) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.counts = make(map[string]map[string]*countEntry)
	s.valueSets = make(map[string]map[string]map[string]*valueSetEntry)
	s.sequences = make(map[string]map[string]*sequenceEntry)
	s.metrics = make(map[string]map[string]*metricEntry)
	s.events = make(map[string]map[string]*eventListEntry)
}

// Stop stops the cleanup goroutine and waits for it to finish
// TASK 147: Added WaitGroup.Wait() with timeout for graceful shutdown
func (s *correlationStateStoreImpl) Stop() {
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}

	// Wait for cleanup goroutine with timeout
	done := make(chan struct{})
	go func() {
		s.cleanupWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Cleanup goroutine stopped successfully
	case <-time.After(5 * time.Second):
		if s.logger != nil {
			s.logger.Warn("enhanced-correlation-state-cleanup goroutine did not stop within 5s")
		}
	}
}

// GetStats returns statistics about the correlation store
func (s *correlationStateStoreImpl) GetStats() CorrelationStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := CorrelationStoreStats{}

	// Count rules and groups
	for _, groups := range s.counts {
		stats.TotalGroups += len(groups)
	}
	stats.TotalRules = len(s.counts)

	// Count total events
	for _, groups := range s.events {
		for _, entry := range groups {
			stats.TotalEvents += len(entry.events)
		}
	}

	// Count total metrics
	for _, groups := range s.metrics {
		for _, entry := range groups {
			stats.TotalMetrics += len(entry.values)
		}
	}

	return stats
}

// startPeriodicCleanup runs periodic cleanup
// TASK 147: Added WaitGroup tracking and panic recovery
func (s *correlationStateStoreImpl) startPeriodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	s.cleanupWg.Add(1)
	go func() {
		defer s.cleanupWg.Done()
		defer goroutine.Recover("enhanced-correlation-state-cleanup", s.logger)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Cleanup entries older than 1 hour
				s.CleanupExpired(1 * time.Hour)
				stats := s.GetStats()
				// Only log if logger is available
				if s.logger != nil {
					s.logger.Debugw("Correlation state cleanup completed",
						"totalRules", stats.TotalRules,
						"totalGroups", stats.TotalGroups,
						"totalEvents", stats.TotalEvents,
						"totalMetrics", stats.TotalMetrics)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ComputeGroupKey creates a hash key from field values for grouping
func ComputeGroupKey(event *core.Event, groupByFields []string) string {
	if len(groupByFields) == 0 {
		return "default"
	}

	// Sort fields for consistent hashing
	sort.Strings(groupByFields)

	// Build key from field values
	keyParts := make([]string, 0, len(groupByFields))
	for _, field := range groupByFields {
		value := getEventField(event, field)
		keyParts = append(keyParts, fmt.Sprintf("%s=%v", field, value))
	}

	// Create hash of the key parts
	keyStr := ""
	for i, part := range keyParts {
		if i > 0 {
			keyStr += "|"
		}
		keyStr += part
	}

	// Hash the key to keep it manageable (using SHA-256 for security)
	hash := sha256.Sum256([]byte(keyStr))
	return hex.EncodeToString(hash[:])
}

// getEventField extracts a field value from an event
func getEventField(event *core.Event, field string) interface{} {
	switch field {
	case "event_id":
		return event.EventID
	case "timestamp":
		return event.Timestamp
	case "source_format":
		return event.SourceFormat
	case "source_ip":
		return event.SourceIP
	case "event_type":
		return event.EventType
	case "severity":
		return event.Severity
	default:
		// Check in Fields map
		if event.Fields != nil {
			if val, ok := event.Fields[field]; ok {
				return val
			}
		}
		return nil
	}
}
