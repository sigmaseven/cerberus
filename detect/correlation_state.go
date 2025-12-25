package detect

import (
	"context"
	"sort"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/util/goroutine"
	"go.uber.org/zap"
)

// CorrelationStateManager manages correlation state for correlation rules
type CorrelationStateManager interface {
	// EvaluateCorrelationRule checks if a correlation rule matches based on event sequence
	EvaluateCorrelationRule(rule core.CorrelationRule, event *core.Event) bool
	// Reset clears all correlation state
	Reset()
	// Stop stops the cleanup goroutine
	Stop()
	// GetStats returns statistics about the correlation state
	GetStats() CorrelationStateStats
}

// CorrelationStateStats provides statistics about correlation state
type CorrelationStateStats struct {
	TotalRules    int
	TotalEvents   int
	MemoryUsageMB float64
}

// correlationStateEntry holds events and metadata for a correlation rule
type correlationStateEntry struct {
	events     []*core.Event
	lastAccess time.Time
}

// correlationStateManagerImpl implements CorrelationStateManager
type correlationStateManagerImpl struct {
	state          map[string]*correlationStateEntry
	stateMu        sync.RWMutex
	correlationTTL int // seconds
	maxRules       int
	cleanupCtx     context.Context
	cleanupCancel  context.CancelFunc
	cleanupWg      sync.WaitGroup // TASK 147: Track cleanup goroutine lifecycle
	logger         *zap.SugaredLogger
}

// NewCorrelationStateManager creates a new correlation state manager
func NewCorrelationStateManager(correlationTTL int, maxRules int, logger *zap.SugaredLogger) CorrelationStateManager {
	csm := &correlationStateManagerImpl{
		state:          make(map[string]*correlationStateEntry),
		correlationTTL: correlationTTL,
		maxRules:       maxRules,
		logger:         logger,
	}

	// Start periodic cleanup
	ctx, cancel := context.WithCancel(context.Background())
	csm.cleanupCtx = ctx
	csm.cleanupCancel = cancel
	csm.startStateCleanup(ctx)

	return csm
}

// EvaluateCorrelationRule checks if a correlation rule matches based on event sequence
func (csm *correlationStateManagerImpl) EvaluateCorrelationRule(rule core.CorrelationRule, event *core.Event) bool {
	csm.stateMu.Lock()
	defer csm.stateMu.Unlock()

	now := time.Now()

	// Get or create state entry for this rule
	entry, exists := csm.state[rule.ID]
	if !exists {
		// Check if we've reached the maximum number of rules
		if len(csm.state) >= csm.maxRules {
			csm.evictOldestRuleLocked()
		}
		entry = &correlationStateEntry{
			events:     make([]*core.Event, 0),
			lastAccess: now,
		}
		csm.state[rule.ID] = entry
	} else {
		entry.lastAccess = now
	}

	events := entry.events

	// Prevent memory exhaustion by limiting events per correlation rule
	if len(events) >= core.MaxCorrelationEventsPerWindow {
		// Remove oldest event(s) to make room for new one
		// Keep MaxCorrelationEventsPerWindow - 1 events to allow insertion of the new event
		keepCount := core.MaxCorrelationEventsPerWindow - 1
		if keepCount < 0 {
			keepCount = 0
		}
		if len(events) > keepCount {
			events = events[len(events)-keepCount:]
			// Update entry.events to reflect the memory limit enforcement
			entry.events = events
		}
	}

	// Find insertion point to maintain sorted order
	insertIndex := sort.Search(len(events), func(i int) bool {
		if events[i].Timestamp.Equal(event.Timestamp) {
			return events[i].EventID >= event.EventID
		}
		return events[i].Timestamp.After(event.Timestamp)
	})
	// Insert event at the correct position - efficient insertion without intermediate slice
	events = append(events, nil)                       // Extend slice by one
	copy(events[insertIndex+1:], events[insertIndex:]) // Shift elements right
	events[insertIndex] = event                        // Insert new event

	// Clean up expired events from the front before window filtering
	for len(events) > 0 && now.Sub(events[0].Timestamp).Seconds() > float64(csm.correlationTTL) {
		events = events[1:]
	}

	// Clean up old events outside the window
	windowStart := now.Add(-rule.Window)
	// Find the first event within the window
	startIndex := sort.Search(len(events), func(i int) bool {
		return events[i].Timestamp.After(windowStart) || events[i].Timestamp.Equal(windowStart)
	})
	validEvents := events[startIndex:]

	if len(validEvents) == 0 {
		return false
	}
	entry.events = validEvents

	// Check if sequence matches
	if len(validEvents) < len(rule.Sequence) {
		return false
	}

	// Check the last len(sequence) events match the sequence in order
	start := len(validEvents) - len(rule.Sequence)
	for i, eventType := range rule.Sequence {
		// Extract event_type - check struct field first, then Fields
		var evtType string
		if validEvents[start+i].EventType != "" {
			evtType = validEvents[start+i].EventType
		} else if validEvents[start+i].Fields != nil {
			if et, ok := validEvents[start+i].Fields["event_type"].(string); ok {
				evtType = et
			}
		}
		if evtType != eventType {
			return false
		}
	}

	// Clear state after successful match to prevent duplicate matches
	delete(csm.state, rule.ID)

	return true
}

// Reset clears all correlation state
func (csm *correlationStateManagerImpl) Reset() {
	csm.stateMu.Lock()
	defer csm.stateMu.Unlock()
	csm.state = make(map[string]*correlationStateEntry)
}

// Stop stops the cleanup goroutine and waits for it to finish
// TASK 147: Added WaitGroup.Wait() with timeout for graceful shutdown
func (csm *correlationStateManagerImpl) Stop() {
	if csm.cleanupCancel != nil {
		csm.cleanupCancel()
	}

	// Wait for cleanup goroutine with timeout
	done := make(chan struct{})
	go func() {
		csm.cleanupWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Cleanup goroutine stopped successfully
	case <-time.After(5 * time.Second):
		if csm.logger != nil {
			csm.logger.Warn("correlation-state-cleanup goroutine did not stop within 5s")
		}
	}
}

// GetStats returns statistics about the correlation state
func (csm *correlationStateManagerImpl) GetStats() CorrelationStateStats {
	csm.stateMu.RLock()
	defer csm.stateMu.RUnlock()

	totalEvents := 0
	for _, entry := range csm.state {
		totalEvents += len(entry.events)
	}

	return CorrelationStateStats{
		TotalRules:  len(csm.state),
		TotalEvents: totalEvents,
		// MemoryUsageMB would need more sophisticated calculation
		MemoryUsageMB: 0,
	}
}

// startStateCleanup runs periodic cleanup of expired correlation state
func (csm *correlationStateManagerImpl) startStateCleanup(ctx context.Context) {
	// Calculate cleanup interval - run at half the TTL, minimum 30 seconds
	var cleanupInterval time.Duration
	if csm.correlationTTL <= 0 {
		cleanupInterval = 30 * time.Second
	} else {
		// Prevent overflow: cap at reasonable maximum (7 days = 604800 seconds)
		// This prevents int64 overflow when multiplying by time.Second (1 billion ns)
		ttl := csm.correlationTTL
		const maxReasonableTTL = 604800 // 7 days in seconds
		if ttl > maxReasonableTTL {
			csm.logger.Warnw("Correlation TTL exceeds reasonable maximum, capping",
				"requested_ttl", ttl,
				"max_ttl", maxReasonableTTL)
			ttl = maxReasonableTTL
		}
		cleanupInterval = time.Duration(ttl/2) * time.Second
		if cleanupInterval < 30*time.Second {
			cleanupInterval = 30 * time.Second
		}
	}

	ticker := time.NewTicker(cleanupInterval)
	// TASK 147: Track cleanup goroutine with WaitGroup and panic recovery
	csm.cleanupWg.Add(1)
	go func() {
		defer csm.cleanupWg.Done()
		defer goroutine.Recover("correlation-state-cleanup", csm.logger)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				csm.cleanupExpiredState()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupExpiredState removes expired entries from correlation state
func (csm *correlationStateManagerImpl) cleanupExpiredState() {
	csm.stateMu.Lock()
	defer csm.stateMu.Unlock()

	now := time.Now()
	ttlDuration := time.Duration(csm.correlationTTL) * time.Second
	removedRules := 0
	removedEvents := 0

	// Additional cleanup: remove idle correlation states (no activity for 2x TTL)
	inactivityThreshold := ttlDuration * 2

	processedCount := 0
	for ruleID, entry := range csm.state {
		// Check context cancellation periodically (every 100 rules)
		if processedCount%100 == 0 {
			select {
			case <-csm.cleanupCtx.Done():
				csm.logger.Debugw("Context cancelled during correlation state cleanup",
					"processed_rules", processedCount,
					"removed_rules", removedRules,
					"removed_events", removedEvents)
				return
			default:
			}
		}
		processedCount++

		events := entry.events
		if len(events) == 0 {
			delete(csm.state, ruleID)
			removedRules++
			continue
		}

		// FIX #30: Clean up idle correlation states with no activity
		// If the correlation state has been inactive for 2x the TTL, remove it entirely
		timeSinceLastAccess := now.Sub(entry.lastAccess)
		if timeSinceLastAccess > inactivityThreshold {
			delete(csm.state, ruleID)
			removedRules++
			csm.logger.Debugw("Removed idle correlation state",
				"ruleID", ruleID,
				"timeSinceLastAccess", timeSinceLastAccess,
				"inactivityThreshold", inactivityThreshold)
			continue
		}

		// Check if oldest event is expired
		oldestEvent := events[0]
		if now.Sub(oldestEvent.Timestamp) > ttlDuration {
			// Remove all expired events
			cutoff := now.Add(-ttlDuration)
			validIdx := sort.Search(len(events), func(i int) bool {
				return events[i].Timestamp.After(cutoff)
			})

			if validIdx >= len(events) {
				// All events expired
				delete(csm.state, ruleID)
				removedRules++
			} else {
				// Keep only valid events
				removedEvents += validIdx
				entry.events = events[validIdx:]
			}
		}
	}

	if removedRules > 0 || removedEvents > 0 {
		csm.logger.Debugw("Cleaned up expired correlation state",
			"removedRules", removedRules,
			"removedEvents", removedEvents,
			"remainingRules", len(csm.state))
	}

	// Additional memory management: if still over limit after cleanup, evict oldest rules
	for len(csm.state) >= csm.maxRules {
		csm.evictOldestRuleLocked()
	}
}

// TASK 138: Removed unused evictOldestRule wrapper (evictOldestRuleLocked called directly)

// evictOldestRuleLocked removes the least recently accessed correlation rule (caller must hold stateMu lock)
// Performance optimization: Build temporary slice instead of iterating twice (O(n) vs O(2n))
func (csm *correlationStateManagerImpl) evictOldestRuleLocked() {
	if len(csm.state) == 0 {
		return
	}

	var oldestRuleID string
	oldestTime := time.Now() // Initialize with current time

	// Single pass: find the rule with the oldest lastAccess time
	// Performance: 2x faster than double iteration, reduces CPU usage during eviction
	for ruleID, entry := range csm.state {
		if entry.lastAccess.Before(oldestTime) {
			oldestRuleID = ruleID
			oldestTime = entry.lastAccess
		}
	}

	// If no rule was found older than now, evict the first one encountered
	if oldestRuleID == "" {
		for ruleID := range csm.state {
			oldestRuleID = ruleID
			break
		}
	}

	if oldestRuleID != "" {
		delete(csm.state, oldestRuleID)
		csm.logger.Debugw("Evicted oldest correlation rule to maintain memory limits",
			"ruleID", oldestRuleID,
			"lastAccess", oldestTime,
			"totalRules", len(csm.state))
	}
}
