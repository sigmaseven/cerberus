package detect

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"cerberus/core"
)

func TestNewSigmaRuleCache_Defaults(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	if cache == nil {
		t.Fatal("NewSigmaRuleCache returned nil")
	}

	if cache.config.MaxEntries != 1000 {
		t.Errorf("Expected MaxEntries=1000, got %d", cache.config.MaxEntries)
	}

	if cache.config.TTL != 30*time.Minute {
		t.Errorf("Expected TTL=30m, got %v", cache.config.TTL)
	}

	if cache.config.CleanupInterval != 5*time.Minute {
		t.Errorf("Expected CleanupInterval=5m, got %v", cache.config.CleanupInterval)
	}
}

func TestNewSigmaRuleCache_CustomConfig(t *testing.T) {
	config := &SigmaRuleCacheConfig{
		MaxEntries:      500,
		TTL:             10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}

	cache := NewSigmaRuleCache(context.Background(), config)

	if cache.config.MaxEntries != 500 {
		t.Errorf("Expected MaxEntries=500, got %d", cache.config.MaxEntries)
	}

	if cache.config.TTL != 10*time.Minute {
		t.Errorf("Expected TTL=10m, got %v", cache.config.TTL)
	}
}

func TestSigmaRuleCache_PutAndGet(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	entry := &CachedSigmaRule{
		RuleID:     "test-rule-1",
		ParsedYAML: map[string]interface{}{"title": "Test Rule"},
	}

	err := cache.Put(entry)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	retrieved := cache.Get(entry.RuleID)
	if retrieved == nil {
		t.Fatal("Get returned nil for cached entry")
	}

	if retrieved.RuleID != entry.RuleID {
		t.Errorf("Expected RuleID=%s, got %s", entry.RuleID, retrieved.RuleID)
	}

	// Verify access count incremented
	if retrieved.AccessCount != 1 {
		t.Errorf("Expected AccessCount=1, got %d", retrieved.AccessCount)
	}
}

func TestSigmaRuleCache_Put_NilEntry(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	err := cache.Put(nil)
	if err == nil {
		t.Error("Expected error for nil entry, got nil")
	}
}

func TestSigmaRuleCache_Put_EmptyRuleID(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	err := cache.Put(&CachedSigmaRule{RuleID: ""})
	if err == nil {
		t.Error("Expected error for empty rule ID, got nil")
	}
}

func TestSigmaRuleCache_Get_NonExistent(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	retrieved := cache.Get("non-existent")
	if retrieved != nil {
		t.Error("Expected nil for non-existent entry")
	}

	stats := cache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
}

func TestSigmaRuleCache_LRUEviction(t *testing.T) {
	config := &SigmaRuleCacheConfig{
		MaxEntries: 3,
		TTL:        0, // Disable TTL
	}
	cache := NewSigmaRuleCache(context.Background(), config)

	// Add 3 entries
	for i := 1; i <= 3; i++ {
		entry := &CachedSigmaRule{
			RuleID: fmt.Sprintf("rule-%d", i),
		}
		cache.Put(entry)
	}

	if cache.Size() != 3 {
		t.Errorf("Expected size=3, got %d", cache.Size())
	}

	// Access rule-1 to make it recently used
	cache.Get("rule-1")

	// Add a 4th entry - should evict rule-2 (least recently used after rule-1 access)
	cache.Put(&CachedSigmaRule{RuleID: "rule-4"})

	if cache.Size() != 3 {
		t.Errorf("Expected size=3 after eviction, got %d", cache.Size())
	}

	// rule-1 should still be cached (was accessed)
	if cache.Get("rule-1") == nil {
		t.Error("rule-1 should still be in cache (recently accessed)")
	}

	// rule-4 should be cached
	if cache.Get("rule-4") == nil {
		t.Error("rule-4 should be in cache")
	}

	// Verify eviction was recorded
	stats := cache.GetStats()
	if stats.Evictions != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats.Evictions)
	}
}

func TestSigmaRuleCache_Update(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Add initial entry
	entry := &CachedSigmaRule{
		RuleID:     "test-rule",
		ParsedYAML: map[string]interface{}{"title": "Original"},
	}
	cache.Put(entry)

	// Update entry
	updated := &CachedSigmaRule{
		RuleID:     "test-rule",
		ParsedYAML: map[string]interface{}{"title": "Updated"},
	}
	cache.Put(updated)

	// Verify update
	retrieved := cache.Get("test-rule")
	if retrieved == nil {
		t.Fatal("Get returned nil")
	}

	title, ok := retrieved.ParsedYAML["title"].(string)
	if !ok || title != "Updated" {
		t.Errorf("Expected title='Updated', got '%v'", title)
	}

	// Should still have only 1 entry
	if cache.Size() != 1 {
		t.Errorf("Expected size=1, got %d", cache.Size())
	}
}

func TestSigmaRuleCache_Invalidate(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	entry := &CachedSigmaRule{RuleID: "test-rule"}
	cache.Put(entry)

	cache.Invalidate("test-rule")

	if cache.Get("test-rule") != nil {
		t.Error("Entry should be invalidated")
	}

	if cache.Size() != 0 {
		t.Errorf("Expected size=0, got %d", cache.Size())
	}
}

func TestSigmaRuleCache_InvalidateNonExistent(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Should not panic
	cache.Invalidate("non-existent")
}

func TestSigmaRuleCache_InvalidateAll(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Add multiple entries
	for i := 1; i <= 5; i++ {
		cache.Put(&CachedSigmaRule{RuleID: fmt.Sprintf("rule-%d", i)})
	}

	if cache.Size() != 5 {
		t.Errorf("Expected size=5, got %d", cache.Size())
	}

	cache.InvalidateAll()

	if cache.Size() != 0 {
		t.Errorf("Expected size=0 after InvalidateAll, got %d", cache.Size())
	}
}

func TestSigmaRuleCache_Contains(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	cache.Put(&CachedSigmaRule{RuleID: "test-rule"})

	if !cache.Contains("test-rule") {
		t.Error("Contains should return true for cached entry")
	}

	if cache.Contains("non-existent") {
		t.Error("Contains should return false for non-existent entry")
	}
}

func TestSigmaRuleCache_ConcurrentAccess(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	const goroutines = 50
	const operations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrent writers
	for i := 0; i < goroutines/2; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				ruleID := fmt.Sprintf("rule-%d-%d", id, j%10)
				cache.Put(&CachedSigmaRule{
					RuleID:     ruleID,
					ParsedYAML: map[string]interface{}{"id": ruleID},
				})
			}
		}(i)
	}

	// Concurrent readers
	for i := goroutines / 2; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				ruleID := fmt.Sprintf("rule-%d-%d", id%10, j%10)
				cache.Get(ruleID)
				cache.Contains(ruleID)
				cache.GetStats()
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is in consistent state
	stats := cache.GetStats()
	t.Logf("After concurrent access: size=%d, hits=%d, misses=%d",
		stats.Size, stats.Hits, stats.Misses)
}

func TestSigmaRuleCache_TTLExpiration(t *testing.T) {
	config := &SigmaRuleCacheConfig{
		MaxEntries:      100,
		TTL:             100 * time.Millisecond,
		CleanupInterval: 0, // Disable cleanup for this test
	}
	cache := NewSigmaRuleCache(context.Background(), config)

	entry := &CachedSigmaRule{RuleID: "test-rule"}
	cache.Put(entry)

	// Should be cached immediately
	if cache.Get("test-rule") == nil {
		t.Error("Entry should be cached")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired now (Get checks TTL)
	if cache.Get("test-rule") != nil {
		t.Error("Entry should be expired")
	}

	stats := cache.GetStats()
	if stats.Expirations != 1 {
		t.Errorf("Expected 1 expiration, got %d", stats.Expirations)
	}
}

func TestSigmaRuleCache_StartAndStop(t *testing.T) {
	config := &SigmaRuleCacheConfig{
		MaxEntries:      100,
		TTL:             50 * time.Millisecond,
		CleanupInterval: 10 * time.Millisecond,
	}
	cache := NewSigmaRuleCache(context.Background(), config)

	// Add some entries
	for i := 0; i < 10; i++ {
		cache.Put(&CachedSigmaRule{RuleID: fmt.Sprintf("rule-%d", i)})
	}

	cache.StartCleanup()

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		cache.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good, Stop() returned
	case <-time.After(1 * time.Second):
		t.Error("Stop() timed out")
	}
}

func TestSigmaRuleCache_GetStats(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Generate some activity
	cache.Put(&CachedSigmaRule{RuleID: "rule-1"})
	cache.Put(&CachedSigmaRule{RuleID: "rule-2"})
	cache.Get("rule-1")       // Hit
	cache.Get("rule-1")       // Hit
	cache.Get("non-existent") // Miss

	stats := cache.GetStats()

	if stats.Size != 2 {
		t.Errorf("Expected Size=2, got %d", stats.Size)
	}

	if stats.Hits != 2 {
		t.Errorf("Expected Hits=2, got %d", stats.Hits)
	}

	if stats.Misses != 1 {
		t.Errorf("Expected Misses=1, got %d", stats.Misses)
	}
}

func TestSigmaRuleCache_StopWithoutStart(t *testing.T) {
	// This tests the fix for goroutine leak - Stop() should not block
	// even if StartCleanup() was never called
	cache := NewSigmaRuleCache(context.Background(), nil)

	cache.Put(&CachedSigmaRule{RuleID: "rule-1"})

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		cache.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good, Stop() returned without blocking
	case <-time.After(1 * time.Second):
		t.Error("Stop() without StartCleanup() should not block")
	}
}

func TestSigmaRuleCache_DoubleStartCleanup(t *testing.T) {
	// StartCleanup should be safe to call multiple times
	config := &SigmaRuleCacheConfig{
		MaxEntries:      100,
		TTL:             100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	cache := NewSigmaRuleCache(context.Background(), config)

	// Call StartCleanup twice - should not panic or start multiple goroutines
	cache.StartCleanup()
	cache.StartCleanup()

	// Should still stop cleanly
	done := make(chan struct{})
	go func() {
		cache.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		t.Error("Stop() timed out after double StartCleanup")
	}
}

func TestSigmaRuleCache_GetCorrelationRuleIDs(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Add rules with and without correlation blocks
	cache.Put(&CachedSigmaRule{
		RuleID:      "rule-1",
		Correlation: nil, // No correlation
	})

	cache.Put(&CachedSigmaRule{
		RuleID: "rule-2",
		Correlation: &core.SigmaCorrelation{
			Type: "event_count",
		},
	})

	cache.Put(&CachedSigmaRule{
		RuleID: "rule-3",
		Correlation: &core.SigmaCorrelation{
			Type: "value_count",
		},
	})

	cache.Put(&CachedSigmaRule{
		RuleID:      "rule-4",
		Correlation: nil, // No correlation
	})

	// Get correlation rule IDs
	correlationIDs := cache.GetCorrelationRuleIDs()

	// Should return only rules with correlation blocks
	if len(correlationIDs) != 2 {
		t.Errorf("Expected 2 correlation rules, got %d", len(correlationIDs))
	}

	// Check that correct IDs are returned
	expectedIDs := map[string]bool{"rule-2": true, "rule-3": true}
	for _, id := range correlationIDs {
		if !expectedIDs[id] {
			t.Errorf("Unexpected correlation rule ID: %s", id)
		}
		delete(expectedIDs, id)
	}

	if len(expectedIDs) > 0 {
		t.Errorf("Missing expected correlation rule IDs: %v", expectedIDs)
	}
}

func TestSigmaRuleCache_GetCorrelationRuleIDs_EmptyCache(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	correlationIDs := cache.GetCorrelationRuleIDs()

	if correlationIDs == nil {
		t.Error("GetCorrelationRuleIDs should return non-nil slice")
	}

	if len(correlationIDs) != 0 {
		t.Errorf("Expected 0 correlation rules in empty cache, got %d", len(correlationIDs))
	}
}

func TestSigmaRuleCache_GetCorrelationRuleIDs_Concurrent(t *testing.T) {
	cache := NewSigmaRuleCache(context.Background(), nil)

	// Add some correlation rules
	for i := 0; i < 10; i++ {
		cache.Put(&CachedSigmaRule{
			RuleID: fmt.Sprintf("corr-rule-%d", i),
			Correlation: &core.SigmaCorrelation{
				Type: "event_count",
			},
		})
	}

	// Add some regular rules
	for i := 0; i < 10; i++ {
		cache.Put(&CachedSigmaRule{
			RuleID:      fmt.Sprintf("regular-rule-%d", i),
			Correlation: nil,
		})
	}

	// Test concurrent access to GetCorrelationRuleIDs
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)

	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ids := cache.GetCorrelationRuleIDs()
			if len(ids) != 10 {
				errors <- fmt.Errorf("expected 10 correlation rules, got %d", len(ids))
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}
