package detect

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"cerberus/core"
)

// CachedSigmaRule stores a parsed SIGMA rule with its condition AST and metadata.
// This struct represents a cache entry with LRU tracking information.
//
// Thread-Safety:
//   - Access to cached rules is protected by SigmaRuleCache.mu
//   - Individual fields should not be modified after creation
//
// Memory Layout:
//   - ParsedYAML: ~2KB average (varies with rule complexity)
//   - ConditionAST: ~1KB average (varies with condition complexity)
//   - DetectionBlocks: ~500 bytes average per block
//   - Correlation: ~500 bytes (if present)
//   - Total: ~5-10KB per cached rule
type CachedSigmaRule struct {
	// RuleID is the unique identifier of the SIGMA rule
	RuleID string

	// ParsedYAML contains the parsed YAML structure from SigmaYAML field
	ParsedYAML map[string]interface{}

	// ConditionAST is the parsed condition expression tree
	ConditionAST ConditionNode

	// DetectionBlocks maps block names to their field conditions
	// e.g., {"selection": {"Image|endswith": ".exe"}, "filter": {"User": "SYSTEM"}}
	DetectionBlocks map[string]map[string]interface{}

	// Logsource contains the logsource definition for field mapping
	Logsource map[string]interface{}

	// Correlation contains the parsed correlation configuration (optional)
	// Present only for hybrid detection+correlation SIGMA rules
	Correlation *core.SigmaCorrelation

	// CachedAt is when this entry was added to the cache
	CachedAt time.Time

	// LastAccessed is when this entry was last retrieved
	LastAccessed time.Time

	// AccessCount tracks how many times this entry has been accessed
	AccessCount int64

	// lruElement is a pointer to the LRU list element for O(1) removal/promotion
	// This is internal and should not be accessed directly
	lruElement *list.Element
}

// SigmaRuleCacheConfig holds configuration options for the cache.
type SigmaRuleCacheConfig struct {
	// MaxEntries is the maximum number of rules to cache (0 = use default)
	MaxEntries int

	// TTL is the time-to-live for cache entries (0 = no expiration)
	TTL time.Duration

	// CleanupInterval is how often to run background cleanup (0 = no cleanup)
	CleanupInterval time.Duration
}

// DefaultSigmaRuleCacheConfig returns sensible defaults for production use.
//
// Sizing rationale:
//   - MaxEntries: 1000 rules ≈ 5-10MB memory, covers typical deployments
//   - TTL: 30 minutes allows hot rules to stay cached during analysis sessions
//   - CleanupInterval: 5 minutes balances CPU overhead vs. memory reclamation
func DefaultSigmaRuleCacheConfig() SigmaRuleCacheConfig {
	return SigmaRuleCacheConfig{
		MaxEntries:      1000,
		TTL:             30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

// SigmaRuleCache provides thread-safe LRU caching of parsed SIGMA rules.
//
// Architecture:
//   - HashMap (rules) provides O(1) lookup by rule ID
//   - Doubly-linked list (lruList) provides O(1) LRU eviction
//   - RWMutex allows concurrent reads, serialized writes
//
// Eviction Policy:
//   - LRU (Least Recently Used) when cache reaches MaxEntries
//   - TTL-based expiration if configured
//   - Manual invalidation via Invalidate/InvalidateAll
//
// Thread-Safety Guarantees:
//   - All public methods are safe for concurrent use
//   - Get operations use RLock (concurrent reads allowed)
//   - Put/Invalidate operations use Lock (serialized writes)
//
// Performance Characteristics:
//   - Get: O(1) hash lookup + O(1) LRU promotion = O(1) total
//   - Put: O(1) hash insert + O(1) list prepend = O(1) total
//   - Evict: O(1) list removal + O(1) hash delete = O(1) total
type SigmaRuleCache struct {
	// mu protects all cache state (rules map and lruList)
	mu sync.RWMutex

	// rules maps rule ID to cached rule
	rules map[string]*CachedSigmaRule

	// lruList maintains access order for LRU eviction
	// Most recently accessed at front, least recently accessed at back
	lruList *list.List

	// config holds cache configuration
	config SigmaRuleCacheConfig

	// stats tracks cache statistics using atomic operations for thread-safety
	stats cacheStatsAtomic

	// ctx is the context for background cleanup
	ctx context.Context

	// cancel cancels the background cleanup goroutine
	cancel context.CancelFunc

	// cleanupDone signals when cleanup goroutine has exited
	cleanupDone chan struct{}

	// cleanupStarted tracks if StartCleanup was called (to prevent Stop() blocking)
	cleanupStarted int32 // Use atomic.LoadInt32/StoreInt32
}

// CacheStats tracks cache performance metrics.
// All fields are safe for concurrent read access as they are snapshot copies.
type CacheStats struct {
	Hits        int64
	Misses      int64
	Evictions   int64
	Expirations int64
	Size        int
}

// cacheStatsAtomic holds atomic counters for thread-safe statistics updates.
// These are internal and exposed via GetStats() as CacheStats snapshots.
type cacheStatsAtomic struct {
	hits        int64 // Use atomic.AddInt64/LoadInt64
	misses      int64
	evictions   int64
	expirations int64
}

// NewSigmaRuleCache creates a new cache with the given configuration.
// If config is nil, uses DefaultSigmaRuleCacheConfig().
//
// TASK 144.4: Now accepts parent context for lifecycle coordination
//
// Parameters:
//   - parentCtx: Parent context for lifecycle management (nil = use Background)
//   - config: Cache configuration (nil = use defaults)
//
// The returned cache is immediately ready for use but background cleanup
// is not started. Call StartCleanup() to enable TTL-based expiration.
func NewSigmaRuleCache(parentCtx context.Context, config *SigmaRuleCacheConfig) *SigmaRuleCache {
	cfg := DefaultSigmaRuleCacheConfig()
	if config != nil {
		if config.MaxEntries > 0 {
			cfg.MaxEntries = config.MaxEntries
		}
		if config.TTL > 0 {
			cfg.TTL = config.TTL
		}
		if config.CleanupInterval > 0 {
			cfg.CleanupInterval = config.CleanupInterval
		}
	}

	// TASK 144.4: Use parent context if provided, otherwise create isolated context
	// This allows parent cancellation to propagate to cleanup goroutine
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)

	return &SigmaRuleCache{
		rules:       make(map[string]*CachedSigmaRule),
		lruList:     list.New(),
		config:      cfg,
		ctx:         ctx,
		cancel:      cancel,
		cleanupDone: make(chan struct{}),
	}
}

// StartCleanup starts the background cleanup goroutine for TTL-based expiration.
// This should be called after creating the cache if TTL expiration is desired.
// Safe to call multiple times - subsequent calls are no-ops.
//
// The cleanup goroutine runs until Stop() is called or the context is cancelled.
func (c *SigmaRuleCache) StartCleanup() {
	// Use atomic CAS to ensure we only start once
	if !atomic.CompareAndSwapInt32(&c.cleanupStarted, 0, 1) {
		// Already started
		return
	}

	if c.config.CleanupInterval <= 0 || c.config.TTL <= 0 {
		// No cleanup needed - close immediately so Stop() doesn't block
		close(c.cleanupDone)
		return
	}

	go c.cleanupLoop()
}

// cleanupLoop runs periodic cleanup of expired entries.
func (c *SigmaRuleCache) cleanupLoop() {
	defer close(c.cleanupDone)

	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.removeExpired()
		}
	}
}

// removeExpired removes all entries that have exceeded their TTL.
func (c *SigmaRuleCache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.config.TTL <= 0 {
		return
	}

	now := time.Now()
	expireThreshold := now.Add(-c.config.TTL)

	// Iterate from back (oldest) to front (newest) for efficient removal
	for e := c.lruList.Back(); e != nil; {
		entry, ok := e.Value.(*CachedSigmaRule)
		if !ok || entry == nil {
			// Skip invalid entries (defensive)
			prev := e.Prev()
			c.lruList.Remove(e)
			e = prev
			continue
		}

		// Check if entry is expired based on last access time
		if entry.LastAccessed.Before(expireThreshold) {
			prev := e.Prev()
			c.lruList.Remove(e)
			delete(c.rules, entry.RuleID)
			atomic.AddInt64(&c.stats.expirations, 1)
			e = prev
		} else {
			// Since list is ordered by access time, if this entry isn't expired,
			// entries after it (toward front) won't be either
			break
		}
	}
}

// Get retrieves a cached rule by ID.
// Returns nil if the rule is not in the cache.
//
// Thread-safe: Uses write lock for LRU updates.
// Returns a shallow copy to prevent mutation of cached state.
// The returned copy shares immutable data (ParsedYAML, DetectionBlocks) with
// the cached version - these should NOT be modified by callers.
func (c *SigmaRuleCache) Get(ruleID string) *CachedSigmaRule {
	c.mu.Lock() // Need write lock to update LRU order
	defer c.mu.Unlock()

	entry, exists := c.rules[ruleID]
	if !exists {
		atomic.AddInt64(&c.stats.misses, 1)
		return nil
	}

	// Check TTL expiration
	if c.config.TTL > 0 && time.Since(entry.LastAccessed) > c.config.TTL {
		// Entry is expired, remove it
		c.lruList.Remove(entry.lruElement)
		delete(c.rules, ruleID)
		atomic.AddInt64(&c.stats.expirations, 1)
		return nil
	}

	// Update access metadata
	entry.LastAccessed = time.Now()
	entry.AccessCount++

	// Move to front of LRU list
	c.lruList.MoveToFront(entry.lruElement)

	atomic.AddInt64(&c.stats.hits, 1)

	// Return a shallow copy to prevent callers from mutating cache state
	// The maps (ParsedYAML, DetectionBlocks, Logsource) are shared references
	// but should be treated as read-only by callers
	return &CachedSigmaRule{
		RuleID:          entry.RuleID,
		ParsedYAML:      entry.ParsedYAML,      // Shared reference (read-only)
		ConditionAST:    entry.ConditionAST,    // Shared reference (read-only)
		DetectionBlocks: entry.DetectionBlocks, // Shared reference (read-only)
		Logsource:       entry.Logsource,       // Shared reference (read-only)
		Correlation:     entry.Correlation,     // Shared reference (read-only)
		CachedAt:        entry.CachedAt,
		LastAccessed:    entry.LastAccessed,
		AccessCount:     entry.AccessCount,
		// lruElement is intentionally not copied - it's internal state
	}
}

// Put adds or updates a cached rule.
// If the cache is full, evicts the least recently used entry.
//
// Thread-safe: Uses write lock.
//
// Parameters:
//   - entry: The cached rule to store. RuleID must be set.
//
// Returns error if entry is nil or RuleID is empty.
func (c *SigmaRuleCache) Put(entry *CachedSigmaRule) error {
	if entry == nil {
		return fmt.Errorf("cannot cache nil entry")
	}
	if entry.RuleID == "" {
		return fmt.Errorf("cannot cache entry with empty rule ID")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if rule already exists
	if existing, exists := c.rules[entry.RuleID]; exists {
		// Update existing entry
		existing.ParsedYAML = entry.ParsedYAML
		existing.ConditionAST = entry.ConditionAST
		existing.DetectionBlocks = entry.DetectionBlocks
		existing.Logsource = entry.Logsource
		existing.Correlation = entry.Correlation
		existing.CachedAt = time.Now()
		existing.LastAccessed = time.Now()
		// Move to front
		c.lruList.MoveToFront(existing.lruElement)
		return nil
	}

	// Check if we need to evict
	if len(c.rules) >= c.config.MaxEntries {
		c.evictLRU()
	}

	// Add new entry
	now := time.Now()
	entry.CachedAt = now
	entry.LastAccessed = now
	entry.lruElement = c.lruList.PushFront(entry)
	c.rules[entry.RuleID] = entry

	return nil
}

// evictLRU removes the least recently used entry.
// Must be called with mu held (write lock).
func (c *SigmaRuleCache) evictLRU() {
	// Get the back element (least recently used)
	back := c.lruList.Back()
	if back == nil {
		return
	}

	entry, ok := back.Value.(*CachedSigmaRule)
	if !ok || entry == nil {
		// Invalid entry - just remove from list
		c.lruList.Remove(back)
		return
	}

	c.lruList.Remove(back)
	delete(c.rules, entry.RuleID)
	atomic.AddInt64(&c.stats.evictions, 1)
}

// Invalidate removes a specific rule from the cache.
// No-op if the rule is not cached.
//
// Thread-safe: Uses write lock.
func (c *SigmaRuleCache) Invalidate(ruleID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.rules[ruleID]
	if !exists {
		return
	}

	c.lruList.Remove(entry.lruElement)
	delete(c.rules, ruleID)
}

// InvalidateAll removes all entries from the cache.
//
// Thread-safe: Uses write lock.
func (c *SigmaRuleCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rules = make(map[string]*CachedSigmaRule)
	c.lruList = list.New()
}

// GetStats returns a snapshot of cache statistics.
//
// Thread-safe: Uses atomic reads for stats and read lock for size.
func (c *SigmaRuleCache) GetStats() CacheStats {
	c.mu.RLock()
	size := len(c.rules)
	c.mu.RUnlock()

	return CacheStats{
		Hits:        atomic.LoadInt64(&c.stats.hits),
		Misses:      atomic.LoadInt64(&c.stats.misses),
		Evictions:   atomic.LoadInt64(&c.stats.evictions),
		Expirations: atomic.LoadInt64(&c.stats.expirations),
		Size:        size,
	}
}

// Stop stops the background cleanup goroutine and waits for it to exit.
// Safe to call even if StartCleanup was never called.
// Should be called during application shutdown.
func (c *SigmaRuleCache) Stop() {
	c.cancel()

	// Only wait for cleanupDone if StartCleanup was called
	if atomic.LoadInt32(&c.cleanupStarted) == 1 {
		<-c.cleanupDone
	}
}

// Size returns the current number of cached entries.
//
// Thread-safe: Uses read lock.
func (c *SigmaRuleCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

// Contains checks if a rule is in the cache without updating LRU order.
// This is useful for statistics and debugging without affecting cache behavior.
//
// Thread-safe: Uses read lock.
func (c *SigmaRuleCache) Contains(ruleID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.rules[ruleID]
	return exists
}

// GetCorrelationRuleIDs returns a snapshot of all rule IDs that have correlation blocks.
// This method provides safe access to correlation rules without exposing internal cache state.
//
// Thread-safe: Uses read lock for safe concurrent access.
//
// Returns:
//   - []string: List of rule IDs with correlation blocks (never nil, may be empty)
//
// Performance: O(n) where n is the number of cached rules.
// Use this when you need to iterate over correlation rules without holding the cache lock.
func (c *SigmaRuleCache) GetCorrelationRuleIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Always return non-nil slice for consistency
	ids := make([]string, 0)
	for ruleID, entry := range c.rules {
		if entry.Correlation != nil {
			ids = append(ids, ruleID)
		}
	}
	return ids
}
