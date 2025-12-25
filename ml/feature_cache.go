package ml

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// FeatureCache provides caching functionality for extracted features
type FeatureCache interface {
	// Get retrieves cached features for an event
	Get(ctx context.Context, eventID string) (*FeatureVector, error)

	// Set stores features for an event with TTL
	Set(ctx context.Context, features *FeatureVector, ttl time.Duration) error

	// Delete removes cached features for an event
	Delete(ctx context.Context, eventID string) error

	// Exists checks if features exist in cache for an event
	Exists(ctx context.Context, eventID string) (bool, error)

	// Clear removes all cached features
	Clear(ctx context.Context) error

	// GetStats returns cache statistics
	GetStats() CacheStats
}

// CacheStats holds cache performance statistics
type CacheStats struct {
	Hits         int64
	Misses       int64
	Sets         int64
	Deletes      int64
	HitRate      float64
	TotalEntries int64
}

// RedisFeatureCache implements FeatureCache using Redis
type RedisFeatureCache struct {
	redisClient *core.RedisCache
	keyPrefix   string
	logger      *zap.SugaredLogger
	stats       CacheStats
	statsMu     sync.RWMutex // protects stats
}

// NewRedisFeatureCache creates a new Redis-based feature cache
func NewRedisFeatureCache(redisClient *core.RedisCache, logger *zap.SugaredLogger) *RedisFeatureCache {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &RedisFeatureCache{
		redisClient: redisClient,
		keyPrefix:   "ml:features:",
		logger:      logger,
		stats:       CacheStats{},
	}
}

// Get retrieves cached features for an event
func (c *RedisFeatureCache) Get(ctx context.Context, eventID string) (*FeatureVector, error) {
	key := c.keyPrefix + eventID

	var features FeatureVector
	found, err := c.redisClient.Get(ctx, key, &features)
	if err != nil {
		c.logger.Errorw("Failed to get features from cache",
			"event_id", eventID,
			"error", err)
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	if !found {
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("features not found in cache for event %s", eventID)
	}

	c.statsMu.Lock()
	c.stats.Hits++
	c.statsMu.Unlock()
	return &features, nil
}

// Set stores features for an event with TTL
func (c *RedisFeatureCache) Set(ctx context.Context, features *FeatureVector, ttl time.Duration) error {
	if features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	key := c.keyPrefix + features.EventID

	if err := c.redisClient.Set(ctx, key, features, ttl); err != nil {
		c.logger.Errorw("Failed to set features in cache",
			"event_id", features.EventID,
			"error", err)
		return fmt.Errorf("cache set failed: %w", err)
	}

	c.statsMu.Lock()
	c.stats.Sets++
	c.statsMu.Unlock()
	return nil
}

// Delete removes cached features for an event
func (c *RedisFeatureCache) Delete(ctx context.Context, eventID string) error {
	key := c.keyPrefix + eventID

	if err := c.redisClient.Delete(ctx, key); err != nil {
		c.logger.Errorw("Failed to delete features from cache",
			"event_id", eventID,
			"error", err)
		return fmt.Errorf("cache delete failed: %w", err)
	}

	c.statsMu.Lock()
	c.stats.Deletes++
	c.statsMu.Unlock()
	return nil
}

// Exists checks if features exist in cache for an event
func (c *RedisFeatureCache) Exists(ctx context.Context, eventID string) (bool, error) {
	key := c.keyPrefix + eventID

	exists, err := c.redisClient.Exists(ctx, key)
	if err != nil {
		c.logger.Errorw("Failed to check feature existence in cache",
			"event_id", eventID,
			"error", err)
		return false, fmt.Errorf("cache exists check failed: %w", err)
	}

	return exists, nil
}

// Clear removes all cached features
func (c *RedisFeatureCache) Clear(ctx context.Context) error {
	// Use Redis SCAN to find all keys with our prefix
	// This is a simplified implementation - in production, you'd want to use Redis SCAN
	pattern := c.keyPrefix + "*"

	// For now, we'll just log that this operation is not implemented
	// In a real implementation, you'd need to:
	// 1. Use Redis SCAN or KEYS to find all matching keys
	// 2. Delete them in batches
	c.logger.Warnw("Clear operation not fully implemented - would require Redis SCAN/KEYS",
		"pattern", pattern)

	return fmt.Errorf("clear operation not implemented")
}

// GetStats returns cache statistics
func (c *RedisFeatureCache) GetStats() CacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	stats := c.stats
	totalRequests := stats.Hits + stats.Misses
	if totalRequests > 0 {
		stats.HitRate = float64(stats.Hits) / float64(totalRequests)
	}

	// Note: TotalEntries would require additional Redis queries
	// For now, we'll leave it as 0
	stats.TotalEntries = 0

	return stats
}

// MemoryFeatureCache implements FeatureCache using in-memory storage
type MemoryFeatureCache struct {
	data    map[string]*cacheEntry
	logger  *zap.SugaredLogger
	stats   CacheStats
	maxSize int          // maximum number of entries
	mu      sync.RWMutex // protects data and stats
}

// cacheEntry represents a cached feature vector with expiration
type cacheEntry struct {
	features  *FeatureVector
	expiresAt time.Time
}

// NewMemoryFeatureCache creates a new in-memory feature cache
func NewMemoryFeatureCache(logger *zap.SugaredLogger) *MemoryFeatureCache {
	return NewMemoryFeatureCacheWithLimit(logger, 10000) // Default max 10,000 entries
}

// NewMemoryFeatureCacheWithLimit creates a new in-memory feature cache with size limit
func NewMemoryFeatureCacheWithLimit(logger *zap.SugaredLogger, maxSize int) *MemoryFeatureCache {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &MemoryFeatureCache{
		data:    make(map[string]*cacheEntry),
		logger:  logger,
		stats:   CacheStats{},
		maxSize: maxSize,
	}
}

// Get retrieves cached features for an event
func (c *MemoryFeatureCache) Get(ctx context.Context, eventID string) (*FeatureVector, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.data[eventID]
	if !exists {
		c.stats.Misses++
		return nil, fmt.Errorf("features not found in cache for event %s", eventID)
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		delete(c.data, eventID)
		c.stats.Misses++
		return nil, fmt.Errorf("features expired in cache for event %s", eventID)
	}

	c.stats.Hits++
	return entry.features, nil
}

// Set stores features for an event with TTL
func (c *MemoryFeatureCache) Set(ctx context.Context, features *FeatureVector, ttl time.Duration) error {
	if features == nil {
		return fmt.Errorf("features cannot be nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries to stay within limits
	if len(c.data) >= c.maxSize {
		c.evictExpiredEntries()
		// If still at limit after eviction, remove oldest entry
		if len(c.data) >= c.maxSize {
			c.evictOldestEntry()
		}
	}

	entry := &cacheEntry{
		features:  features,
		expiresAt: time.Now().Add(ttl),
	}

	c.data[features.EventID] = entry
	c.stats.Sets++
	return nil
}

// Delete removes cached features for an event
func (c *MemoryFeatureCache) Delete(ctx context.Context, eventID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.data[eventID]; exists {
		delete(c.data, eventID)
		c.stats.Deletes++
	}
	return nil
}

// Exists checks if features exist in cache for an event
func (c *MemoryFeatureCache) Exists(ctx context.Context, eventID string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.data[eventID]
	if !exists {
		return false, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		delete(c.data, eventID)
		return false, nil
	}

	return true, nil
}

// Clear removes all cached features
func (c *MemoryFeatureCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*cacheEntry)
	c.stats = CacheStats{} // Reset stats too
	return nil
}

// evictExpiredEntries removes all expired entries from the cache
func (c *MemoryFeatureCache) evictExpiredEntries() {
	now := time.Now()
	var expiredKeys []string

	// First pass: collect expired keys
	for eventID, entry := range c.data {
		if now.After(entry.expiresAt) {
			expiredKeys = append(expiredKeys, eventID)
		}
	}

	// Second pass: delete expired entries
	for _, eventID := range expiredKeys {
		delete(c.data, eventID)
		c.stats.Deletes++
	}
}

// evictOldestEntry removes the entry that expires soonest
func (c *MemoryFeatureCache) evictOldestEntry() {
	var oldestEventID string
	var oldestExpiry time.Time

	for eventID, entry := range c.data {
		if oldestEventID == "" || entry.expiresAt.Before(oldestExpiry) {
			oldestEventID = eventID
			oldestExpiry = entry.expiresAt
		}
	}

	if oldestEventID != "" {
		delete(c.data, oldestEventID)
		c.stats.Deletes++
	}
}

// GetStats returns cache statistics
func (c *MemoryFeatureCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	totalRequests := stats.Hits + stats.Misses
	if totalRequests > 0 {
		stats.HitRate = float64(stats.Hits) / float64(totalRequests)
	}

	stats.TotalEntries = int64(len(c.data))
	return stats
}

// FeatureCacheManager manages feature caching with fallback strategies
type FeatureCacheManager struct {
	primaryCache  FeatureCache // Usually Redis
	fallbackCache FeatureCache // Usually in-memory for fallback
	logger        *zap.SugaredLogger
}

// NewFeatureCacheManager creates a new cache manager with primary and fallback caches
func NewFeatureCacheManager(primaryCache, fallbackCache FeatureCache, logger *zap.SugaredLogger) *FeatureCacheManager {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	return &FeatureCacheManager{
		primaryCache:  primaryCache,
		fallbackCache: fallbackCache,
		logger:        logger,
	}
}

// Get retrieves features using primary cache with fallback
func (m *FeatureCacheManager) Get(ctx context.Context, eventID string) (*FeatureVector, error) {
	// Try primary cache first
	features, err := m.primaryCache.Get(ctx, eventID)
	if err == nil {
		return features, nil
	}

	// If primary fails, try fallback cache
	m.logger.Debugw("Primary cache miss, trying fallback",
		"event_id", eventID,
		"primary_error", err)

	features, err = m.fallbackCache.Get(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("features not found in any cache for event %s", eventID)
	}

	return features, nil
}

// Set stores features in both primary and fallback caches
func (m *FeatureCacheManager) Set(ctx context.Context, features *FeatureVector, ttl time.Duration) error {
	// Store in primary cache
	if err := m.primaryCache.Set(ctx, features, ttl); err != nil {
		m.logger.Warnw("Failed to set features in primary cache, using fallback",
			"event_id", features.EventID,
			"error", err)

		// Store in fallback cache if primary fails
		if err := m.fallbackCache.Set(ctx, features, ttl); err != nil {
			return fmt.Errorf("failed to set features in any cache: %w", err)
		}
		return nil
	}

	// Also store in fallback cache for redundancy
	if err := m.fallbackCache.Set(ctx, features, ttl); err != nil {
		m.logger.Warnw("Failed to set features in fallback cache",
			"event_id", features.EventID,
			"error", err)
		// Don't fail the operation if fallback fails
	}

	return nil
}

// Delete removes features from both caches
func (m *FeatureCacheManager) Delete(ctx context.Context, eventID string) error {
	// Delete from both caches
	primaryErr := m.primaryCache.Delete(ctx, eventID)
	fallbackErr := m.fallbackCache.Delete(ctx, eventID)

	// Return error only if both fail
	if primaryErr != nil && fallbackErr != nil {
		return fmt.Errorf("failed to delete from any cache: primary=%v, fallback=%v", primaryErr, fallbackErr)
	}

	return nil
}

// Exists checks if features exist in either cache
func (m *FeatureCacheManager) Exists(ctx context.Context, eventID string) (bool, error) {
	// Check primary cache first
	exists, err := m.primaryCache.Exists(ctx, eventID)
	if err == nil && exists {
		return true, nil
	}

	// Check fallback cache
	exists, err = m.fallbackCache.Exists(ctx, eventID)
	if err != nil {
		return false, fmt.Errorf("failed to check cache existence: %w", err)
	}

	return exists, nil
}

// Clear removes all features from both caches
func (m *FeatureCacheManager) Clear(ctx context.Context) error {
	primaryErr := m.primaryCache.Clear(ctx)
	fallbackErr := m.fallbackCache.Clear(ctx)

	if primaryErr != nil && fallbackErr != nil {
		return fmt.Errorf("failed to clear any cache: primary=%v, fallback=%v", primaryErr, fallbackErr)
	}

	return nil
}

// GetStats returns combined cache statistics
func (m *FeatureCacheManager) GetStats() (primaryStats, fallbackStats CacheStats) {
	return m.primaryCache.GetStats(), m.fallbackCache.GetStats()
}
