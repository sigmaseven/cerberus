package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cerberus/metrics"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisCache provides a Redis-based cache for frequently accessed data
type RedisCache struct {
	client *redis.Client
	logger *zap.SugaredLogger
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(addr, password string, db, poolSize int, logger *zap.SugaredLogger) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
		PoolSize: poolSize,
	})

	return &RedisCache{
		client: client,
		logger: logger,
	}
}

// Ping tests the Redis connection
func (rc *RedisCache) Ping(ctx context.Context) error {
	return rc.client.Ping(ctx).Err()
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

// Set stores a value in the cache with expiration
func (rc *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		rc.logger.Errorf("Failed to marshal cache value for key %s: %v", key, err)
		metrics.CacheErrors.WithLabelValues("redis", "marshal").Inc()
		return err
	}

	// Check size limit to prevent excessive memory usage (10MB limit)
	const maxSize = 10 * 1024 * 1024 // 10MB
	if len(data) > maxSize {
		rc.logger.Warnf("Cache value for key %s exceeds size limit (%d bytes > %d bytes), rejecting", key, len(data), maxSize)
		metrics.CacheErrors.WithLabelValues("redis", "size_limit").Inc()
		return fmt.Errorf("cache value size %d bytes exceeds maximum allowed size %d bytes", len(data), maxSize)
	}

	err = rc.client.Set(ctx, key, data, expiration).Err()
	if err != nil {
		metrics.CacheErrors.WithLabelValues("redis", "set").Inc()
	}
	return err
}

// Get retrieves a value from the cache
func (rc *RedisCache) Get(ctx context.Context, key string, dest interface{}) (bool, error) {
	data, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			metrics.CacheMisses.WithLabelValues("redis").Inc()
			return false, nil // Key not found
		}
		rc.logger.Errorf("Failed to get cache value for key %s: %v", key, err)
		metrics.CacheErrors.WithLabelValues("redis", "get").Inc()
		return false, err
	}

	err = json.Unmarshal([]byte(data), dest)
	if err != nil {
		rc.logger.Errorf("Failed to unmarshal cache value for key %s: %v", key, err)
		metrics.CacheErrors.WithLabelValues("redis", "unmarshal").Inc()
		return false, err
	}

	metrics.CacheHits.WithLabelValues("redis").Inc()
	return true, nil
}

// Delete removes a key from the cache
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	return rc.client.Del(ctx, key).Err()
}

// Exists checks if a key exists in the cache
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := rc.client.Exists(ctx, key).Result()
	return count > 0, err
}

// SetNX sets a value only if the key does not exist (atomic operation)
func (rc *RedisCache) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		rc.logger.Errorf("Failed to marshal cache value for key %s: %v", key, err)
		return false, err
	}

	return rc.client.SetNX(ctx, key, data, expiration).Result()
}

// GetTTL returns the remaining TTL for a key
func (rc *RedisCache) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	return rc.client.TTL(ctx, key).Result()
}

// FlushAll clears all keys from the current database
func (rc *RedisCache) FlushAll(ctx context.Context) error {
	return rc.client.FlushAll(ctx).Err()
}

// Cache keys for different data types
const (
	CacheKeyRulePrefix    = "rule:"
	CacheKeyAlertPrefix   = "alert:"
	CacheKeyConfigPrefix  = "config:"
	CacheKeyStatsPrefix   = "stats:"
	CacheKeyUserPrefix    = "user:"
	CacheKeySessionPrefix = "session:"
)

// GetRuleCacheKey generates a cache key for rules
func GetRuleCacheKey(ruleID string) string {
	return CacheKeyRulePrefix + ruleID
}

// GetAlertCacheKey generates a cache key for alerts
func GetAlertCacheKey(alertID string) string {
	return CacheKeyAlertPrefix + alertID
}

// GetConfigCacheKey generates a cache key for configuration
func GetConfigCacheKey(configKey string) string {
	return CacheKeyConfigPrefix + configKey
}

// GetStatsCacheKey generates a cache key for statistics
func GetStatsCacheKey(statsKey string) string {
	return CacheKeyStatsPrefix + statsKey
}

// GetUserCacheKey generates a cache key for users
func GetUserCacheKey(userID string) string {
	return CacheKeyUserPrefix + userID
}

// GetSessionCacheKey generates a cache key for sessions
func GetSessionCacheKey(sessionID string) string {
	return CacheKeySessionPrefix + sessionID
}
