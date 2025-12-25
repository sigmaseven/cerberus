package threat

import (
	"sync"
	"time"
)

// IOCCache provides a simple in-memory cache for IOC lookups
type IOCCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	done    chan struct{} // signal to stop cleanup goroutine
}

type cacheEntry struct {
	intel      *ThreatIntel
	expiration time.Time
}

// NewIOCCache creates a new IOC cache
func NewIOCCache() *IOCCache {
	cache := &IOCCache{
		entries: make(map[string]*cacheEntry),
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached threat intel entry
func (c *IOCCache) Get(ioc string) (*ThreatIntel, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.entries[ioc]
	if !found {
		return nil, false
	}

	if time.Now().After(entry.expiration) {
		return nil, false
	}

	return entry.intel, true
}

// Set stores a threat intel entry in the cache
func (c *IOCCache) Set(ioc string, intel *ThreatIntel, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ioc] = &cacheEntry{
		intel:      intel,
		expiration: time.Now().Add(ttl),
	}
}

// cleanup removes expired entries periodically
func (c *IOCCache) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, entry := range c.entries {
				if now.After(entry.expiration) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		case <-c.done:
			// Shutdown signal received, exit cleanup goroutine
			return
		}
	}
}

// Close stops the cleanup goroutine and releases resources
func (c *IOCCache) Close() {
	close(c.done)
}
