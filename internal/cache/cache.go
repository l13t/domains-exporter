// Package cache provides TTL-based caching for domain expiration data.
package cache

import (
	"sync"
	"time"
)

// Entry represents a cached WHOIS lookup result.
type Entry struct {
	ExpirationTime time.Time
	Success        bool
	Error          string
	Timestamp      time.Time
	CachedDuration time.Duration
}

// Cache holds domain expiration data with TTL.
type Cache struct {
	mu     sync.RWMutex
	data   map[string]*Entry
	ttl    time.Duration
	ticker *time.Ticker
	stopCh chan struct{}
}

// New creates a new Cache with the specified TTL.
func New(ttl time.Duration) *Cache {
	c := &Cache{
		data:   make(map[string]*Entry),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	c.ticker = time.NewTicker(time.Minute)
	go c.cleanupLoop()

	return c
}

// Get retrieves an entry from the cache if it hasn't expired.
// Returns the entry and a bool indicating if the entry was found and valid.
func (c *Cache) Get(domain string) (*Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[domain]
	if !exists {
		return nil, false
	}

	// Check if entry has expired
	if time.Since(entry.Timestamp) > c.ttl {
		return nil, false
	}

	return entry, true
}

// Set stores an entry in the cache.
func (c *Cache) Set(domain string, entry *Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.Timestamp = time.Now()
	entry.CachedDuration = c.ttl
	c.data[domain] = entry
}

// Remove deletes an entry from the cache.
func (c *Cache) Remove(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, domain)
}

// Size returns the number of entries currently in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.data)
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*Entry)
}

// Close stops the cache cleanup goroutine.
func (c *Cache) Close() {
	close(c.stopCh)
}

// cleanupLoop periodically removes expired entries.
func (c *Cache) cleanupLoop() {
	defer c.ticker.Stop()

	for {
		select {
		case <-c.ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// cleanup removes expired entries from the cache.
func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for domain, entry := range c.data {
		if now.Sub(entry.Timestamp) > c.ttl {
			delete(c.data, domain)
		}
	}
}
