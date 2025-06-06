package storage

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryConfig configuration for memory storage
type MemoryConfig struct {
	MaxKeys         int           `json:"max_keys"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	EnableMetrics   bool          `json:"enable_metrics"`
}

// MemoryStorage implements RateLimiterStorage using in-memory storage
type MemoryStorage struct {
	data      map[string]*ClientEntry
	mu        sync.RWMutex
	config    *MemoryConfig
	metrics   *PerformanceMetrics
	metricsMu sync.RWMutex
	closed    bool
}

// NewMemoryStorage creates a new memory storage instance
func NewMemoryStorage(config *MemoryConfig) *MemoryStorage {
	if config == nil {
		config = &MemoryConfig{
			MaxKeys:         10000,
			CleanupInterval: 5 * time.Minute,
			EnableMetrics:   true,
		}
	}

	storage := &MemoryStorage{
		data:   make(map[string]*ClientEntry),
		config: config,
		metrics: &PerformanceMetrics{
			LastOperation: time.Now(),
		},
	}

	return storage
}

func (m *MemoryStorage) recordOperation(success bool, duration time.Duration) {
	if !m.config.EnableMetrics {
		return
	}

	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	atomic.AddInt64(&m.metrics.TotalOperations, 1)
	if success {
		atomic.AddInt64(&m.metrics.SuccessfulOps, 1)
	} else {
		atomic.AddInt64(&m.metrics.FailedOps, 1)
	}

	// Update average latency (simple moving average)
	if m.metrics.TotalOperations == 1 {
		m.metrics.AvgLatency = duration
	} else {
		m.metrics.AvgLatency = (m.metrics.AvgLatency + duration) / 2
	}
	m.metrics.LastOperation = time.Now()
}

func (m *MemoryStorage) GetTokens(ctx context.Context, key string) (int, time.Time, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return 0, time.Time{}, ErrStorageNotReady
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, exists := m.data[key]; exists {
		return entry.Tokens, entry.LastRefill, nil
	}
	return 0, time.Time{}, nil
}

func (m *MemoryStorage) SetTokens(ctx context.Context, key string, tokens int, lastRefill time.Time, ttl time.Duration) error {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check max keys limit
	if len(m.data) >= m.config.MaxKeys {
		if _, exists := m.data[key]; !exists {
			// Remove oldest entry
			m.removeOldestEntry()
		}
	}

	entry, exists := m.data[key]
	if !exists {
		entry = &ClientEntry{
			Created:  time.Now(),
			Metadata: make(map[string]string),
		}
		m.data[key] = entry
	}

	entry.Tokens = tokens
	entry.LastRefill = lastRefill
	entry.LastAccess = time.Now()

	return nil
}

func (m *MemoryStorage) removeOldestEntry() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range m.data {
		if entry.LastAccess.Before(oldestTime) {
			oldestTime = entry.LastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(m.data, oldestKey)
	}
}

func (m *MemoryStorage) AddRequest(ctx context.Context, key string, timestamp time.Time, window time.Duration) error {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-window)

	entry, exists := m.data[key]
	if !exists {
		entry = &ClientEntry{
			Created:    now,
			LastAccess: now,
			Requests:   make([]int64, 0),
			Metadata:   make(map[string]string),
		}
		m.data[key] = entry
	}

	// Clean old requests
	validRequests := make([]int64, 0, len(entry.Requests))
	for _, reqTime := range entry.Requests {
		if time.Unix(0, reqTime).After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Add new request
	validRequests = append(validRequests, timestamp.UnixNano())
	entry.Requests = validRequests
	entry.LastAccess = now

	return nil
}

func (m *MemoryStorage) GetRequestCount(ctx context.Context, key string, window time.Duration) (int, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return 0, ErrStorageNotReady
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.data[key]
	if !exists {
		return 0, nil
	}

	windowStart := time.Now().Add(-window)
	count := 0
	for _, reqTime := range entry.Requests {
		if time.Unix(0, reqTime).After(windowStart) {
			count++
		}
	}

	return count, nil
}

func (m *MemoryStorage) CleanupWindow(ctx context.Context, key string, window time.Duration) error {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.data[key]
	if !exists {
		return nil
	}

	windowStart := time.Now().Add(-window)
	validRequests := make([]int64, 0, len(entry.Requests))
	for _, reqTime := range entry.Requests {
		if time.Unix(0, reqTime).After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}
	entry.Requests = validRequests

	return nil
}

func (m *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return false, ErrStorageNotReady
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.data[key]
	return exists, nil
}

func (m *MemoryStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *MemoryStorage) TTL(ctx context.Context, key string) (time.Duration, error) {
	// Memory storage doesn't implement TTL
	return 0, nil
}

func (m *MemoryStorage) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	// Memory storage doesn't implement TTL
	return nil
}

func (m *MemoryStorage) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return nil, ErrStorageNotReady
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.data {
		if pattern == "" || pattern == "*" || strings.Contains(key, strings.TrimSuffix(pattern, "*")) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *MemoryStorage) DeletePattern(ctx context.Context, pattern string) (int, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return 0, ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key := range m.data {
		if pattern == "" || pattern == "*" || strings.Contains(key, strings.TrimSuffix(pattern, "*")) {
			delete(m.data, key)
			count++
		}
	}
	return count, nil
}

func (m *MemoryStorage) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	defer func() { m.recordOperation(true, time.Since(start)) }()

	if m.closed {
		return 0, ErrStorageNotReady
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.data[key]
	if !exists {
		entry = &ClientEntry{
			Created:    time.Now(),
			LastAccess: time.Now(),
			Metadata:   make(map[string]string),
		}
		m.data[key] = entry
	}

	entry.RequestCount += delta
	entry.LastAccess = time.Now()
	return entry.RequestCount, nil
}

func (m *MemoryStorage) Decrement(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	return m.Increment(ctx, key, -delta, ttl)
}

func (m *MemoryStorage) Ping(ctx context.Context) error {
	if m.closed {
		return ErrStorageNotReady
	}
	return nil
}

func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.data = make(map[string]*ClientEntry)
	return nil
}

func (m *MemoryStorage) Type() StorageType {
	return MemoryStorageType
}

func (m *MemoryStorage) Info() StorageInfo {
	m.mu.RLock()
	keyCount := len(m.data)
	m.mu.RUnlock()

	m.metricsMu.RLock()
	metrics := *m.metrics
	m.metricsMu.RUnlock()

	return StorageInfo{
		Type:      MemoryStorageType,
		Status:    "healthy",
		Connected: !m.closed,
		Metadata: map[string]interface{}{
			"key_count": keyCount,
			"max_keys":  m.config.MaxKeys,
		},
		Performance: &metrics,
	}
}
