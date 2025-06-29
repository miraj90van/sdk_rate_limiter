// sliding_window_rate_limiter.go
// Purpose: Sliding window rate limiting with Redis support and fallback
// Use case: Precise rate limiting with smooth distribution over time windows

package middleware

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"net/http"
)

var _ RateLimiter = (*SlidingWindowRateLimiter)(nil)

// SlidingWindowError represents a sliding window rate limiting error
type SlidingWindowError struct {
	Type             string        `json:"type"`
	Message          string        `json:"message"`
	ClientKey        string        `json:"client_key"`
	RequestsInWindow int           `json:"requests_in_window"`
	WindowSize       time.Duration `json:"window_size"`
	WindowUsage      float64       `json:"window_usage"`
	RetryAfter       time.Duration `json:"retry_after"`
}

func (e *SlidingWindowError) Error() string {
	return e.Message
}

// SlidingWindowInfo provides detailed information about the current sliding window
type SlidingWindowInfo struct {
	Start          time.Time     `json:"start"`
	End            time.Time     `json:"end"`
	Size           time.Duration `json:"size"`
	RequestCount   int           `json:"request_count"`
	Limit          int           `json:"limit"`
	Usage          float64       `json:"usage"`           // 0.0 to 1.0
	Remaining      int           `json:"remaining"`       // Available requests
	OldestRequest  *time.Time    `json:"oldest_request"`  // Oldest request timestamp
	NewestRequest  *time.Time    `json:"newest_request"`  // Newest request timestamp
	EstimatedReset time.Time     `json:"estimated_reset"` // When oldest request expires
}

// SlidingWindowConfig configuration for sliding window rate limiter
type SlidingWindowConfig struct {
	Rate                   int           // Requests per window
	WindowSize             time.Duration // Window duration (e.g., 1 minute, 1 hour)
	RedisClient            *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix         string        // Prefix for Redis keys
	EnableFallback         bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor           KeyExtractor  // Function to extract a client key
	MaxClients             int           // Maximum clients to track (fallback mode)
	MaxTrackedClients      int           // Maximum clients to track in statistics
	CleanupInterval        time.Duration // Cleanup interval (fallback mode)
	ClientTTL              time.Duration // Client TTL (fallback mode)
	RequestTimeout         time.Duration // Timeout for Redis operations
	EnableHeaders          bool          // Include rate limit headers
	EnableLogging          bool          // Enable logging
	EnableJitter           bool          // Enable jitter to prevent synchronization
	ErrorMessage           string        // Custom error message
	ErrorResponse          interface{}   // Custom error response structure
	MetricsCollector       Metrics       // Optional metrics collector
	MaxTimestampsPerClient int           // Maximum timestamps to store per client (memory optimization)
	OnLimitExceeded        func(*gin.Context, *SlidingWindowRequestInfo)
	OnRequestProcessed     func(*gin.Context, *SlidingWindowRequestInfo, bool)
}

// Validate validates the configuration
func (config *SlidingWindowConfig) Validate() error {
	if config.Rate <= 0 {
		return fmt.Errorf("rate must be positive, got %d", config.Rate)
	}
	if config.WindowSize <= 0 {
		return fmt.Errorf("window size must be positive, got %v", config.WindowSize)
	}
	if config.MaxClients <= 0 {
		return fmt.Errorf("max clients must be positive, got %d", config.MaxClients)
	}
	if config.MaxTrackedClients <= 0 {
		return fmt.Errorf("max tracked clients must be positive, got %d", config.MaxTrackedClients)
	}
	if config.ClientTTL <= 0 {
		return fmt.Errorf("client TTL must be positive, got %v", config.ClientTTL)
	}
	if config.CleanupInterval <= 0 {
		return fmt.Errorf("cleanup interval must be positive, got %v", config.CleanupInterval)
	}
	if config.RequestTimeout <= 0 {
		return fmt.Errorf("request timeout must be positive, got %v", config.RequestTimeout)
	}
	if config.MaxTimestampsPerClient <= 0 {
		return fmt.Errorf("max timestamps per client must be positive, got %d", config.MaxTimestampsPerClient)
	}
	if config.MaxTimestampsPerClient < config.Rate {
		return fmt.Errorf("max timestamps per client (%d) should not be less than rate (%d)", config.MaxTimestampsPerClient, config.Rate)
	}
	return nil
}

// SlidingWindowRequestInfo contains request information for sliding window limiter
type SlidingWindowRequestInfo struct {
	BaseRequestInfo
	ClientKey        string     `json:"client_key"`
	WindowStart      time.Time  `json:"window_start"`
	WindowEnd        time.Time  `json:"window_end"`
	RequestsInWindow int        `json:"requests_in_window"`
	WindowUsage      float64    `json:"window_usage"` // 0.0 to 1.0
	OldestRequest    *time.Time `json:"oldest_request"`
	EstimatedReset   time.Time  `json:"estimated_reset"`
}

// SlidingWindowStats statistics for sliding window rate limiter
type SlidingWindowStats struct {
	*BaseStats
	ActiveClients      int64                   `json:"active_clients"`
	RedisMode          bool                    `json:"redis_mode"`
	FallbackMode       bool                    `json:"fallback_mode"`
	RedisErrors        int64                   `json:"redis_errors"`
	TimestampsStored   int64                   `json:"timestamps_stored"`  // Total timestamps across all clients
	MemoryUsageBytes   int64                   `json:"memory_usage_bytes"` // Estimated memory usage
	AverageWindowUsage float64                 `json:"average_window_usage"`
	ClientStats        map[string]*ClientStats `json:"client_stats"`
	mutex              sync.RWMutex
}

// ringBuffer implements a circular buffer for efficient timestamp storage
type ringBuffer struct {
	data []int64 // Store timestamps as Unix nanoseconds
	head int     // Points to oldest element
	tail int     // Points to next insertion point
	size int     // Current size
	cap  int     // Maximum capacity
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{
		data: make([]int64, capacity),
		cap:  capacity,
	}
}

func (rb *ringBuffer) add(timestamp int64) {
	rb.data[rb.tail] = timestamp
	rb.tail = (rb.tail + 1) % rb.cap

	if rb.size < rb.cap {
		rb.size++
	} else {
		// Buffer is full, move head forward
		rb.head = (rb.head + 1) % rb.cap
	}
}

func (rb *ringBuffer) removeOlderThan(cutoff int64) int {
	removed := 0
	for rb.size > 0 && rb.data[rb.head] < cutoff {
		rb.head = (rb.head + 1) % rb.cap
		rb.size--
		removed++
	}
	return removed
}

func (rb *ringBuffer) count() int {
	return rb.size
}

func (rb *ringBuffer) oldest() (int64, bool) {
	if rb.size == 0 {
		return 0, false
	}
	return rb.data[rb.head], true
}

func (rb *ringBuffer) newest() (int64, bool) {
	if rb.size == 0 {
		return 0, false
	}
	prevTail := (rb.tail - 1 + rb.cap) % rb.cap
	return rb.data[prevTail], true
}

// getAllSorted returns all timestamps in sorted order (oldest first)
func (rb *ringBuffer) getAllSorted() []int64 {
	if rb.size == 0 {
		return nil
	}

	result := make([]int64, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.cap
		result[i] = rb.data[idx]
	}

	// Should already be sorted due to ring buffer nature, but ensure it
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})

	return result
}

// clientEntry represents a client's rate limiting data in fallback mode
type clientEntry struct {
	timestamps   *ringBuffer // Circular buffer for efficient timestamp storage
	lastAccess   int64       // Last access time in Unix nanoseconds (atomic)
	requestCount int32       // Atomic counter for quick access
}

// SlidingWindowRateLimiter implements sliding window rate limiting
type SlidingWindowRateLimiter struct {
	config     *SlidingWindowConfig
	stats      *SlidingWindowStats
	clients    sync.Map  // map[string]*clientEntry - Better concurrent performance
	clientsLRU *lruCache // LRU cache for client statistics
	stopChan   chan struct{}
	redisMode  bool
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter
func NewSlidingWindowRateLimiter(config *SlidingWindowConfig) (*SlidingWindowRateLimiter, error) {
	if config == nil {
		config = DefaultSlidingWindowConfig()
	}

	// Set defaults
	if config.WindowSize == 0 {
		config.WindowSize = time.Minute
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "rate_limit:sliding:"
	}
	if config.KeyExtractor == nil {
		config.KeyExtractor = IPKeyExtractor
	}
	if config.MaxClients == 0 {
		config.MaxClients = 10000
	}
	if config.MaxTrackedClients == 0 {
		config.MaxTrackedClients = 1000
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Minute * 5
	}
	if config.ClientTTL == 0 {
		config.ClientTTL = time.Hour
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = time.Second * 5
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Sliding Window Rate limit exceeded"
	}
	if config.MaxTimestampsPerClient == 0 {
		// Set to 2x rate to handle burst scenarios efficiently
		config.MaxTimestampsPerClient = config.Rate * 2
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	swrl := &SlidingWindowRateLimiter{
		config:     config,
		clientsLRU: newLRUCache(config.MaxTrackedClients),
		stopChan:   make(chan struct{}),
		redisMode:  config.RedisClient != nil,
		stats: &SlidingWindowStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: SlidingWindowType,
			},
			ClientStats: make(map[string]*ClientStats),
		},
	}

	// Test Redis connection
	if swrl.redisMode {
		if err := swrl.testRedisConnection(); err != nil {
			if config.EnableFallback {
				log.Printf("[SLIDING_WINDOW] Redis connection failed, falling back to in-memory: %v", err)
				swrl.redisMode = false
				swrl.stats.FallbackMode = true
			} else {
				return nil, fmt.Errorf("redis connection failed and fallback disabled: %w", err)
			}
		} else {
			swrl.stats.RedisMode = true
		}
	} else {
		swrl.stats.FallbackMode = true
	}

	// Start cleanup routine for fallback mode
	if !swrl.redisMode {
		go swrl.cleanupRoutine()
	}

	return swrl, nil
}

// DefaultSlidingWindowConfig returns default configuration
func DefaultSlidingWindowConfig() *SlidingWindowConfig {
	return &SlidingWindowConfig{
		Rate:                   100,
		WindowSize:             time.Minute,
		EnableFallback:         true,
		KeyExtractor:           IPKeyExtractor,
		MaxClients:             10000,
		MaxTrackedClients:      1000,
		CleanupInterval:        time.Minute * 5,
		ClientTTL:              time.Hour,
		RequestTimeout:         time.Second * 5,
		EnableHeaders:          true,
		EnableLogging:          false,
		EnableJitter:           false,
		ErrorMessage:           "Rate limit exceeded",
		MaxTimestampsPerClient: 200, // 2x default rate
	}
}

// testRedisConnection tests the Redis connection
func (swrl *SlidingWindowRateLimiter) testRedisConnection() error {
	if swrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), swrl.config.RequestTimeout)
	defer cancel()

	return swrl.config.RedisClient.Ping(ctx).Err()
}

// addJitter adds deterministic jitter to timing calculations
func (swrl *SlidingWindowRateLimiter) addJitter(baseTime time.Time, clientKey string) time.Time {
	if !swrl.config.EnableJitter {
		return baseTime
	}

	hash := fnv.New32a()
	hash.Write([]byte(clientKey))
	// Add up to 50ms jitter
	jitterMs := int64(hash.Sum32() % 50)
	return baseTime.Add(time.Duration(jitterMs) * time.Millisecond)
}

// checkRateLimitRedis checks rate limit using Redis with enhanced script
func (swrl *SlidingWindowRateLimiter) checkRateLimitRedis(ctx context.Context, clientKey string) (bool, int, *time.Time, error) {
	now := time.Now()
	// Add jitter to current time to prevent synchronization
	jitteredNow := swrl.addJitter(now, clientKey)
	currentTime := jitteredNow.UnixMilli() // Use milliseconds for better precision
	windowSizeMs := swrl.config.WindowSize.Milliseconds()

	// Enhanced Redis Lua script with input validation and clock skew protection
	script := `
		local key = KEYS[1]
		local window = tonumber(ARGV[1])        -- Window size in milliseconds
		local limit = tonumber(ARGV[2])         -- Rate limit
		local current_time = tonumber(ARGV[3])  -- Current timestamp in milliseconds
		
		-- Input validation
		if not window or window <= 0 then
			return redis.error_reply("Invalid window size: " .. tostring(ARGV[1]))
		end
		if not limit or limit <= 0 then
			return redis.error_reply("Invalid limit: " .. tostring(ARGV[2]))
		end
		if not current_time or current_time <= 0 then
			return redis.error_reply("Invalid current time: " .. tostring(ARGV[3]))
		end
		
		-- Calculate cutoff time (with clock skew tolerance)
		local cutoff_time = current_time - window
		
		-- Remove expired entries (older than window)
		local removed_count = redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff_time)
		
		-- Count current entries in the window
		local current_count = redis.call('ZCARD', key)
		
		-- Get oldest and newest timestamps for additional info
		local oldest_newest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
		local oldest_time = nil
		if #oldest_newest > 0 then
			oldest_time = tonumber(oldest_newest[2])
		end
		
		-- Check if limit would be exceeded
		if current_count >= limit then
			-- Calculate estimated reset time
			local estimated_reset = oldest_time and (oldest_time + window) or (current_time + window)
			return {0, current_count, oldest_time, estimated_reset, removed_count}
		end
		
		-- Add current request with unique identifier to handle concurrent requests
		-- Use random number to ensure uniqueness under high concurrency
		local unique_id = current_time .. ':' .. math.random(100000, 999999)
		redis.call('ZADD', key, current_time, unique_id)
		
		-- Set expiry slightly longer than window to handle clock drift
		local expire_seconds = math.ceil(window / 1000) + 10
		redis.call('EXPIRE', key, expire_seconds)
		
		-- Get updated oldest timestamp after insertion
		local updated_oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
		local new_oldest_time = nil
		if #updated_oldest > 0 then
			new_oldest_time = tonumber(updated_oldest[2])
		end
		
		-- Calculate remaining requests and estimated reset
		local new_count = current_count + 1
		local estimated_reset = new_oldest_time and (new_oldest_time + window) or (current_time + window)
		
		-- Return: allowed(1), new_count, oldest_time, estimated_reset, removed_count
		return {1, new_count, new_oldest_time, estimated_reset, removed_count}
	`

	result, err := swrl.config.RedisClient.Eval(ctx, script, []string{
		swrl.config.RedisKeyPrefix + clientKey,
	}, windowSizeMs, swrl.config.Rate, currentTime).Result()

	if err != nil {
		atomic.AddInt64(&swrl.stats.RedisErrors, 1)
		swrl.recordMetric("redis_errors", 1, map[string]string{"client": clientKey})
		return false, 0, nil, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 5 {
		return false, 0, nil, fmt.Errorf("unexpected Redis result format: %v", result)
	}

	allowed := resultSlice[0].(int64) == 1
	count := int(resultSlice[1].(int64))

	var oldestTime *time.Time
	if resultSlice[2] != nil {
		if oldestTs, ok := resultSlice[2].(int64); ok {
			t := time.UnixMilli(oldestTs)
			oldestTime = &t
		}
	}

	return allowed, count, oldestTime, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage with ring buffer
func (swrl *SlidingWindowRateLimiter) checkRateLimitFallback(clientKey string) (bool, int, *time.Time) {
	now := time.Now()
	// Add jitter to prevent synchronization
	jitteredNow := swrl.addJitter(now, clientKey)
	nowNano := jitteredNow.UnixNano()
	windowStartNano := nowNano - swrl.config.WindowSize.Nanoseconds()

	// Load or create entry using sync.Map for better concurrent performance
	value, _ := swrl.clients.LoadOrStore(clientKey, &clientEntry{
		timestamps:   newRingBuffer(swrl.config.MaxTimestampsPerClient),
		lastAccess:   nowNano,
		requestCount: 0,
	})

	entry := value.(*clientEntry)

	// Update last access atomically
	atomic.StoreInt64(&entry.lastAccess, nowNano)

	// Clean up expired timestamps and get current count
	removedCount := entry.timestamps.removeOlderThan(windowStartNano)
	currentCount := entry.timestamps.count()

	// Update atomic counter
	atomic.AddInt32(&entry.requestCount, int32(-removedCount))

	// Get oldest timestamp
	var oldestTime *time.Time
	if oldest, exists := entry.timestamps.oldest(); exists {
		t := time.Unix(0, oldest)
		oldestTime = &t
	}

	// Check if limit exceeded
	if currentCount >= swrl.config.Rate {
		return false, currentCount, oldestTime
	}

	// Add current request
	entry.timestamps.add(nowNano)
	atomic.AddInt32(&entry.requestCount, 1)

	// Update memory usage stats
	atomic.AddInt64(&swrl.stats.TimestampsStored, 1-int64(removedCount))

	return true, currentCount + 1, oldestTime
}

// cleanupRoutine cleans up expired client entries in fallback mode
func (swrl *SlidingWindowRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(swrl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			swrl.cleanupExpiredClients()
		case <-swrl.stopChan:
			return
		}
	}
}

// cleanupExpiredClients removes expired client entries and calculates memory usage
func (swrl *SlidingWindowRateLimiter) cleanupExpiredClients() {
	now := time.Now()
	expiry := now.Add(-swrl.config.ClientTTL).UnixNano()
	deletedCount := 0
	totalTimestamps := int64(0)
	totalMemoryBytes := int64(0)

	swrl.clients.Range(func(key, value interface{}) bool {
		entry := value.(*clientEntry)
		lastAccess := atomic.LoadInt64(&entry.lastAccess)

		if lastAccess < expiry {
			swrl.clients.Delete(key)
			deletedCount++
		} else {
			// Count timestamps and estimate memory usage
			count := entry.timestamps.count()
			totalTimestamps += int64(count)
			// Rough estimate: each timestamp (8 bytes) + overhead
			totalMemoryBytes += int64(count) * 16
		}
		return true
	})

	// Update statistics
	atomic.StoreInt64(&swrl.stats.TimestampsStored, totalTimestamps)
	atomic.StoreInt64(&swrl.stats.MemoryUsageBytes, totalMemoryBytes)

	if deletedCount > 0 {
		swrl.recordMetric("clients_cleaned", float64(deletedCount), nil)
	}

	// Update active clients count
	activeCount := int64(0)
	swrl.clients.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	atomic.StoreInt64(&swrl.stats.ActiveClients, activeCount)
}

// createRequestInfo creates request information
func (swrl *SlidingWindowRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, requestsInWindow int, oldestTime *time.Time) *SlidingWindowRequestInfo {
	now := time.Now()
	windowStart := now.Add(-swrl.config.WindowSize)

	var estimatedReset time.Time
	if oldestTime != nil {
		estimatedReset = oldestTime.Add(swrl.config.WindowSize)
	} else {
		estimatedReset = now.Add(swrl.config.WindowSize)
	}

	return &SlidingWindowRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: now,
			Allowed:   allowed,
		},
		ClientKey:        clientKey,
		WindowStart:      windowStart,
		WindowEnd:        now,
		RequestsInWindow: requestsInWindow,
		WindowUsage:      float64(requestsInWindow) / float64(swrl.config.Rate),
		OldestRequest:    oldestTime,
		EstimatedReset:   estimatedReset,
	}
}

// setHeaders sets rate limit headers
func (swrl *SlidingWindowRateLimiter) setHeaders(c *gin.Context, remaining int, estimatedReset time.Time) {
	if !swrl.config.EnableHeaders {
		return
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(swrl.config.Rate))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", estimatedReset.Format(time.RFC3339))
	c.Header("X-RateLimit-Window", swrl.config.WindowSize.String())
	c.Header("X-RateLimit-Algorithm", swrl.Algorithm().String())

	if swrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
	}
}

// recordMetric records a metric if metrics collector is configured
func (swrl *SlidingWindowRateLimiter) recordMetric(name string, value float64, tags map[string]string) {
	if swrl.config.MetricsCollector != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["limiter_type"] = "sliding_window"
		tags["mode"] = "memory"
		if swrl.redisMode {
			tags["mode"] = "redis"
		}
		swrl.config.MetricsCollector.RecordHistogram(name, value, tags)
	}
}

// logEvent logs rate limiting events
func (swrl *SlidingWindowRateLimiter) logEvent(info *SlidingWindowRequestInfo) {
	if !swrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	mode := "MEMORY"
	if swrl.redisMode {
		mode = "REDIS"
	}

	oldestInfo := "none"
	if info.OldestRequest != nil {
		oldestInfo = fmt.Sprintf("%.2fs ago", time.Since(*info.OldestRequest).Seconds())
	}

	log.Printf("[SLIDING_WINDOW_%s] %s - Client: %s, Method: %s, Path: %s, Usage: %.2f%%, Requests: %d/%d, Oldest: %s",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.WindowUsage*100, info.RequestsInWindow, swrl.config.Rate, oldestInfo)
}

// handleLimitExceeded handles when rate limit is exceeded
func (swrl *SlidingWindowRateLimiter) handleLimitExceeded(c *gin.Context, info *SlidingWindowRequestInfo) {
	// Set Retry-After header
	retryAfter := info.EstimatedReset.Sub(time.Now())
	if retryAfter > 0 {
		SetRetryAfterHeader(c, retryAfter)
	}

	// Call custom handler if provided
	if swrl.config.OnLimitExceeded != nil {
		swrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if swrl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, swrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Create structured error response
	slidingWindowError := &SlidingWindowError{
		Type:             "sliding_window_rate_limit_exceeded",
		Message:          swrl.config.ErrorMessage,
		ClientKey:        info.ClientKey,
		RequestsInWindow: info.RequestsInWindow,
		WindowSize:       swrl.config.WindowSize,
		WindowUsage:      info.WindowUsage,
		RetryAfter:       retryAfter,
	}

	// Default error response
	response := gin.H{
		"error":  slidingWindowError.Message,
		"type":   slidingWindowError.Type,
		"client": slidingWindowError.ClientKey,
		"window_info": gin.H{
			"size":         slidingWindowError.WindowSize.String(),
			"requests":     slidingWindowError.RequestsInWindow,
			"limit":        swrl.config.Rate,
			"usage":        fmt.Sprintf("%.1f%%", slidingWindowError.WindowUsage*100),
			"window_start": info.WindowStart.Format(time.RFC3339),
			"window_end":   info.WindowEnd.Format(time.RFC3339),
		},
		"algorithm": swrl.Algorithm().String(),
		"timestamp": info.Timestamp.Format(time.RFC3339),
	}

	if retryAfter > 0 {
		response["retry_after_seconds"] = retryAfter.Seconds()
		response["retry_after"] = retryAfter.String()
		response["estimated_reset"] = info.EstimatedReset.Format(time.RFC3339)
	}

	if info.OldestRequest != nil {
		response["oldest_request"] = info.OldestRequest.Format(time.RFC3339)
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// updateClientStats updates statistics for a specific client with LRU eviction
func (swrl *SlidingWindowRateLimiter) updateClientStats(clientKey string, allowed bool, windowUsage float64) {
	// Check if we should evict before adding
	if swrl.clientsLRU.shouldEvict(clientKey) {
		return // Skip tracking to prevent memory bloat
	}

	swrl.stats.mutex.Lock()
	defer swrl.stats.mutex.Unlock()

	clientStats, exists := swrl.stats.ClientStats[clientKey]
	if !exists {
		// Check bounds again with lock held
		if len(swrl.stats.ClientStats) >= swrl.config.MaxTrackedClients {
			// Evict oldest client
			swrl.evictOldestClientLocked()
		}

		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		swrl.stats.ClientStats[clientKey] = clientStats
	}

	// Update LRU cache
	swrl.clientsLRU.access(clientKey)

	clientStats.TotalRequests++
	clientStats.LastAccess = time.Now()
	clientStats.IsActive = true

	if allowed {
		clientStats.AllowedRequests++
	} else {
		clientStats.BlockedRequests++
	}

	// Update average window usage
	currentAvg := swrl.stats.AverageWindowUsage
	totalRequests := float64(atomic.LoadInt64(&swrl.stats.TotalRequests))
	swrl.stats.AverageWindowUsage = (currentAvg*(totalRequests-1) + windowUsage) / totalRequests
}

// evictOldestClientLocked evicts the oldest client from statistics (must be called with lock held)
func (swrl *SlidingWindowRateLimiter) evictOldestClientLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, stats := range swrl.stats.ClientStats {
		if oldestKey == "" || stats.FirstSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.FirstSeen
		}
	}

	if oldestKey != "" {
		delete(swrl.stats.ClientStats, oldestKey)
	}
}

// Middleware returns the sliding window rate limiting middleware
func (swrl *SlidingWindowRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create request-specific context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), swrl.config.RequestTimeout)
		defer cancel()

		// Extract a client key
		clientKey := swrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var requestsInWindow int
		var oldestTime *time.Time
		var err error

		startTime := time.Now()

		// Check rate limit
		if swrl.redisMode {
			allowed, requestsInWindow, oldestTime, err = swrl.checkRateLimitRedis(ctx, clientKey)
			if err != nil && swrl.config.EnableFallback {
				log.Printf("[SLIDING_WINDOW] Redis error, falling back to memory: %v", err)
				swrl.redisMode = false
				swrl.stats.FallbackMode = true
				allowed, requestsInWindow, oldestTime = swrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, requestsInWindow, oldestTime = swrl.checkRateLimitFallback(clientKey)
		}

		// Record operation duration
		duration := time.Since(startTime)
		swrl.recordMetric("rate_limit_check_duration_ms", float64(duration.Milliseconds()), map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		// Update global statistics
		atomic.AddInt64(&swrl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&swrl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&swrl.stats.BlockedRequests, 1)
		}

		// Create request info
		info := swrl.createRequestInfo(c, clientKey, allowed, requestsInWindow, oldestTime)

		// Update client statistics
		swrl.updateClientStats(clientKey, allowed, info.WindowUsage)

		// Calculate remaining requests
		remaining := swrl.config.Rate - requestsInWindow
		if remaining < 0 {
			remaining = 0
		}

		// Set headers
		swrl.setHeaders(c, remaining, info.EstimatedReset)

		// Log event
		swrl.logEvent(info)

		// Record metrics
		swrl.recordMetric("requests_total", 1, map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		swrl.recordMetric("window_usage", info.WindowUsage, map[string]string{
			"client": clientKey,
		})

		// Call request processed handler if provided
		if swrl.config.OnRequestProcessed != nil {
			swrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			swrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns rate limiting statistics
func (swrl *SlidingWindowRateLimiter) GetStats() interface{} {
	// Update live counters
	swrl.stats.TotalRequests = atomic.LoadInt64(&swrl.stats.BaseStats.TotalRequests)
	swrl.stats.AllowedRequests = atomic.LoadInt64(&swrl.stats.BaseStats.AllowedRequests)
	swrl.stats.BlockedRequests = atomic.LoadInt64(&swrl.stats.BaseStats.BlockedRequests)
	swrl.stats.ActiveClients = atomic.LoadInt64(&swrl.stats.ActiveClients)
	swrl.stats.RedisMode = swrl.redisMode
	return swrl.stats
}

// GetClientStats returns statistics for a specific client
func (swrl *SlidingWindowRateLimiter) GetClientStats(clientKey string) ClientStats {
	swrl.stats.mutex.RLock()
	defer swrl.stats.mutex.RUnlock()

	if stats, exists := swrl.stats.ClientStats[clientKey]; exists {
		return *stats
	}
	return ClientStats{ClientKey: clientKey}
}

// GetSlidingWindowInfo returns current window information for a client
func (swrl *SlidingWindowRateLimiter) GetSlidingWindowInfo(clientKey string) *SlidingWindowInfo {
	now := time.Now()
	windowStart := now.Add(-swrl.config.WindowSize)

	if swrl.redisMode {
		// For Redis mode, query the sorted set
		ctx, cancel := context.WithTimeout(context.Background(), swrl.config.RequestTimeout)
		defer cancel()

		key := swrl.config.RedisKeyPrefix + clientKey
		cutoffTime := float64(windowStart.UnixMilli())

		// Remove expired entries first
		swrl.config.RedisClient.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatFloat(cutoffTime, 'f', 0, 64))

		// Get count of valid entries
		count, _ := swrl.config.RedisClient.ZCard(ctx, key).Result()

		var oldestTime, newestTime *time.Time
		if count > 0 {
			// Get oldest timestamp using ZRangeWithScores (compatible with go-redis v8)
			if oldestEntries, err := swrl.config.RedisClient.ZRangeWithScores(ctx, key, 0, 0).Result(); err == nil && len(oldestEntries) > 0 {
				t := time.UnixMilli(int64(oldestEntries[0].Score))
				oldestTime = &t
			}

			// Get newest timestamp using ZRangeWithScores
			if newestEntries, err := swrl.config.RedisClient.ZRangeWithScores(ctx, key, -1, -1).Result(); err == nil && len(newestEntries) > 0 {
				t := time.UnixMilli(int64(newestEntries[0].Score))
				newestTime = &t
			}
		}

		remaining := swrl.config.Rate - int(count)
		if remaining < 0 {
			remaining = 0
		}

		estimatedReset := now.Add(swrl.config.WindowSize)
		if oldestTime != nil {
			estimatedReset = oldestTime.Add(swrl.config.WindowSize)
		}

		return &SlidingWindowInfo{
			Start:          windowStart,
			End:            now,
			Size:           swrl.config.WindowSize,
			RequestCount:   int(count),
			Limit:          swrl.config.Rate,
			Usage:          float64(count) / float64(swrl.config.Rate),
			Remaining:      remaining,
			OldestRequest:  oldestTime,
			NewestRequest:  newestTime,
			EstimatedReset: estimatedReset,
		}
	} else {
		// For memory mode, access the ring buffer
		value, exists := swrl.clients.Load(clientKey)
		if !exists {
			return &SlidingWindowInfo{
				Start:          windowStart,
				End:            now,
				Size:           swrl.config.WindowSize,
				RequestCount:   0,
				Limit:          swrl.config.Rate,
				Usage:          0,
				Remaining:      swrl.config.Rate,
				EstimatedReset: now.Add(swrl.config.WindowSize),
			}
		}

		entry := value.(*clientEntry)
		cutoffNano := windowStart.UnixNano()

		// Clean up expired entries first
		entry.timestamps.removeOlderThan(cutoffNano)
		count := entry.timestamps.count()

		var oldestTime, newestTime *time.Time
		if oldest, exists := entry.timestamps.oldest(); exists {
			t := time.Unix(0, oldest)
			oldestTime = &t
		}
		if newest, exists := entry.timestamps.newest(); exists {
			t := time.Unix(0, newest)
			newestTime = &t
		}

		remaining := swrl.config.Rate - count
		if remaining < 0 {
			remaining = 0
		}

		estimatedReset := now.Add(swrl.config.WindowSize)
		if oldestTime != nil {
			estimatedReset = oldestTime.Add(swrl.config.WindowSize)
		}

		return &SlidingWindowInfo{
			Start:          windowStart,
			End:            now,
			Size:           swrl.config.WindowSize,
			RequestCount:   count,
			Limit:          swrl.config.Rate,
			Usage:          float64(count) / float64(swrl.config.Rate),
			Remaining:      remaining,
			OldestRequest:  oldestTime,
			NewestRequest:  newestTime,
			EstimatedReset: estimatedReset,
		}
	}
}

// ResetClient resets rate limiting for a specific client
func (swrl *SlidingWindowRateLimiter) ResetClient(clientKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), swrl.config.RequestTimeout)
	defer cancel()

	if swrl.redisMode {
		swrl.config.RedisClient.Del(ctx, swrl.config.RedisKeyPrefix+clientKey)
	} else {
		swrl.clients.Delete(clientKey)
	}

	// Reset client stats
	swrl.stats.mutex.Lock()
	delete(swrl.stats.ClientStats, clientKey)
	swrl.stats.mutex.Unlock()
}

// ListActiveClients returns a list of currently active clients
func (swrl *SlidingWindowRateLimiter) ListActiveClients() []string {
	swrl.stats.mutex.RLock()
	defer swrl.stats.mutex.RUnlock()

	clients := make([]string, 0, len(swrl.stats.ClientStats))
	for clientKey, stats := range swrl.stats.ClientStats {
		if stats.IsActive {
			clients = append(clients, clientKey)
		}
	}
	return clients
}

// GetClientCount returns the number of active clients
func (swrl *SlidingWindowRateLimiter) GetClientCount() int {
	if swrl.redisMode {
		// For Redis mode, this is an approximation
		return len(swrl.ListActiveClients())
	}

	count := 0
	swrl.clients.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// ResetStats resets all statistics
func (swrl *SlidingWindowRateLimiter) ResetStats() {
	atomic.StoreInt64(&swrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&swrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&swrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&swrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&swrl.stats.TimestampsStored, 0)
	atomic.StoreInt64(&swrl.stats.MemoryUsageBytes, 0)
	swrl.stats.BaseStats.StartTime = time.Now()
	swrl.stats.AverageWindowUsage = 0

	swrl.stats.mutex.Lock()
	swrl.stats.ClientStats = make(map[string]*ClientStats)
	swrl.stats.mutex.Unlock()

	// Reset LRU cache
	swrl.clientsLRU = newLRUCache(swrl.config.MaxTrackedClients)
}

// Stop gracefully stops the rate limiter
func (swrl *SlidingWindowRateLimiter) Stop() {
	close(swrl.stopChan)
}

// Type returns the type of rate limiter
func (swrl *SlidingWindowRateLimiter) Type() RateLimiterType {
	return SlidingWindowType
}

// Algorithm returns the algorithm used
func (swrl *SlidingWindowRateLimiter) Algorithm() Algorithm {
	return SlidingWindowAlg
}
