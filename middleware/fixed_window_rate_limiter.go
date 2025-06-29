// fixed_window_rate_limiter.go
// Purpose: Fixed window rate limiting with Redis support and fallback
// Use case: Simple rate limiting with fixed time windows (e.g., 100 req/minute)

package middleware

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"net/http"
)

var _ RateLimiter = (*FixedWindowRateLimiter)(nil)

// RateLimitError represents a rate limiting error with detailed information
type RateLimitError struct {
	Type       string        `json:"type"`
	Message    string        `json:"message"`
	ClientKey  string        `json:"client_key"`
	RetryAfter time.Duration `json:"retry_after"`
	WindowInfo *WindowInfo   `json:"window_info"`
}

func (e *RateLimitError) Error() string {
	return e.Message
}

// WindowInfo provides information about the current window
type WindowInfo struct {
	Number      int64         `json:"number"`
	Start       time.Time     `json:"start"`
	End         time.Time     `json:"end"`
	Usage       float64       `json:"usage"`
	Remaining   int           `json:"remaining"`
	TimeToReset time.Duration `json:"time_to_reset"`
}

// FixedWindowConfig configuration for fixed window rate limiter
type FixedWindowConfig struct {
	Rate               int           // Requests per window
	WindowSize         time.Duration // Fixed window duration (e.g., 1 minute, 1 hour)
	RedisClient        *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix     string        // Prefix for Redis keys
	EnableFallback     bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor       KeyExtractor  // Function to extract a client key
	MaxClients         int           // Maximum clients to track (fallback mode)
	MaxTrackedClients  int           // Maximum clients to track in statistics
	CleanupInterval    time.Duration // Cleanup interval (fallback mode)
	ClientTTL          time.Duration // Client TTL (fallback mode)
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	EnableJitter       bool          // Enable jitter to prevent thundering herd
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	MetricsCollector   Metrics       // Optional metrics collector
	RequestTimeout     time.Duration // Timeout for Redis operations
	OnLimitExceeded    func(*gin.Context, *FixedWindowRequestInfo)
	OnRequestProcessed func(*gin.Context, *FixedWindowRequestInfo, bool)
}

// Validate validates the configuration
func (config *FixedWindowConfig) Validate() error {
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
	return nil
}

// FixedWindowRequestInfo contains request information for fixed window limiter
type FixedWindowRequestInfo struct {
	BaseRequestInfo
	ClientKey        string        `json:"client_key"`
	WindowStart      time.Time     `json:"window_start"`
	WindowEnd        time.Time     `json:"window_end"`
	WindowNumber     int64         `json:"window_number"` // Window identifier
	RequestsInWindow int           `json:"requests_in_window"`
	WindowUsage      float64       `json:"window_usage"`  // 0.0 to 1.0
	TimeToReset      time.Duration `json:"time_to_reset"` // Time until a window resets
}

// FixedWindowStats statistics for fixed window rate limiter
type FixedWindowStats struct {
	*BaseStats
	ActiveClients    int64                   `json:"active_clients"`
	RedisMode        bool                    `json:"redis_mode"`
	FallbackMode     bool                    `json:"fallback_mode"`
	RedisErrors      int64                   `json:"redis_errors"`
	WindowsProcessed int64                   `json:"windows_processed"`
	ClientStats      map[string]*ClientStats `json:"client_stats"`
	mutex            sync.RWMutex
}

// fixedWindowEntry represents a client's window data in fallback mode
type fixedWindowEntry struct {
	count       int64
	windowStart time.Time
	lastAccess  time.Time
}

// lruNode represents a node in the LRU cache for client statistics
type lruNode struct {
	key  string
	prev *lruNode
	next *lruNode
}

// lruCache implements LRU eviction for client statistics
type lruCache struct {
	capacity int
	cache    map[string]*lruNode
	head     *lruNode
	tail     *lruNode
	mutex    sync.Mutex
}

func newLRUCache(capacity int) *lruCache {
	head := &lruNode{}
	tail := &lruNode{}
	head.next = tail
	tail.prev = head

	return &lruCache{
		capacity: capacity,
		cache:    make(map[string]*lruNode),
		head:     head,
		tail:     tail,
	}
}

func (lru *lruCache) access(key string) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if node, exists := lru.cache[key]; exists {
		lru.moveToHead(node)
		return
	}

	node := &lruNode{key: key}
	lru.cache[key] = node
	lru.addToHead(node)

	if len(lru.cache) > lru.capacity {
		tail := lru.removeTail()
		delete(lru.cache, tail.key)
	}
}

func (lru *lruCache) moveToHead(node *lruNode) {
	lru.removeNode(node)
	lru.addToHead(node)
}

func (lru *lruCache) addToHead(node *lruNode) {
	node.prev = lru.head
	node.next = lru.head.next
	lru.head.next.prev = node
	lru.head.next = node
}

func (lru *lruCache) removeNode(node *lruNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

func (lru *lruCache) removeTail() *lruNode {
	lastNode := lru.tail.prev
	lru.removeNode(lastNode)
	return lastNode
}

func (lru *lruCache) shouldEvict(key string) bool {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	_, exists := lru.cache[key]
	return !exists && len(lru.cache) >= lru.capacity
}

// FixedWindowRateLimiter implements fixed window rate limiting
type FixedWindowRateLimiter struct {
	config     *FixedWindowConfig
	stats      *FixedWindowStats
	clients    sync.Map // map[string]*fixedWindowEntry - Better concurrent performance
	clientsLRU *lruCache
	stopChan   chan struct{}
	redisMode  bool
}

// NewFixedWindowRateLimiter creates a new fixed window rate limiter
func NewFixedWindowRateLimiter(config *FixedWindowConfig) (*FixedWindowRateLimiter, error) {
	if config == nil {
		config = DefaultFixedWindowConfig()
	}

	// Set defaults
	if config.WindowSize == 0 {
		config.WindowSize = time.Minute
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "rate_limit:fixed_window:"
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
		config.ErrorMessage = "Fixed Window Rate limit exceeded"
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	fwrl := &FixedWindowRateLimiter{
		config:     config,
		clientsLRU: newLRUCache(config.MaxTrackedClients),
		stopChan:   make(chan struct{}),
		redisMode:  config.RedisClient != nil,
		stats: &FixedWindowStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: FixedWindowType,
			},
			ClientStats: make(map[string]*ClientStats),
		},
	}

	// Test Redis connection
	if fwrl.redisMode {
		if err := fwrl.testRedisConnection(); err != nil {
			if config.EnableFallback {
				log.Printf("[FIXED_WINDOW] Redis connection failed, falling back to in-memory: %v", err)
				fwrl.redisMode = false
				fwrl.stats.FallbackMode = true
			} else {
				return nil, fmt.Errorf("redis connection failed and fallback disabled: %w", err)
			}
		} else {
			fwrl.stats.RedisMode = true
		}
	} else {
		fwrl.stats.FallbackMode = true
	}

	// Start cleanup routine for fallback mode
	if !fwrl.redisMode {
		go fwrl.cleanupRoutine()
	}

	return fwrl, nil
}

// DefaultFixedWindowConfig returns default configuration
func DefaultFixedWindowConfig() *FixedWindowConfig {
	return &FixedWindowConfig{
		Rate:              100,
		WindowSize:        time.Minute,
		EnableFallback:    true,
		KeyExtractor:      IPKeyExtractor,
		MaxClients:        10000,
		MaxTrackedClients: 1000,
		CleanupInterval:   time.Minute * 5,
		ClientTTL:         time.Hour,
		RequestTimeout:    time.Second * 5,
		EnableHeaders:     true,
		EnableLogging:     false,
		EnableJitter:      false,
		ErrorMessage:      "Rate limit exceeded",
	}
}

// testRedisConnection tests the Redis connection
func (fwrl *FixedWindowRateLimiter) testRedisConnection() error {
	if fwrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), fwrl.config.RequestTimeout)
	defer cancel()

	return fwrl.config.RedisClient.Ping(ctx).Err()
}

// getWindowNumber calculates the current window number for consistent windowing
func (fwrl *FixedWindowRateLimiter) getWindowNumber(t time.Time, clientKey string) int64 {
	baseWindow := t.Unix() / int64(fwrl.config.WindowSize.Seconds())

	// Add deterministic jitter based on client key to prevent thundering herd
	if fwrl.config.EnableJitter {
		hash := fnv.New32a()
		hash.Write([]byte(clientKey))
		jitter := int64(hash.Sum32() % uint32(fwrl.config.WindowSize.Seconds()/10))
		return (t.Unix() + jitter) / int64(fwrl.config.WindowSize.Seconds())
	}

	return baseWindow
}

// getWindowStart calculates the start time of the current window
func (fwrl *FixedWindowRateLimiter) getWindowStart(windowNumber int64) time.Time {
	return time.Unix(windowNumber*int64(fwrl.config.WindowSize.Seconds()), 0)
}

// checkRateLimitRedis checks rate limit using Redis
func (fwrl *FixedWindowRateLimiter) checkRateLimitRedis(ctx context.Context, clientKey string) (bool, int, int64, error) {
	now := time.Now()
	windowNumber := fwrl.getWindowNumber(now, clientKey)

	// Enhanced Redis Lua script for fixed window rate limiting with better error handling
	script := `
		local key = KEYS[1]
		local window_number = ARGV[1]
		local rate_limit = tonumber(ARGV[2])
		local expire_seconds = tonumber(ARGV[3])
		
		-- Input validation
		if not rate_limit or rate_limit <= 0 then
			return redis.error_reply("Invalid rate limit: " .. tostring(ARGV[2]))
		end
		
		if not window_number then
			return redis.error_reply("Invalid window number: " .. tostring(ARGV[1]))
		end
		
		-- Create window-specific key
		local window_key = key .. ":" .. window_number
		
		-- Increment counter for this window
		local current_count = redis.call('INCR', window_key)
		
		-- Set expiry for the key (only on first increment)
		if current_count == 1 then
			redis.call('EXPIRE', window_key, expire_seconds)
		end
		
		-- Get TTL for better reset time calculation
		local ttl = redis.call('TTL', window_key)
		if ttl == -1 then
			-- Key exists but has no TTL, set it
			redis.call('EXPIRE', window_key, expire_seconds)
			ttl = expire_seconds
		end
		
		-- Check if limit exceeded
		local allowed = current_count <= rate_limit and 1 or 0
		
		-- Return allowed, count, window_number, ttl
		return {allowed, current_count, window_number, ttl}
	`

	expireSeconds := int64(fwrl.config.WindowSize.Seconds()) + 60 // Add buffer

	result, err := fwrl.config.RedisClient.Eval(ctx, script, []string{
		fwrl.config.RedisKeyPrefix + clientKey,
	}, windowNumber, fwrl.config.Rate, expireSeconds).Result()

	if err != nil {
		atomic.AddInt64(&fwrl.stats.RedisErrors, 1)
		fwrl.recordMetric("redis_errors", 1, map[string]string{"client": clientKey})
		return false, 0, windowNumber, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 4 {
		return false, 0, windowNumber, fmt.Errorf("unexpected Redis result format: %v", result)
	}

	allowed := resultSlice[0].(int64) == 1
	count := int(resultSlice[1].(int64))
	returnedWindow := resultSlice[2].(int64)

	return allowed, count, returnedWindow, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage
func (fwrl *FixedWindowRateLimiter) checkRateLimitFallback(clientKey string) (bool, int, int64) {
	now := time.Now()
	windowNumber := fwrl.getWindowNumber(now, clientKey)
	windowStart := fwrl.getWindowStart(windowNumber)

	// Load or create entry using sync.Map for better concurrent performance
	value, _ := fwrl.clients.LoadOrStore(clientKey, &fixedWindowEntry{
		count:       0,
		windowStart: windowStart,
		lastAccess:  now,
	})

	entry := value.(*fixedWindowEntry)

	// Use atomic operations for better performance
	entry.lastAccess = now

	// Check if we're in a new window
	if entry.windowStart.Before(windowStart) {
		// New window, reset counter atomically
		atomic.StoreInt64(&entry.count, 0)
		entry.windowStart = windowStart
		atomic.AddInt64(&fwrl.stats.WindowsProcessed, 1)
	}

	// Check if limit exceeded
	currentCount := atomic.LoadInt64(&entry.count)
	if currentCount >= int64(fwrl.config.Rate) {
		return false, int(currentCount), windowNumber
	}

	// Increment counter atomically
	newCount := atomic.AddInt64(&entry.count, 1)
	return true, int(newCount), windowNumber
}

// cleanupRoutine cleans up expired client entries in fallback mode
func (fwrl *FixedWindowRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(fwrl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fwrl.cleanupExpiredClients()
		case <-fwrl.stopChan:
			return
		}
	}
}

// cleanupExpiredClients removes expired client entries
func (fwrl *FixedWindowRateLimiter) cleanupExpiredClients() {
	now := time.Now()
	expiry := now.Add(-fwrl.config.ClientTTL)
	deletedCount := 0

	fwrl.clients.Range(func(key, value interface{}) bool {
		entry := value.(*fixedWindowEntry)
		if entry.lastAccess.Before(expiry) {
			fwrl.clients.Delete(key)
			deletedCount++
		}
		return true
	})

	// Update metrics
	if deletedCount > 0 {
		fwrl.recordMetric("clients_cleaned", float64(deletedCount), nil)
	}

	// Update active clients count
	activeCount := int64(0)
	fwrl.clients.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	atomic.StoreInt64(&fwrl.stats.ActiveClients, activeCount)
}

// createRequestInfo creates request information
func (fwrl *FixedWindowRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, requestsInWindow int, windowNumber int64) *FixedWindowRequestInfo {
	now := time.Now()
	windowStart := fwrl.getWindowStart(windowNumber)
	windowEnd := windowStart.Add(fwrl.config.WindowSize)
	timeToReset := windowEnd.Sub(now)
	if timeToReset < 0 {
		timeToReset = 0
	}

	return &FixedWindowRequestInfo{
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
		WindowEnd:        windowEnd,
		WindowNumber:     windowNumber,
		RequestsInWindow: requestsInWindow,
		WindowUsage:      float64(requestsInWindow) / float64(fwrl.config.Rate),
		TimeToReset:      timeToReset,
	}
}

// setHeaders sets rate limit headers
func (fwrl *FixedWindowRateLimiter) setHeaders(c *gin.Context, remaining int, resetTime time.Time) {
	if !fwrl.config.EnableHeaders {
		return
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(fwrl.config.Rate))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", resetTime.Format(time.RFC3339))
	c.Header("X-RateLimit-Window", fwrl.config.WindowSize.String())
	c.Header("X-RateLimit-Algorithm", fwrl.Algorithm().String())

	if fwrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
	}
}

// recordMetric records a metric if metrics collector is configured
func (fwrl *FixedWindowRateLimiter) recordMetric(name string, value float64, tags map[string]string) {
	if fwrl.config.MetricsCollector != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["limiter_type"] = "fixed_window"
		tags["mode"] = "memory"
		if fwrl.redisMode {
			tags["mode"] = "redis"
		}
		fwrl.config.MetricsCollector.RecordHistogram(name, value, tags)
	}
}

// logEvent logs rate limiting events
func (fwrl *FixedWindowRateLimiter) logEvent(info *FixedWindowRequestInfo) {
	if !fwrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	mode := "MEMORY"
	if fwrl.redisMode {
		mode = "REDIS"
	}

	log.Printf("[FIXED_WINDOW_%s] %s - Client: %s, Method: %s, Path: %s, Window: %d, Usage: %.1f%%, Reset: %v",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.WindowNumber, info.WindowUsage*100, info.TimeToReset)
}

// handleLimitExceeded handles when rate limit is exceeded
func (fwrl *FixedWindowRateLimiter) handleLimitExceeded(c *gin.Context, info *FixedWindowRequestInfo) {
	// Set Retry-After header
	if info.TimeToReset > 0 {
		SetRetryAfterHeader(c, info.TimeToReset)
	}

	// Call custom handler if provided
	if fwrl.config.OnLimitExceeded != nil {
		fwrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if fwrl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, fwrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Create structured error response
	rateLimitError := &RateLimitError{
		Type:       "fixed_window_rate_limit_exceeded",
		Message:    fwrl.config.ErrorMessage,
		ClientKey:  info.ClientKey,
		RetryAfter: info.TimeToReset,
		WindowInfo: &WindowInfo{
			Number:      info.WindowNumber,
			Start:       info.WindowStart,
			End:         info.WindowEnd,
			Usage:       info.WindowUsage,
			Remaining:   fwrl.config.Rate - info.RequestsInWindow,
			TimeToReset: info.TimeToReset,
		},
	}

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       rateLimitError.Message,
		"type":        rateLimitError.Type,
		"client":      rateLimitError.ClientKey,
		"window_info": rateLimitError.WindowInfo,
		"retry_after": rateLimitError.RetryAfter.Seconds(),
		"algorithm":   fwrl.Algorithm().String(),
		"timestamp":   info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// updateClientStats updates statistics for a specific client with LRU eviction
func (fwrl *FixedWindowRateLimiter) updateClientStats(clientKey string, allowed bool) {
	// Check if we should evict before adding
	if fwrl.clientsLRU.shouldEvict(clientKey) {
		return // Skip tracking to prevent memory bloat
	}

	fwrl.stats.mutex.Lock()
	defer fwrl.stats.mutex.Unlock()

	clientStats, exists := fwrl.stats.ClientStats[clientKey]
	if !exists {
		// Check bounds again with lock held
		if len(fwrl.stats.ClientStats) >= fwrl.config.MaxTrackedClients {
			// Evict oldest client
			fwrl.evictOldestClientLocked()
		}

		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		fwrl.stats.ClientStats[clientKey] = clientStats
	}

	// Update LRU cache
	fwrl.clientsLRU.access(clientKey)

	clientStats.TotalRequests++
	clientStats.LastAccess = time.Now()
	clientStats.IsActive = true

	if allowed {
		clientStats.AllowedRequests++
	} else {
		clientStats.BlockedRequests++
	}
}

// evictOldestClientLocked evicts the oldest client from statistics (must be called with lock held)
func (fwrl *FixedWindowRateLimiter) evictOldestClientLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, stats := range fwrl.stats.ClientStats {
		if oldestKey == "" || stats.FirstSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.FirstSeen
		}
	}

	if oldestKey != "" {
		delete(fwrl.stats.ClientStats, oldestKey)
	}
}

// Middleware returns the fixed window rate limiting middleware
func (fwrl *FixedWindowRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create request-specific context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), fwrl.config.RequestTimeout)
		defer cancel()

		// Extract a client key
		clientKey := fwrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var requestsInWindow int
		var windowNumber int64
		var err error

		startTime := time.Now()

		// Check rate limit
		if fwrl.redisMode {
			allowed, requestsInWindow, windowNumber, err = fwrl.checkRateLimitRedis(ctx, clientKey)
			if err != nil && fwrl.config.EnableFallback {
				log.Printf("[FIXED_WINDOW] Redis error, falling back to memory: %v", err)
				fwrl.redisMode = false
				fwrl.stats.FallbackMode = true
				allowed, requestsInWindow, windowNumber = fwrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, requestsInWindow, windowNumber = fwrl.checkRateLimitFallback(clientKey)
		}

		// Record operation duration
		duration := time.Since(startTime)
		fwrl.recordMetric("rate_limit_check_duration_ms", float64(duration.Milliseconds()), map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		// Update global statistics
		atomic.AddInt64(&fwrl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&fwrl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&fwrl.stats.BlockedRequests, 1)
		}

		// Update client statistics
		fwrl.updateClientStats(clientKey, allowed)

		// Create request info
		info := fwrl.createRequestInfo(c, clientKey, allowed, requestsInWindow, windowNumber)

		// Calculate remaining requests
		remaining := fwrl.config.Rate - requestsInWindow
		if remaining < 0 {
			remaining = 0
		}

		// Set headers
		fwrl.setHeaders(c, remaining, info.WindowEnd)

		// Log event
		fwrl.logEvent(info)

		// Record metrics
		fwrl.recordMetric("requests_total", 1, map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		// Call request processed handler if provided
		if fwrl.config.OnRequestProcessed != nil {
			fwrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			fwrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns rate limiting statistics
func (fwrl *FixedWindowRateLimiter) GetStats() interface{} {
	// Update live counters
	fwrl.stats.TotalRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.TotalRequests)
	fwrl.stats.AllowedRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.AllowedRequests)
	fwrl.stats.BlockedRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.BlockedRequests)
	fwrl.stats.ActiveClients = atomic.LoadInt64(&fwrl.stats.ActiveClients)
	fwrl.stats.RedisMode = fwrl.redisMode
	return fwrl.stats
}

// GetClientStats returns statistics for a specific client
func (fwrl *FixedWindowRateLimiter) GetClientStats(clientKey string) ClientStats {
	fwrl.stats.mutex.RLock()
	defer fwrl.stats.mutex.RUnlock()

	if stats, exists := fwrl.stats.ClientStats[clientKey]; exists {
		return *stats
	}
	return ClientStats{ClientKey: clientKey}
}

// ResetClient resets rate limiting for a specific client
func (fwrl *FixedWindowRateLimiter) ResetClient(clientKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), fwrl.config.RequestTimeout)
	defer cancel()

	if fwrl.redisMode {
		// Delete all window keys for this client (pattern match)
		pattern := fwrl.config.RedisKeyPrefix + clientKey + ":*"
		keys, err := fwrl.config.RedisClient.Keys(ctx, pattern).Result()
		if err == nil && len(keys) > 0 {
			fwrl.config.RedisClient.Del(ctx, keys...)
		}
	} else {
		fwrl.clients.Delete(clientKey)
	}

	// Reset client stats
	fwrl.stats.mutex.Lock()
	delete(fwrl.stats.ClientStats, clientKey)
	fwrl.stats.mutex.Unlock()
}

// ListActiveClients returns a list of currently active clients
func (fwrl *FixedWindowRateLimiter) ListActiveClients() []string {
	fwrl.stats.mutex.RLock()
	defer fwrl.stats.mutex.RUnlock()

	clients := make([]string, 0, len(fwrl.stats.ClientStats))
	for clientKey, stats := range fwrl.stats.ClientStats {
		if stats.IsActive {
			clients = append(clients, clientKey)
		}
	}
	return clients
}

// GetClientCount returns the number of active clients
func (fwrl *FixedWindowRateLimiter) GetClientCount() int {
	if fwrl.redisMode {
		// For Redis mode, this is an approximation
		return len(fwrl.ListActiveClients())
	}

	count := 0
	fwrl.clients.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// ResetStats resets all statistics
func (fwrl *FixedWindowRateLimiter) ResetStats() {
	atomic.StoreInt64(&fwrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&fwrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&fwrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&fwrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&fwrl.stats.WindowsProcessed, 0)
	fwrl.stats.BaseStats.StartTime = time.Now()

	fwrl.stats.mutex.Lock()
	fwrl.stats.ClientStats = make(map[string]*ClientStats)
	fwrl.stats.mutex.Unlock()

	// Reset LRU cache
	fwrl.clientsLRU = newLRUCache(fwrl.config.MaxTrackedClients)
}

// Stop gracefully stops the rate limiter
func (fwrl *FixedWindowRateLimiter) Stop() {
	close(fwrl.stopChan)
}

// Type returns the type of rate limiter
func (fwrl *FixedWindowRateLimiter) Type() RateLimiterType {
	return FixedWindowType
}

// Algorithm returns the algorithm used
func (fwrl *FixedWindowRateLimiter) Algorithm() Algorithm {
	return FixedWindowAlg
}
