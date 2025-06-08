// sliding_window_rate_limiter.go
// Purpose: Sliding window rate limiting with Redis support and fallback
// Use case: Precise rate limiting with smooth distribution over time windows

package middleware

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"net/http"
)

var _ RateLimiter = (*SlidingWindowRateLimiter)(nil)

// SlidingWindowConfig configuration for sliding window rate limiter
type SlidingWindowConfig struct {
	Rate               int           // Requests per window
	WindowSize         time.Duration // Window duration (e.g., 1 minute, 1 hour)
	RedisClient        *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix     string        // Prefix for Redis keys
	EnableFallback     bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor       KeyExtractor  // Function to extract a client key
	MaxClients         int           // Maximum clients to track (fallback mode)
	CleanupInterval    time.Duration // Cleanup interval (fallback mode)
	ClientTTL          time.Duration // Client TTL (fallback mode)
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *SlidingWindowRequestInfo)
	OnRequestProcessed func(*gin.Context, *SlidingWindowRequestInfo, bool)
}

// SlidingWindowRequestInfo contains request information for sliding window limiter
type SlidingWindowRequestInfo struct {
	BaseRequestInfo
	ClientKey        string    `json:"client_key"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	RequestsInWindow int       `json:"requests_in_window"`
	WindowUsage      float64   `json:"window_usage"` // 0.0 to 1.0
}

// SlidingWindowStats statistics for sliding window rate limiter
type SlidingWindowStats struct {
	*BaseStats
	ActiveClients int64                   `json:"active_clients"`
	RedisMode     bool                    `json:"redis_mode"`
	FallbackMode  bool                    `json:"fallback_mode"`
	RedisErrors   int64                   `json:"redis_errors"`
	ClientStats   map[string]*ClientStats `json:"client_stats"`
	mutex         sync.RWMutex
}

// clientEntry represents a client's rate limiting data in fallback mode
type clientEntry struct {
	timestamps []time.Time
	lastAccess time.Time
	mutex      sync.RWMutex
}

// SlidingWindowRateLimiter implements sliding window rate limiting
type SlidingWindowRateLimiter struct {
	config     *SlidingWindowConfig
	stats      *SlidingWindowStats
	clients    map[string]*clientEntry // Fallback mode client storage
	clientsMux sync.RWMutex
	stopChan   chan struct{}
	redisMode  bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter
func NewSlidingWindowRateLimiter(config *SlidingWindowConfig) *SlidingWindowRateLimiter {
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
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Minute * 5
	}
	if config.ClientTTL == 0 {
		config.ClientTTL = time.Hour
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Sliding Window Rate limit exceeded"
	}

	ctx, cancel := context.WithCancel(context.Background())

	swrl := &SlidingWindowRateLimiter{
		config:    config,
		clients:   make(map[string]*clientEntry),
		stopChan:  make(chan struct{}),
		redisMode: config.RedisClient != nil,
		ctx:       ctx,
		cancel:    cancel,
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
				log.Printf("[SLIDING_WINDOW] Redis connection failed and fallback disabled: %v", err)
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

	return swrl
}

// DefaultSlidingWindowConfig returns default configuration
func DefaultSlidingWindowConfig() *SlidingWindowConfig {
	return &SlidingWindowConfig{
		Rate:            100,
		WindowSize:      time.Minute,
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded",
	}
}

// testRedisConnection tests the Redis connection
func (swrl *SlidingWindowRateLimiter) testRedisConnection() error {
	if swrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}
	return swrl.config.RedisClient.Ping(swrl.ctx).Err()
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

// cleanupExpiredClients removes expired client entries
func (swrl *SlidingWindowRateLimiter) cleanupExpiredClients() {
	now := time.Now()
	expiry := now.Add(-swrl.config.ClientTTL)

	swrl.clientsMux.Lock()
	defer swrl.clientsMux.Unlock()

	for key, entry := range swrl.clients {
		entry.mutex.RLock()
		lastAccess := entry.lastAccess
		entry.mutex.RUnlock()

		if lastAccess.Before(expiry) {
			delete(swrl.clients, key)
		}
	}

	// Update active clients count
	atomic.StoreInt64(&swrl.stats.ActiveClients, int64(len(swrl.clients)))
}

// checkRateLimitRedis checks rate limit using Redis with improved script
func (swrl *SlidingWindowRateLimiter) checkRateLimitRedis(clientKey string) (bool, int, error) {
	now := time.Now()
	currentTime := now.UnixMilli() // Use milliseconds for better precision
	windowSizeMs := swrl.config.WindowSize.Milliseconds()

	// Improved Redis Lua script (based on your better example)
	script := `
		local key = KEYS[1]
		local window = tonumber(ARGV[1])        -- Window size in milliseconds
		local limit = tonumber(ARGV[2])         -- Rate limit
		local current_time = tonumber(ARGV[3])  -- Current timestamp in milliseconds
		
		-- Remove expired entries (older than window)
		local cutoff_time = current_time - window
		redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff_time)
		
		-- Count current entries in the window
		local current_count = redis.call('ZCARD', key)
		
		-- Check if limit would be exceeded
		if current_count >= limit then
			return {0, current_count, 0}
		end
		
		-- Add current request with unique identifier to handle concurrent requests
		local unique_id = current_time .. ':' .. math.random(100000, 999999)
		redis.call('ZADD', key, current_time, unique_id)
		
		-- Set expiry slightly longer than window to handle clock drift
		local expire_seconds = math.ceil(window / 1000) + 5
		redis.call('EXPIRE', key, expire_seconds)
		
		-- Calculate remaining requests
		local remaining = limit - current_count - 1
		
		-- Return: allowed(1), current_count+1, remaining
		return {1, current_count + 1, remaining}
	`

	result, err := swrl.config.RedisClient.Eval(swrl.ctx, script, []string{
		swrl.config.RedisKeyPrefix + clientKey,
	}, windowSizeMs, swrl.config.Rate, currentTime).Result()

	if err != nil {
		atomic.AddInt64(&swrl.stats.RedisErrors, 1)
		return false, 0, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return false, 0, fmt.Errorf("unexpected Redis result format")
	}

	allowed := resultSlice[0].(int64) == 1
	count := int(resultSlice[1].(int64))
	// remaining := int(resultSlice[2].(int64))  // Can be used for better headers

	return allowed, count, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage
func (swrl *SlidingWindowRateLimiter) checkRateLimitFallback(clientKey string) (bool, int) {
	now := time.Now()
	windowStart := now.Add(-swrl.config.WindowSize)

	swrl.clientsMux.Lock()
	entry, exists := swrl.clients[clientKey]
	if !exists {
		entry = &clientEntry{
			timestamps: make([]time.Time, 0),
			lastAccess: now,
		}
		swrl.clients[clientKey] = entry
	}
	swrl.clientsMux.Unlock()

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.lastAccess = now

	// Remove expired timestamps
	validTimestamps := make([]time.Time, 0, len(entry.timestamps))
	for _, ts := range entry.timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	entry.timestamps = validTimestamps

	// Check if limit exceeded
	if len(entry.timestamps) >= swrl.config.Rate {
		return false, len(entry.timestamps)
	}

	// Add current request
	entry.timestamps = append(entry.timestamps, now)
	return true, len(entry.timestamps)
}

// createRequestInfo creates request information
func (swrl *SlidingWindowRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, requestsInWindow int) *SlidingWindowRequestInfo {
	now := time.Now()
	windowStart := now.Add(-swrl.config.WindowSize)

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
	}
}

// setHeaders sets rate limit headers
func (swrl *SlidingWindowRateLimiter) setHeaders(c *gin.Context, remaining int, windowEnd time.Time) {
	if !swrl.config.EnableHeaders {
		return
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(swrl.config.Rate))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", windowEnd.Add(swrl.config.WindowSize).Format(time.RFC3339))
	c.Header("X-RateLimit-Window", swrl.config.WindowSize.String())
	c.Header("X-RateLimit-Algorithm", swrl.Algorithm().String())

	if swrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
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

	log.Printf("[SLIDING_WINDOW_%s] %s - Client: %s, Method: %s, Path: %s, Usage: %.2f%%, Requests: %d/%d",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.WindowUsage*100, info.RequestsInWindow, swrl.config.Rate)
}

// handleLimitExceeded handles when rate limit is exceeded
func (swrl *SlidingWindowRateLimiter) handleLimitExceeded(c *gin.Context, info *SlidingWindowRequestInfo) {
	// Set Retry-After header
	retryAfter := info.WindowEnd.Add(swrl.config.WindowSize).Sub(time.Now())
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

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       swrl.config.ErrorMessage,
		"message":     fmt.Sprintf("Rate limit exceeded: %d requests in %v window", info.RequestsInWindow, swrl.config.WindowSize),
		"client":      info.ClientKey,
		"window":      swrl.config.WindowSize.String(),
		"algorithm":   swrl.Algorithm().String(),
		"timestamp":   info.Timestamp.Format(time.RFC3339),
		"retry_after": retryAfter.Seconds(),
	})
	c.Abort()
}

// updateClientStats updates statistics for a specific client
func (swrl *SlidingWindowRateLimiter) updateClientStats(clientKey string, allowed bool) {
	swrl.stats.mutex.Lock()
	defer swrl.stats.mutex.Unlock()

	clientStats, exists := swrl.stats.ClientStats[clientKey]
	if !exists {
		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		swrl.stats.ClientStats[clientKey] = clientStats
	}

	clientStats.TotalRequests++
	clientStats.LastAccess = time.Now()
	clientStats.IsActive = true

	if allowed {
		clientStats.AllowedRequests++
	} else {
		clientStats.BlockedRequests++
	}
}

// Middleware returns the sliding window rate limiting middleware
func (swrl *SlidingWindowRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract a client key
		clientKey := swrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var requestsInWindow int
		var err error

		// Check rate limit
		if swrl.redisMode {
			allowed, requestsInWindow, err = swrl.checkRateLimitRedis(clientKey)
			if err != nil && swrl.config.EnableFallback {
				log.Printf("[SLIDING_WINDOW] Redis error, falling back to memory: %v", err)
				swrl.redisMode = false
				swrl.stats.FallbackMode = true
				allowed, requestsInWindow = swrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, requestsInWindow = swrl.checkRateLimitFallback(clientKey)
		}

		// Update global statistics
		atomic.AddInt64(&swrl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&swrl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&swrl.stats.BlockedRequests, 1)
		}

		// Update client statistics
		swrl.updateClientStats(clientKey, allowed)

		// Create request info
		info := swrl.createRequestInfo(c, clientKey, allowed, requestsInWindow)

		// Calculate remaining requests
		remaining := swrl.config.Rate - requestsInWindow
		if remaining < 0 {
			remaining = 0
		}

		// Set headers
		swrl.setHeaders(c, remaining, info.WindowEnd)

		// Log event
		swrl.logEvent(info)

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
func (swrl *SlidingWindowRateLimiter) GetStats() Stats {
	// Update live counters
	swrl.stats.TotalRequests = atomic.LoadInt64(&swrl.stats.BaseStats.TotalRequests)
	swrl.stats.AllowedRequests = atomic.LoadInt64(&swrl.stats.BaseStats.AllowedRequests)
	swrl.stats.BlockedRequests = atomic.LoadInt64(&swrl.stats.BaseStats.BlockedRequests)
	swrl.stats.ActiveClients = int64(len(swrl.clients))
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

// ResetClient resets rate limiting for a specific client
func (swrl *SlidingWindowRateLimiter) ResetClient(clientKey string) {
	if swrl.redisMode {
		swrl.config.RedisClient.Del(swrl.ctx, swrl.config.RedisKeyPrefix+clientKey)
	} else {
		swrl.clientsMux.Lock()
		delete(swrl.clients, clientKey)
		swrl.clientsMux.Unlock()
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

	swrl.clientsMux.RLock()
	defer swrl.clientsMux.RUnlock()
	return len(swrl.clients)
}

// ResetStats resets all statistics
func (swrl *SlidingWindowRateLimiter) ResetStats() {
	atomic.StoreInt64(&swrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&swrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&swrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&swrl.stats.RedisErrors, 0)
	swrl.stats.BaseStats.StartTime = time.Now()

	swrl.stats.mutex.Lock()
	swrl.stats.ClientStats = make(map[string]*ClientStats)
	swrl.stats.mutex.Unlock()
}

// Stop gracefully stops the rate limiter
func (swrl *SlidingWindowRateLimiter) Stop() {
	close(swrl.stopChan)
	swrl.cancel()
}

// Type returns the type of rate limiter
func (swrl *SlidingWindowRateLimiter) Type() RateLimiterType {
	return SlidingWindowType
}

// Algorithm returns the algorithm used
func (swrl *SlidingWindowRateLimiter) Algorithm() Algorithm {
	return SlidingWindowAlg
}
