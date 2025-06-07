// fixed_window_rate_limiter.go
// Purpose: Fixed window rate limiting with Redis support and fallback
// Use case: Simple rate limiting with fixed time windows (e.g., 100 req/minute)

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

var _ RateLimiter = (*FixedWindowRateLimiter)(nil)
var _ ClientAwareRateLimiter = (*FixedWindowRateLimiter)(nil)

// FixedWindowConfig configuration for fixed window rate limiter
type FixedWindowConfig struct {
	Rate               int           // Requests per window
	WindowSize         time.Duration // Fixed window duration (e.g., 1 minute, 1 hour)
	RedisClient        *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix     string        // Prefix for Redis keys
	EnableFallback     bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor       KeyExtractor  // Function to extract client key
	MaxClients         int           // Maximum clients to track (fallback mode)
	CleanupInterval    time.Duration // Cleanup interval (fallback mode)
	ClientTTL          time.Duration // Client TTL (fallback mode)
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *FixedWindowRequestInfo)
	OnRequestProcessed func(*gin.Context, *FixedWindowRequestInfo, bool)
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
	TimeToReset      time.Duration `json:"time_to_reset"` // Time until window resets
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
	count       int
	windowStart time.Time
	lastAccess  time.Time
	mutex       sync.RWMutex
}

// FixedWindowRateLimiter implements fixed window rate limiting
type FixedWindowRateLimiter struct {
	config     *FixedWindowConfig
	stats      *FixedWindowStats
	clients    map[string]*fixedWindowEntry // Fallback mode client storage
	clientsMux sync.RWMutex
	stopChan   chan struct{}
	redisMode  bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewFixedWindowRateLimiter creates a new fixed window rate limiter
func NewFixedWindowRateLimiter(config *FixedWindowConfig) *FixedWindowRateLimiter {
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
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Minute * 5
	}
	if config.ClientTTL == 0 {
		config.ClientTTL = time.Hour
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Fixed Window Rate limit exceeded"
	}

	ctx, cancel := context.WithCancel(context.Background())

	fwrl := &FixedWindowRateLimiter{
		config:    config,
		clients:   make(map[string]*fixedWindowEntry),
		stopChan:  make(chan struct{}),
		redisMode: config.RedisClient != nil,
		ctx:       ctx,
		cancel:    cancel,
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
				log.Printf("[FIXED_WINDOW] Redis connection failed and fallback disabled: %v", err)
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

	return fwrl
}

// DefaultFixedWindowConfig returns default configuration
func DefaultFixedWindowConfig() *FixedWindowConfig {
	return &FixedWindowConfig{
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
func (fwrl *FixedWindowRateLimiter) testRedisConnection() error {
	if fwrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}
	return fwrl.config.RedisClient.Ping(fwrl.ctx).Err()
}

// getWindowNumber calculates the current window number for consistent windowing
func (fwrl *FixedWindowRateLimiter) getWindowNumber(t time.Time) int64 {
	return t.Unix() / int64(fwrl.config.WindowSize.Seconds())
}

// getWindowStart calculates the start time of the current window
func (fwrl *FixedWindowRateLimiter) getWindowStart(windowNumber int64) time.Time {
	return time.Unix(windowNumber*int64(fwrl.config.WindowSize.Seconds()), 0)
}

// checkRateLimitRedis checks rate limit using Redis
func (fwrl *FixedWindowRateLimiter) checkRateLimitRedis(clientKey string) (bool, int, int64, error) {
	now := time.Now()
	windowNumber := fwrl.getWindowNumber(now)

	// Redis Lua script for fixed window rate limiting
	script := `
		local key = KEYS[1]
		local window_number = ARGV[1]
		local rate_limit = tonumber(ARGV[2])
		local expire_seconds = tonumber(ARGV[3])
		
		-- Create window-specific key
		local window_key = key .. ":" .. window_number
		
		-- Increment counter for this window
		local current_count = redis.call('INCR', window_key)
		
		-- Set expiry for the key (only on first increment)
		if current_count == 1 then
			redis.call('EXPIRE', window_key, expire_seconds)
		end
		
		-- Check if limit exceeded
		if current_count > rate_limit then
			return {0, current_count, window_number}
		end
		
		-- Return allowed, count, window_number
		return {1, current_count, window_number}
	`

	expireSeconds := int64(fwrl.config.WindowSize.Seconds()) + 60 // Add buffer

	result, err := fwrl.config.RedisClient.Eval(fwrl.ctx, script, []string{
		fwrl.config.RedisKeyPrefix + clientKey,
	}, windowNumber, fwrl.config.Rate, expireSeconds).Result()

	if err != nil {
		atomic.AddInt64(&fwrl.stats.RedisErrors, 1)
		return false, 0, windowNumber, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return false, 0, windowNumber, fmt.Errorf("unexpected Redis result format")
	}

	allowed := resultSlice[0].(int64) == 1
	count := int(resultSlice[1].(int64))
	returnedWindow, _ := strconv.ParseInt(resultSlice[2].(string), 10, 64)

	return allowed, count, returnedWindow, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage
func (fwrl *FixedWindowRateLimiter) checkRateLimitFallback(clientKey string) (bool, int, int64) {
	now := time.Now()
	windowNumber := fwrl.getWindowNumber(now)
	windowStart := fwrl.getWindowStart(windowNumber)

	fwrl.clientsMux.Lock()
	entry, exists := fwrl.clients[clientKey]
	if !exists {
		entry = &fixedWindowEntry{
			count:       0,
			windowStart: windowStart,
			lastAccess:  now,
		}
		fwrl.clients[clientKey] = entry
	}
	fwrl.clientsMux.Unlock()

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.lastAccess = now

	// Check if we're in a new window
	if entry.windowStart.Before(windowStart) {
		// New window, reset counter
		entry.count = 0
		entry.windowStart = windowStart
		atomic.AddInt64(&fwrl.stats.WindowsProcessed, 1)
	}

	// Check if limit exceeded
	if entry.count >= fwrl.config.Rate {
		return false, entry.count, windowNumber
	}

	// Increment counter
	entry.count++
	return true, entry.count, windowNumber
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

	fwrl.clientsMux.Lock()
	defer fwrl.clientsMux.Unlock()

	for key, entry := range fwrl.clients {
		entry.mutex.RLock()
		lastAccess := entry.lastAccess
		entry.mutex.RUnlock()

		if lastAccess.Before(expiry) {
			delete(fwrl.clients, key)
		}
	}

	// Update active clients count
	atomic.StoreInt64(&fwrl.stats.ActiveClients, int64(len(fwrl.clients)))
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
	c.Header("X-RateLimit-Algorithm", "fixed-window")

	if fwrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
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

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":         fwrl.config.ErrorMessage,
		"message":       fmt.Sprintf("Rate limit exceeded: %d requests in %v window", info.RequestsInWindow, fwrl.config.WindowSize),
		"client":        info.ClientKey,
		"window_number": info.WindowNumber,
		"window_size":   fwrl.config.WindowSize.String(),
		"reset_time":    info.WindowEnd.Format(time.RFC3339),
		"time_to_reset": info.TimeToReset.Seconds(),
		"algorithm":     "fixed-window",
		"timestamp":     info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// updateClientStats updates statistics for a specific client
func (fwrl *FixedWindowRateLimiter) updateClientStats(clientKey string, allowed bool) {
	fwrl.stats.mutex.Lock()
	defer fwrl.stats.mutex.Unlock()

	clientStats, exists := fwrl.stats.ClientStats[clientKey]
	if !exists {
		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		fwrl.stats.ClientStats[clientKey] = clientStats
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

// Middleware returns the fixed window rate limiting middleware
func (fwrl *FixedWindowRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract client key
		clientKey := fwrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var requestsInWindow int
		var windowNumber int64
		var err error

		// Check rate limit
		if fwrl.redisMode {
			allowed, requestsInWindow, windowNumber, err = fwrl.checkRateLimitRedis(clientKey)
			if err != nil && fwrl.config.EnableFallback {
				log.Printf("[FIXED_WINDOW] Redis error, falling back to memory: %v", err)
				fwrl.redisMode = false
				fwrl.stats.FallbackMode = true
				allowed, requestsInWindow, windowNumber = fwrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, requestsInWindow, windowNumber = fwrl.checkRateLimitFallback(clientKey)
		}

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
func (fwrl *FixedWindowRateLimiter) GetStats() Stats {
	// Update live counters
	fwrl.stats.TotalRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.TotalRequests)
	fwrl.stats.AllowedRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.AllowedRequests)
	fwrl.stats.BlockedRequests = atomic.LoadInt64(&fwrl.stats.BaseStats.BlockedRequests)
	fwrl.stats.ActiveClients = int64(len(fwrl.clients))
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
	if fwrl.redisMode {
		// Delete all window keys for this client (pattern match)
		pattern := fwrl.config.RedisKeyPrefix + clientKey + ":*"
		keys, err := fwrl.config.RedisClient.Keys(fwrl.ctx, pattern).Result()
		if err == nil && len(keys) > 0 {
			fwrl.config.RedisClient.Del(fwrl.ctx, keys...)
		}
	} else {
		fwrl.clientsMux.Lock()
		delete(fwrl.clients, clientKey)
		fwrl.clientsMux.Unlock()
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

	fwrl.clientsMux.RLock()
	defer fwrl.clientsMux.RUnlock()
	return len(fwrl.clients)
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
}

// Stop gracefully stops the rate limiter
func (fwrl *FixedWindowRateLimiter) Stop() {
	close(fwrl.stopChan)
	fwrl.cancel()
}

// Type returns the type of rate limiter
func (fwrl *FixedWindowRateLimiter) Type() RateLimiterType {
	return FixedWindowType
}

// Algorithm returns the algorithm used
func (fwrl *FixedWindowRateLimiter) Algorithm() Algorithm {
	return FixedWindowAlg
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

// FixedWindowMiddleware creates a simple fixed window rate limiter
func FixedWindowMiddleware(requestsPerWindow int, windowSize time.Duration, redisClient *redis.Client) gin.HandlerFunc {
	config := &FixedWindowConfig{
		Rate:           requestsPerWindow,
		WindowSize:     windowSize,
		RedisClient:    redisClient,
		EnableFallback: true,
		EnableHeaders:  true,
		KeyExtractor:   IPKeyExtractor,
	}
	limiter := NewFixedWindowRateLimiter(config)
	return limiter.Middleware()
}

// FixedWindowPerIPMiddleware creates a per-IP fixed window rate limiter
func FixedWindowPerIPMiddleware(requestsPerWindow int, windowSize time.Duration, redisClient *redis.Client) gin.HandlerFunc {
	return FixedWindowMiddleware(requestsPerWindow, windowSize, redisClient)
}

// FixedWindowPerUserMiddleware creates a per-user fixed window rate limiter
func FixedWindowPerUserMiddleware(requestsPerWindow int, windowSize time.Duration, redisClient *redis.Client) gin.HandlerFunc {
	config := &FixedWindowConfig{
		Rate:           requestsPerWindow,
		WindowSize:     windowSize,
		RedisClient:    redisClient,
		EnableFallback: true,
		EnableHeaders:  true,
		KeyExtractor:   UserIDKeyExtractor,
	}
	limiter := NewFixedWindowRateLimiter(config)
	return limiter.Middleware()
}

// FixedWindowPerAPIKeyMiddleware creates a per-API-key fixed window rate limiter
func FixedWindowPerAPIKeyMiddleware(requestsPerWindow int, windowSize time.Duration, redisClient *redis.Client) gin.HandlerFunc {
	config := &FixedWindowConfig{
		Rate:           requestsPerWindow,
		WindowSize:     windowSize,
		RedisClient:    redisClient,
		EnableFallback: true,
		EnableHeaders:  true,
		KeyExtractor:   APIKeyExtractor,
	}
	limiter := NewFixedWindowRateLimiter(config)
	return limiter.Middleware()
}
