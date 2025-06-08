// leaky_bucket_rate_limiter.go
// Purpose: Leaky bucket rate limiting with Redis support and fallback
// Use case: Smooth rate limiting with constant outflow rate and buffer capacity

package middleware

import (
	"context"
	"fmt"
	"log"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"net/http"
)

var _ RateLimiter = (*LeakyBucketRateLimiter)(nil)

// LeakyBucketConfig configuration for leaky bucket rate limiter
type LeakyBucketConfig struct {
	LeakRate           float64       // Requests per second that leak out
	Capacity           int           // Maximum bucket capacity (buffer size)
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
	AllowQueueing      bool          // Allow requests to wait in queue
	MaxQueueTime       time.Duration // Maximum time to wait in queue
	OnLimitExceeded    func(*gin.Context, *LeakyBucketRequestInfo)
	OnRequestProcessed func(*gin.Context, *LeakyBucketRequestInfo, bool)
}

// LeakyBucketRequestInfo contains request information for leaky bucket limiter
type LeakyBucketRequestInfo struct {
	BaseRequestInfo
	ClientKey     string        `json:"client_key"`
	CurrentLevel  float64       `json:"current_level"`  // Current bucket level (0.0 to capacity)
	Capacity      int           `json:"capacity"`       // Bucket capacity
	LeakRate      float64       `json:"leak_rate"`      // Leak rate per second
	BucketUsage   float64       `json:"bucket_usage"`   // 0.0 to 1.0
	EstimatedWait time.Duration `json:"estimated_wait"` // Time to wait if queueing enabled
	TimeToEmpty   time.Duration `json:"time_to_empty"`  // Time for bucket to empty
}

// LeakyBucketStats statistics for leaky bucket rate limiter
type LeakyBucketStats struct {
	*BaseStats
	ActiveClients   int64                   `json:"active_clients"`
	RedisMode       bool                    `json:"redis_mode"`
	FallbackMode    bool                    `json:"fallback_mode"`
	RedisErrors     int64                   `json:"redis_errors"`
	QueuedRequests  int64                   `json:"queued_requests"`
	DroppedRequests int64                   `json:"dropped_requests"`
	AverageWaitTime time.Duration           `json:"average_wait_time"`
	ClientStats     map[string]*ClientStats `json:"client_stats"`
	mutex           sync.RWMutex
}

// leakyBucketEntry represents a client's bucket state in fallback mode
type leakyBucketEntry struct {
	level      float64   // Current bucket level
	lastUpdate time.Time // Last update time
	lastAccess time.Time // Last access time
	mutex      sync.RWMutex
}

// LeakyBucketRateLimiter implements leaky bucket rate limiting
type LeakyBucketRateLimiter struct {
	config     *LeakyBucketConfig
	stats      *LeakyBucketStats
	clients    map[string]*leakyBucketEntry // Fallback mode client storage
	clientsMux sync.RWMutex
	stopChan   chan struct{}
	redisMode  bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewLeakyBucketRateLimiter creates a new leaky bucket rate limiter
func NewLeakyBucketRateLimiter(config *LeakyBucketConfig) *LeakyBucketRateLimiter {
	if config == nil {
		config = DefaultLeakyBucketConfig()
	}

	// Set defaults
	if config.LeakRate <= 0 {
		config.LeakRate = 10.0 // 10 requests per second
	}
	if config.Capacity <= 0 {
		config.Capacity = 100 // 100 request buffer
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "rate_limit:leaky_bucket:"
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
		config.ErrorMessage = "Rate limit exceeded"
	}
	if config.MaxQueueTime == 0 {
		config.MaxQueueTime = time.Second * 10
	}

	ctx, cancel := context.WithCancel(context.Background())

	lbrl := &LeakyBucketRateLimiter{
		config:    config,
		clients:   make(map[string]*leakyBucketEntry),
		stopChan:  make(chan struct{}),
		redisMode: config.RedisClient != nil,
		ctx:       ctx,
		cancel:    cancel,
		stats: &LeakyBucketStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: LeakyBucketType,
			},
			ClientStats: make(map[string]*ClientStats),
		},
	}

	// Test Redis connection
	if lbrl.redisMode {
		if err := lbrl.testRedisConnection(); err != nil {
			if config.EnableFallback {
				log.Printf("[LEAKY_BUCKET] Redis connection failed, falling back to in-memory: %v", err)
				lbrl.redisMode = false
				lbrl.stats.FallbackMode = true
			} else {
				log.Printf("[LEAKY_BUCKET] Redis connection failed and fallback disabled: %v", err)
			}
		} else {
			lbrl.stats.RedisMode = true
		}
	} else {
		lbrl.stats.FallbackMode = true
	}

	// Start cleanup routine for fallback mode
	if !lbrl.redisMode {
		go lbrl.cleanupRoutine()
	}

	return lbrl
}

// DefaultLeakyBucketConfig returns default configuration
func DefaultLeakyBucketConfig() *LeakyBucketConfig {
	return &LeakyBucketConfig{
		LeakRate:        10.0, // 10 requests per second
		Capacity:        100,  // 100 request buffer
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded",
		AllowQueueing:   false,
		MaxQueueTime:    time.Second * 10,
	}
}

// testRedisConnection tests the Redis connection
func (lbrl *LeakyBucketRateLimiter) testRedisConnection() error {
	if lbrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}
	return lbrl.config.RedisClient.Ping(lbrl.ctx).Err()
}

// checkRateLimitRedis checks rate limit using Redis
func (lbrl *LeakyBucketRateLimiter) checkRateLimitRedis(clientKey string) (bool, float64, time.Duration, error) {
	now := time.Now()
	currentTimeMs := now.UnixMilli()

	// Redis Lua script for leaky bucket rate limiting
	script := `
		local key = KEYS[1]
		local current_time = tonumber(ARGV[1])  -- Current time in milliseconds
		local leak_rate = tonumber(ARGV[2])     -- Leak rate per second
		local capacity = tonumber(ARGV[3])      -- Bucket capacity
		local request_cost = tonumber(ARGV[4])  -- Cost of this request (usually 1)
		
		-- Get current bucket state
		local bucket_data = redis.call('HMGET', key, 'level', 'last_update')
		local current_level = tonumber(bucket_data[1]) or 0
		local last_update = tonumber(bucket_data[2]) or current_time
		
		-- Calculate time passed and amount leaked
		local time_passed_seconds = (current_time - last_update) / 1000.0
		local leak_amount = time_passed_seconds * leak_rate
		
		-- Update bucket level (subtract leaked amount)
		local new_level = math.max(0, current_level - leak_amount)
		
		-- Check if request can be accommodated
		if new_level + request_cost > capacity then
			-- Bucket overflow, calculate wait time
			local overflow = (new_level + request_cost) - capacity
			local wait_time_seconds = overflow / leak_rate
			
			-- Update bucket state without adding the request
			redis.call('HMSET', key, 'level', new_level, 'last_update', current_time)
			redis.call('EXPIRE', key, 3600)
			
			return {0, new_level, wait_time_seconds} -- not allowed, level, wait_time
		else
			-- Add request to bucket
			new_level = new_level + request_cost
			
			-- Update bucket state
			redis.call('HMSET', key, 'level', new_level, 'last_update', current_time)
			redis.call('EXPIRE', key, 3600)
			
			return {1, new_level, 0} -- allowed, new_level, wait_time
		end
	`

	result, err := lbrl.config.RedisClient.Eval(lbrl.ctx, script, []string{
		lbrl.config.RedisKeyPrefix + clientKey,
	}, currentTimeMs, lbrl.config.LeakRate, lbrl.config.Capacity, 1).Result()

	if err != nil {
		atomic.AddInt64(&lbrl.stats.RedisErrors, 1)
		return false, 0, 0, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return false, 0, 0, fmt.Errorf("unexpected Redis result format")
	}

	allowed := resultSlice[0].(int64) == 1
	currentLevel, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[1]), 64)
	waitTimeSeconds, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[2]), 64)
	waitTime := time.Duration(waitTimeSeconds * float64(time.Second))

	return allowed, currentLevel, waitTime, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage
func (lbrl *LeakyBucketRateLimiter) checkRateLimitFallback(clientKey string) (bool, float64, time.Duration) {
	now := time.Now()

	lbrl.clientsMux.Lock()
	entry, exists := lbrl.clients[clientKey]
	if !exists {
		entry = &leakyBucketEntry{
			level:      0,
			lastUpdate: now,
			lastAccess: now,
		}
		lbrl.clients[clientKey] = entry
	}
	lbrl.clientsMux.Unlock()

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.lastAccess = now

	// Calculate time passed and leak amount
	timePassed := now.Sub(entry.lastUpdate)
	leakAmount := timePassed.Seconds() * lbrl.config.LeakRate

	// Update bucket level (subtract leaked amount)
	entry.level = math.Max(0, entry.level-leakAmount)
	entry.lastUpdate = now

	// Check if request can be accommodated
	requestCost := 1.0
	if entry.level+requestCost > float64(lbrl.config.Capacity) {
		// Bucket overflow, calculate wait time
		overflow := (entry.level + requestCost) - float64(lbrl.config.Capacity)
		waitTime := time.Duration(overflow/lbrl.config.LeakRate) * time.Second

		return false, entry.level, waitTime
	}

	// Add request to bucket
	entry.level += requestCost
	return true, entry.level, 0
}

// cleanupRoutine cleans up expired client entries in fallback mode
func (lbrl *LeakyBucketRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(lbrl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lbrl.cleanupExpiredClients()
		case <-lbrl.stopChan:
			return
		}
	}
}

// cleanupExpiredClients removes expired client entries
func (lbrl *LeakyBucketRateLimiter) cleanupExpiredClients() {
	now := time.Now()
	expiry := now.Add(-lbrl.config.ClientTTL)

	lbrl.clientsMux.Lock()
	defer lbrl.clientsMux.Unlock()

	for key, entry := range lbrl.clients {
		entry.mutex.RLock()
		lastAccess := entry.lastAccess
		entry.mutex.RUnlock()

		if lastAccess.Before(expiry) {
			delete(lbrl.clients, key)
		}
	}

	// Update active clients count
	atomic.StoreInt64(&lbrl.stats.ActiveClients, int64(len(lbrl.clients)))
}

// createRequestInfo creates request information
func (lbrl *LeakyBucketRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, currentLevel float64, estimatedWait time.Duration) *LeakyBucketRequestInfo {
	now := time.Now()
	bucketUsage := currentLevel / float64(lbrl.config.Capacity)
	timeToEmpty := time.Duration(currentLevel/lbrl.config.LeakRate) * time.Second

	return &LeakyBucketRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: now,
			Allowed:   allowed,
		},
		ClientKey:     clientKey,
		CurrentLevel:  currentLevel,
		Capacity:      lbrl.config.Capacity,
		LeakRate:      lbrl.config.LeakRate,
		BucketUsage:   bucketUsage,
		EstimatedWait: estimatedWait,
		TimeToEmpty:   timeToEmpty,
	}
}

// setHeaders sets rate limit headers
func (lbrl *LeakyBucketRateLimiter) setHeaders(c *gin.Context, currentLevel float64, timeToEmpty time.Duration) {
	if !lbrl.config.EnableHeaders {
		return
	}

	remaining := int(math.Max(0, float64(lbrl.config.Capacity)-currentLevel))

	c.Header("X-RateLimit-Limit", strconv.Itoa(lbrl.config.Capacity))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(timeToEmpty).Format(time.RFC3339))
	c.Header("X-RateLimit-Leak-Rate", fmt.Sprintf("%.2f/sec", lbrl.config.LeakRate))
	c.Header("X-RateLimit-Bucket-Level", fmt.Sprintf("%.2f", currentLevel))
	c.Header("X-RateLimit-Algorithm", lbrl.Algorithm().String())

	if lbrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
	}
}

// logEvent logs rate limiting events
func (lbrl *LeakyBucketRateLimiter) logEvent(info *LeakyBucketRequestInfo) {
	if !lbrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	mode := "MEMORY"
	if lbrl.redisMode {
		mode = "REDIS"
	}

	log.Printf("[LEAKY_BUCKET_%s] %s - Client: %s, Method: %s, Path: %s, Level: %.2f/%d (%.1f%%), Wait: %v",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.CurrentLevel, info.Capacity, info.BucketUsage*100, info.EstimatedWait)
}

// handleLimitExceeded handles when rate limit is exceeded
func (lbrl *LeakyBucketRateLimiter) handleLimitExceeded(c *gin.Context, info *LeakyBucketRequestInfo) {
	// Set Retry-After header if wait time is reasonable
	if info.EstimatedWait > 0 && info.EstimatedWait <= lbrl.config.MaxQueueTime {
		SetRetryAfterHeader(c, info.EstimatedWait)
	}

	// Call custom handler if provided
	if lbrl.config.OnLimitExceeded != nil {
		lbrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if lbrl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, lbrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response:
	response := gin.H{
		"error":        lbrl.config.ErrorMessage,
		"message":      "Bucket capacity exceeded",
		"client":       info.ClientKey,
		"bucket_level": info.CurrentLevel,
		"capacity":     info.Capacity,
		"leak_rate":    fmt.Sprintf("%.2f req/sec", info.LeakRate),
		"bucket_usage": fmt.Sprintf("%.1f%%", info.BucketUsage*100),
		"algorithm":    lbrl.Algorithm().String(),
		"timestamp":    info.Timestamp.Format(time.RFC3339),
	}

	if info.EstimatedWait > 0 {
		response["estimated_wait_seconds"] = info.EstimatedWait.Seconds()
		response["estimated_wait"] = info.EstimatedWait.String()
		response["time_to_empty"] = info.TimeToEmpty.String()
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// handleQueuedRequest handles requests that need to wait
func (lbrl *LeakyBucketRateLimiter) handleQueuedRequest(c *gin.Context, info *LeakyBucketRequestInfo) bool {
	if !lbrl.config.AllowQueueing || info.EstimatedWait <= 0 || info.EstimatedWait > lbrl.config.MaxQueueTime {
		return false
	}

	atomic.AddInt64(&lbrl.stats.QueuedRequests, 1)

	// Wait for bucket to have space:
	select {
	case <-time.After(info.EstimatedWait):
		// Try again after waiting
		return true
	case <-lbrl.ctx.Done():
		return false
	}
}

// updateClientStats updates statistics for a specific client
func (lbrl *LeakyBucketRateLimiter) updateClientStats(clientKey string, allowed bool) {
	lbrl.stats.mutex.Lock()
	defer lbrl.stats.mutex.Unlock()

	clientStats, exists := lbrl.stats.ClientStats[clientKey]
	if !exists {
		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		lbrl.stats.ClientStats[clientKey] = clientStats
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

// Middleware returns the leaky bucket rate limiting middleware
func (lbrl *LeakyBucketRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract a client key
		clientKey := lbrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var currentLevel float64
		var estimatedWait time.Duration
		var err error

		// Check rate limit
		if lbrl.redisMode {
			allowed, currentLevel, estimatedWait, err = lbrl.checkRateLimitRedis(clientKey)
			if err != nil && lbrl.config.EnableFallback {
				log.Printf("[LEAKY_BUCKET] Redis error, falling back to memory: %v", err)
				lbrl.redisMode = false
				lbrl.stats.FallbackMode = true
				allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
		}

		// Handle queueing if enabled and request is blocked
		if !allowed && lbrl.config.AllowQueueing {
			if lbrl.handleQueuedRequest(c, &LeakyBucketRequestInfo{EstimatedWait: estimatedWait}) {
				// Retry after waiting
				if lbrl.redisMode {
					allowed, currentLevel, estimatedWait, _ = lbrl.checkRateLimitRedis(clientKey)
				} else {
					allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
				}
			}
		}

		// Update global statistics
		atomic.AddInt64(&lbrl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&lbrl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&lbrl.stats.BlockedRequests, 1)
			atomic.AddInt64(&lbrl.stats.DroppedRequests, 1)
		}

		// Update client statistics
		lbrl.updateClientStats(clientKey, allowed)

		// Create request info
		info := lbrl.createRequestInfo(c, clientKey, allowed, currentLevel, estimatedWait)

		// Set headers
		lbrl.setHeaders(c, currentLevel, info.TimeToEmpty)

		// Log event
		lbrl.logEvent(info)

		// Call request processed handler if provided
		if lbrl.config.OnRequestProcessed != nil {
			lbrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			lbrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns rate limiting statistics
func (lbrl *LeakyBucketRateLimiter) GetStats() Stats {
	// Update live counters
	lbrl.stats.TotalRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.TotalRequests)
	lbrl.stats.AllowedRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.AllowedRequests)
	lbrl.stats.BlockedRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.BlockedRequests)
	lbrl.stats.ActiveClients = int64(len(lbrl.clients))
	lbrl.stats.RedisMode = lbrl.redisMode
	return lbrl.stats
}

// GetClientStats returns statistics for a specific client
func (lbrl *LeakyBucketRateLimiter) GetClientStats(clientKey string) ClientStats {
	lbrl.stats.mutex.RLock()
	defer lbrl.stats.mutex.RUnlock()

	if stats, exists := lbrl.stats.ClientStats[clientKey]; exists {
		return *stats
	}
	return ClientStats{ClientKey: clientKey}
}

// ResetClient resets rate limiting for a specific client
func (lbrl *LeakyBucketRateLimiter) ResetClient(clientKey string) {
	if lbrl.redisMode {
		lbrl.config.RedisClient.Del(lbrl.ctx, lbrl.config.RedisKeyPrefix+clientKey)
	} else {
		lbrl.clientsMux.Lock()
		delete(lbrl.clients, clientKey)
		lbrl.clientsMux.Unlock()
	}

	// Reset client stats
	lbrl.stats.mutex.Lock()
	delete(lbrl.stats.ClientStats, clientKey)
	lbrl.stats.mutex.Unlock()
}

// ListActiveClients returns a list of currently active clients
func (lbrl *LeakyBucketRateLimiter) ListActiveClients() []string {
	lbrl.stats.mutex.RLock()
	defer lbrl.stats.mutex.RUnlock()

	clients := make([]string, 0, len(lbrl.stats.ClientStats))
	for clientKey, stats := range lbrl.stats.ClientStats {
		if stats.IsActive {
			clients = append(clients, clientKey)
		}
	}
	return clients
}

// GetClientCount returns the number of active clients
func (lbrl *LeakyBucketRateLimiter) GetClientCount() int {
	if lbrl.redisMode {
		// For Redis mode, this is an approximation
		return len(lbrl.ListActiveClients())
	}

	lbrl.clientsMux.RLock()
	defer lbrl.clientsMux.RUnlock()
	return len(lbrl.clients)
}

// ResetStats resets all statistics
func (lbrl *LeakyBucketRateLimiter) ResetStats() {
	atomic.StoreInt64(&lbrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&lbrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&lbrl.stats.QueuedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.DroppedRequests, 0)
	lbrl.stats.BaseStats.StartTime = time.Now()

	lbrl.stats.mutex.Lock()
	lbrl.stats.ClientStats = make(map[string]*ClientStats)
	lbrl.stats.mutex.Unlock()
}

// Stop gracefully stops the rate limiter
func (lbrl *LeakyBucketRateLimiter) Stop() {
	close(lbrl.stopChan)
	lbrl.cancel()
}

// Type returns the type of rate limiter
func (lbrl *LeakyBucketRateLimiter) Type() RateLimiterType {
	return LeakyBucketType
}

// Algorithm returns the algorithm used
func (lbrl *LeakyBucketRateLimiter) Algorithm() Algorithm {
	return LeakyBucketAlg
}
