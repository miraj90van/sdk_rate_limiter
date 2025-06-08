// token_bucket_rate_limiter.go
// Purpose: Token bucket rate limiting with Redis support and fallback
// Use case: Precise rate limiting with burst support and smooth token refill

package middleware

import (
	"context"
	"fmt"
	"github.com/miraj90van/sdk_rate_limiter/component"
	"log"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
	"net/http"
)

var _ RateLimiter = (*TokenBucketRateLimiter)(nil)

// TokenBucketConfig configuration for token bucket rate limiter
type TokenBucketConfig struct {
	Rate               rate.Limit             // Tokens per second
	Burst              int                    // Bucket capacity
	RedisClient        *redis.Client          // Redis client for distributed limiting
	RedisConfig        *component.RedisConfig // Redis configuration
	RedisKeyPrefix     string                 // Prefix for Redis keys
	EnableFallback     bool                   // Enable fallback to in-memory when Redis fails
	KeyExtractor       KeyExtractor           // Function to extract a client key
	MaxClients         int                    // Maximum clients to track (fallback mode)
	CleanupInterval    time.Duration          // Cleanup interval (fallback mode)
	ClientTTL          time.Duration          // Client TTL (fallback mode)
	EnableHeaders      bool                   // Include rate limit headers
	EnableLogging      bool                   // Enable logging
	ErrorMessage       string                 // Custom error message
	ErrorResponse      interface{}            // Custom error response structure
	AllowWaiting       bool                   // Allow requests to wait for tokens
	MaxWaitTime        time.Duration          // Maximum wait time for tokens
	OnLimitExceeded    func(*gin.Context, *TokenBucketRequestInfo)
	OnRequestProcessed func(*gin.Context, *TokenBucketRequestInfo, bool)
}

// TokenBucketRequestInfo contains request information for token bucket limiter
type TokenBucketRequestInfo struct {
	BaseRequestInfo
	ClientKey       string        `json:"client_key"`
	TokensAvailable float64       `json:"tokens_available"`
	TokensUsed      int           `json:"tokens_used"`
	WaitTime        time.Duration `json:"wait_time"`
	BucketCapacity  int           `json:"bucket_capacity"`
	RefillRate      float64       `json:"refill_rate"`
}

// TokenBucketStats statistics for token bucket rate limiter
type TokenBucketStats struct {
	*BaseStats
	ActiveClients   int64                   `json:"active_clients"`
	RedisMode       bool                    `json:"redis_mode"`
	FallbackMode    bool                    `json:"fallback_mode"`
	RedisErrors     int64                   `json:"redis_errors"`
	WaitingRequests int64                   `json:"waiting_requests"`
	AverageWaitTime time.Duration           `json:"average_wait_time"`
	ClientStats     map[string]*ClientStats `json:"client_stats"`
	mutex           sync.RWMutex
}

// tokenBucketEntry represents a client's token bucket in fallback mode
type tokenBucketEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
	mutex      sync.RWMutex
}

// TokenBucketRateLimiter implements token bucket rate limiting
type TokenBucketRateLimiter struct {
	config     *TokenBucketConfig
	stats      *TokenBucketStats
	clients    map[string]*tokenBucketEntry // Fallback mode client storage
	clientsMux sync.RWMutex
	stopChan   chan struct{}
	redisMode  bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter
func NewTokenBucketRateLimiter(config *TokenBucketConfig) *TokenBucketRateLimiter {
	if config == nil {
		config = DefaultTokenBucketConfig()
	}

	// Set defaults
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "rate_limit:token_bucket:"
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
	if config.MaxWaitTime == 0 {
		config.MaxWaitTime = time.Second * 5
	}

	ctx, cancel := context.WithCancel(context.Background())

	tbrl := &TokenBucketRateLimiter{
		config:    config,
		clients:   make(map[string]*tokenBucketEntry),
		stopChan:  make(chan struct{}),
		redisMode: config.RedisClient != nil,
		ctx:       ctx,
		cancel:    cancel,
		stats: &TokenBucketStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: TokenBucketType,
			},
			ClientStats: make(map[string]*ClientStats),
		},
	}

	// Test Redis connection
	if tbrl.redisMode {
		if err := tbrl.testRedisConnection(); err != nil {
			if config.EnableFallback {
				log.Printf("[TOKEN_BUCKET] Redis connection failed, falling back to in-memory: %v", err)
				tbrl.redisMode = false
				tbrl.stats.FallbackMode = true
			} else {
				log.Printf("[TOKEN_BUCKET] Redis connection failed and fallback disabled: %v", err)
			}
		} else {
			tbrl.stats.RedisMode = true
		}
	} else {
		tbrl.stats.FallbackMode = true
	}

	// Start cleanup routine for fallback mode
	if !tbrl.redisMode {
		go tbrl.cleanupRoutine()
	}

	return tbrl
}

// DefaultTokenBucketConfig returns default configuration
func DefaultTokenBucketConfig() *TokenBucketConfig {
	return &TokenBucketConfig{
		Rate:            rate.Limit(100),
		Burst:           200,
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded",
		AllowWaiting:    false,
		MaxWaitTime:     time.Second * 5,
	}
}

// testRedisConnection tests the Redis connection
func (tbrl *TokenBucketRateLimiter) testRedisConnection() error {
	if tbrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}
	return tbrl.config.RedisClient.Ping(tbrl.ctx).Err()
}

// cleanupRoutine cleans up expired client entries in fallback mode
func (tbrl *TokenBucketRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(tbrl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tbrl.cleanupExpiredClients()
		case <-tbrl.stopChan:
			return
		}
	}
}

// cleanupExpiredClients removes expired client entries
func (tbrl *TokenBucketRateLimiter) cleanupExpiredClients() {
	now := time.Now()
	expiry := now.Add(-tbrl.config.ClientTTL)

	tbrl.clientsMux.Lock()
	defer tbrl.clientsMux.Unlock()

	for key, entry := range tbrl.clients {
		entry.mutex.RLock()
		lastAccess := entry.lastAccess
		entry.mutex.RUnlock()

		if lastAccess.Before(expiry) {
			delete(tbrl.clients, key)
		}
	}

	// Update active clients count
	atomic.StoreInt64(&tbrl.stats.ActiveClients, int64(len(tbrl.clients)))
}

// checkRateLimitRedis checks rate limit using Redis
func (tbrl *TokenBucketRateLimiter) checkRateLimitRedis(clientKey string, tokensRequested int) (bool, float64, time.Duration, error) {
	now := time.Now()

	// Redis Lua script for token bucket rate limiting
	script := `
		local key = KEYS[1]
		local tokens_requested = tonumber(ARGV[1])
		local capacity = tonumber(ARGV[2])
		local refill_rate = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		-- Get current bucket state
		local bucket_data = redis.call('HMGET', key, 'tokens', 'last_refill')
		local current_tokens = tonumber(bucket_data[1]) or capacity
		local last_refill = tonumber(bucket_data[2]) or now
		
		-- Calculate time passed and tokens to add
		local time_passed = now - last_refill
		local tokens_to_add = time_passed * refill_rate
		local new_tokens = math.min(capacity, current_tokens + tokens_to_add)
		
		-- Check if enough tokens available
		if new_tokens >= tokens_requested then
			-- Consume tokens
			new_tokens = new_tokens - tokens_requested
			
			-- Update bucket state
			redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
			redis.call('EXPIRE', key, 3600)
			
			return {1, new_tokens, 0} -- allowed, remaining_tokens, wait_time
		else
			-- Calculate wait time for enough tokens
			local tokens_needed = tokens_requested - new_tokens
			local wait_time = tokens_needed / refill_rate
			
			-- Update last_refill time but don't consume tokens
			redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
			redis.call('EXPIRE', key, 3600)
			
			return {0, new_tokens, wait_time} -- not allowed, remaining_tokens, wait_time
		end
	`

	result, err := tbrl.config.RedisClient.Eval(tbrl.ctx, script, []string{
		tbrl.config.RedisKeyPrefix + clientKey,
	}, tokensRequested, tbrl.config.Burst, float64(tbrl.config.Rate), now.Unix()).Result()

	if err != nil {
		atomic.AddInt64(&tbrl.stats.RedisErrors, 1)
		return false, 0, 0, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return false, 0, 0, fmt.Errorf("unexpected Redis result format")
	}

	allowed := resultSlice[0].(int64) == 1
	remainingTokens, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[1]), 64)
	waitTimeSeconds, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[2]), 64)
	waitTime := time.Duration(waitTimeSeconds * float64(time.Second))

	return allowed, remainingTokens, waitTime, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage
func (tbrl *TokenBucketRateLimiter) checkRateLimitFallback(clientKey string, tokensRequested int) (bool, float64, time.Duration) {
	now := time.Now()

	tbrl.clientsMux.Lock()
	entry, exists := tbrl.clients[clientKey]
	if !exists {
		entry = &tokenBucketEntry{
			limiter:    rate.NewLimiter(tbrl.config.Rate, tbrl.config.Burst),
			lastAccess: now,
		}
		tbrl.clients[clientKey] = entry
	}
	tbrl.clientsMux.Unlock()

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.lastAccess = now

	// Check if tokens are available
	if entry.limiter.AllowN(now, tokensRequested) {
		// Estimate remaining tokens
		remaining := EstimateRemainingFromReservation(entry.limiter, tbrl.config.Burst)
		return true, float64(remaining), 0
	}

	// Calculate wait time
	reservation := entry.limiter.ReserveN(now, tokensRequested)
	waitTime := reservation.Delay()
	reservation.Cancel()

	// Estimate current tokens (rough approximation)
	remaining := EstimateRemainingFromReservation(entry.limiter, tbrl.config.Burst)

	return false, float64(remaining), waitTime
}

// createRequestInfo creates request information
func (tbrl *TokenBucketRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, tokensAvailable float64, tokensUsed int, waitTime time.Duration) *TokenBucketRequestInfo {
	return &TokenBucketRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: time.Now(),
			Allowed:   allowed,
		},
		ClientKey:       clientKey,
		TokensAvailable: tokensAvailable,
		TokensUsed:      tokensUsed,
		WaitTime:        waitTime,
		BucketCapacity:  tbrl.config.Burst,
		RefillRate:      float64(tbrl.config.Rate),
	}
}

// setHeaders sets rate limit headers
func (tbrl *TokenBucketRateLimiter) setHeaders(c *gin.Context, tokensRemaining float64, retryAfter time.Duration) {
	if !tbrl.config.EnableHeaders {
		return
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(tbrl.config.Burst))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(int(math.Floor(tokensRemaining))))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Duration(float64(time.Second)/float64(tbrl.config.Rate))).Format(time.RFC3339))
	c.Header("X-RateLimit-Refill-Rate", fmt.Sprintf("%.2f/sec", float64(tbrl.config.Rate)))
	c.Header("X-RateLimit-Algorithm", tbrl.Algorithm().String())

	if retryAfter > 0 {
		SetRetryAfterHeader(c, retryAfter)
	}

	if tbrl.redisMode {
		c.Header("X-RateLimit-Mode", "redis")
	} else {
		c.Header("X-RateLimit-Mode", "memory")
	}
}

// logEvent logs rate limiting events
func (tbrl *TokenBucketRateLimiter) logEvent(info *TokenBucketRequestInfo) {
	if !tbrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	mode := "MEMORY"
	if tbrl.redisMode {
		mode = "REDIS"
	}

	log.Printf("[TOKEN_BUCKET_%s] %s - Client: %s, Method: %s, Path: %s, Tokens: %.2f/%d, Used: %d, Wait: %v",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.TokensAvailable, info.BucketCapacity, info.TokensUsed, info.WaitTime)
}

// handleLimitExceeded handles when rate limit is exceeded
func (tbrl *TokenBucketRateLimiter) handleLimitExceeded(c *gin.Context, info *TokenBucketRequestInfo) {
	// Set Retry-After header if wait time is reasonable
	if info.WaitTime > 0 && info.WaitTime <= tbrl.config.MaxWaitTime {
		SetRetryAfterHeader(c, info.WaitTime)
	}

	// Call custom handler if provided
	if tbrl.config.OnLimitExceeded != nil {
		tbrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if tbrl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, tbrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	response := gin.H{
		"error":           tbrl.config.ErrorMessage,
		"message":         "Token bucket exhausted",
		"client":          info.ClientKey,
		"tokens_used":     info.TokensUsed,
		"bucket_capacity": info.BucketCapacity,
		"refill_rate":     fmt.Sprintf("%.2f tokens/sec", info.RefillRate),
		"algorithm":       tbrl.Algorithm().String(),
		"timestamp":       info.Timestamp.Format(time.RFC3339),
	}

	if info.WaitTime > 0 {
		response["retry_after_seconds"] = info.WaitTime.Seconds()
		response["estimated_wait"] = info.WaitTime.String()
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// handleWaitingRequest handles requests that need to wait for tokens
func (tbrl *TokenBucketRateLimiter) handleWaitingRequest(c *gin.Context, info *TokenBucketRequestInfo) bool {
	if !tbrl.config.AllowWaiting || info.WaitTime <= 0 || info.WaitTime > tbrl.config.MaxWaitTime {
		return false
	}

	atomic.AddInt64(&tbrl.stats.WaitingRequests, 1)

	// Wait for tokens to be available
	select {
	case <-time.After(info.WaitTime):
		// Try again after waiting
		return true
	case <-tbrl.ctx.Done():
		return false
	}
}

// updateClientStats updates statistics for a specific client
func (tbrl *TokenBucketRateLimiter) updateClientStats(clientKey string, allowed bool) {
	tbrl.stats.mutex.Lock()
	defer tbrl.stats.mutex.Unlock()

	clientStats, exists := tbrl.stats.ClientStats[clientKey]
	if !exists {
		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		tbrl.stats.ClientStats[clientKey] = clientStats
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

// Middleware returns the token bucket rate limiting middleware
func (tbrl *TokenBucketRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract a client key
		clientKey := tbrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		// Default: 1 token per request:
		tokensRequested := 1

		// Allow custom token consumption via header
		if tokenHeader := c.GetHeader("X-Tokens-Requested"); tokenHeader != "" {
			if tokens, err := strconv.Atoi(tokenHeader); err == nil && tokens > 0 && tokens <= 10 {
				tokensRequested = tokens
			}
		}

		var allowed bool
		var tokensAvailable float64
		var waitTime time.Duration
		var err error

		// Check rate limit
		if tbrl.redisMode {
			allowed, tokensAvailable, waitTime, err = tbrl.checkRateLimitRedis(clientKey, tokensRequested)
			if err != nil && tbrl.config.EnableFallback {
				log.Printf("[TOKEN_BUCKET] Redis error, falling back to memory: %v", err)
				tbrl.redisMode = false
				tbrl.stats.FallbackMode = true
				allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
			}
		} else {
			allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
		}

		// Handle waiting requests if enabled
		if !allowed && tbrl.config.AllowWaiting {
			if tbrl.handleWaitingRequest(c, &TokenBucketRequestInfo{WaitTime: waitTime}) {
				// Retry after waiting
				if tbrl.redisMode {
					allowed, tokensAvailable, waitTime, _ = tbrl.checkRateLimitRedis(clientKey, tokensRequested)
				} else {
					allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
				}
			}
		}

		// Update global statistics
		atomic.AddInt64(&tbrl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&tbrl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&tbrl.stats.BlockedRequests, 1)
		}

		// Update client statistics
		tbrl.updateClientStats(clientKey, allowed)

		// Create request info
		tokensUsed := 0
		if allowed {
			tokensUsed = tokensRequested
		}
		info := tbrl.createRequestInfo(c, clientKey, allowed, tokensAvailable, tokensUsed, waitTime)

		// Set headers
		tbrl.setHeaders(c, tokensAvailable, waitTime)

		// Log event
		tbrl.logEvent(info)

		// Call request processed handler if provided
		if tbrl.config.OnRequestProcessed != nil {
			tbrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			tbrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns rate limiting statistics
func (tbrl *TokenBucketRateLimiter) GetStats() Stats {
	// Update live counters
	tbrl.stats.TotalRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.TotalRequests)
	tbrl.stats.AllowedRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.AllowedRequests)
	tbrl.stats.BlockedRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.BlockedRequests)
	tbrl.stats.ActiveClients = int64(len(tbrl.clients))
	tbrl.stats.RedisMode = tbrl.redisMode
	return tbrl.stats
}

// GetClientStats returns statistics for a specific client
func (tbrl *TokenBucketRateLimiter) GetClientStats(clientKey string) ClientStats {
	tbrl.stats.mutex.RLock()
	defer tbrl.stats.mutex.RUnlock()

	if stats, exists := tbrl.stats.ClientStats[clientKey]; exists {
		return *stats
	}
	return ClientStats{ClientKey: clientKey}
}

// ResetClient resets rate limiting for a specific client
func (tbrl *TokenBucketRateLimiter) ResetClient(clientKey string) {
	if tbrl.redisMode {
		tbrl.config.RedisClient.Del(tbrl.ctx, tbrl.config.RedisKeyPrefix+clientKey)
	} else {
		tbrl.clientsMux.Lock()
		delete(tbrl.clients, clientKey)
		tbrl.clientsMux.Unlock()
	}

	// Reset client stats
	tbrl.stats.mutex.Lock()
	delete(tbrl.stats.ClientStats, clientKey)
	tbrl.stats.mutex.Unlock()
}

// ListActiveClients returns a list of currently active clients
func (tbrl *TokenBucketRateLimiter) ListActiveClients() []string {
	tbrl.stats.mutex.RLock()
	defer tbrl.stats.mutex.RUnlock()

	clients := make([]string, 0, len(tbrl.stats.ClientStats))
	for clientKey, stats := range tbrl.stats.ClientStats {
		if stats.IsActive {
			clients = append(clients, clientKey)
		}
	}
	return clients
}

// GetClientCount returns the number of active clients
func (tbrl *TokenBucketRateLimiter) GetClientCount() int {
	if tbrl.redisMode {
		// For Redis mode, this is an approximation
		return len(tbrl.ListActiveClients())
	}

	tbrl.clientsMux.RLock()
	defer tbrl.clientsMux.RUnlock()
	return len(tbrl.clients)
}

// ResetStats resets all statistics
func (tbrl *TokenBucketRateLimiter) ResetStats() {
	atomic.StoreInt64(&tbrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&tbrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&tbrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&tbrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&tbrl.stats.WaitingRequests, 0)
	tbrl.stats.BaseStats.StartTime = time.Now()

	tbrl.stats.mutex.Lock()
	tbrl.stats.ClientStats = make(map[string]*ClientStats)
	tbrl.stats.mutex.Unlock()
}

// Stop gracefully stops the rate limiter
func (tbrl *TokenBucketRateLimiter) Stop() {
	close(tbrl.stopChan)
	tbrl.cancel()
}

// Type returns the type of rate limiter
func (tbrl *TokenBucketRateLimiter) Type() RateLimiterType {
	return TokenBucketType
}

// Algorithm returns the algorithm used
func (tbrl *TokenBucketRateLimiter) Algorithm() Algorithm {
	return TokenBucketAlg
}
