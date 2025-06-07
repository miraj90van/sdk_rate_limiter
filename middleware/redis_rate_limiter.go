package middleware

import (
	"context"
	"fmt"
	"github.com/miraj90van/sdk_rate_limiter/component"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var _ RateLimiter = (*RedisRateLimiter)(nil)

// Lua script for sliding window rate limiting
const slidingWindowLuaScript = `
	local key = KEYS[1]
	local window = tonumber(ARGV[1])
	local limit = tonumber(ARGV[2])
	local current_time = tonumber(ARGV[3])
	
	-- Remove expired entries
	redis.call('ZREMRANGEBYSCORE', key, '-inf', current_time - window * 1000)
	
	-- Count current entries
	local current_count = redis.call('ZCARD', key)
	
	if current_count < limit then
		-- Add current request
		redis.call('ZADD', key, current_time, current_time)
		redis.call('EXPIRE', key, window + 1)
		return {1, limit - current_count - 1}
	else
		return {0, 0}
	end
`

// RedisRateLimiterConfig extends BasicRateLimiterConfig with Redis support
type RedisRateLimiterConfig struct {
	// Basic rate limiting config
	Rate               rate.Limit  // Requests per second
	Burst              int         // Burst capacity
	EnableHeaders      bool        // Include rate limit headers
	EnableLogging      bool        // Enable logging
	ErrorMessage       string      // Custom error message
	ErrorResponse      interface{} // Custom error response
	OnLimitExceeded    func(*gin.Context, *RedisRequestInfo)
	OnRequestProcessed func(*gin.Context, *RedisRequestInfo, bool)

	// Redis-specific config
	RedisConfig    *component.RedisConfig // Redis configuration
	WindowDuration time.Duration          // Sliding window duration (default: 1 minute)
	KeyExtractor   KeyExtractor           // Function to extract client key
	Scope          string                 // Rate limiting scope (global, ip, user, etc.)
}

// RedisRequestInfo contains request information for Redis rate limiter
type RedisRequestInfo struct {
	BaseRequestInfo
	ClientKey    string `json:"client_key"`
	Scope        string `json:"scope"`
	WindowStart  int64  `json:"window_start"`
	WindowEnd    int64  `json:"window_end"`
	RedisEnabled bool   `json:"redis_enabled"`
}

// RedisRateLimiter implements distributed rate limiting using Redis
type RedisRateLimiter struct {
	config          *RedisRateLimiterConfig
	redisClient     component.RedisClient
	fallbackLimiter *rate.Limiter // Fallback to in-memory when Redis is unavailable
	stats           *RedisStats
	ctx             context.Context
	cancel          context.CancelFunc
	healthCheck     chan bool
	isRedisHealthy  bool
	mu              sync.RWMutex
}

// RedisStats extends BaseStats with Redis-specific metrics
type RedisStats struct {
	*BaseStats
	RedisOperations    int64     `json:"redis_operations"`
	RedisErrors        int64     `json:"redis_errors"`
	FallbackOperations int64     `json:"fallback_operations"`
	HealthCheckFails   int64     `json:"health_check_fails"`
	LastRedisError     string    `json:"last_redis_error"`
	LastHealthCheck    time.Time `json:"last_health_check"`
	IsRedisHealthy     bool      `json:"is_redis_healthy"`
}

// NewRedisRateLimiter creates a new Redis-backed rate limiter
func NewRedisRateLimiter(config *RedisRateLimiterConfig, redisClient component.RedisClient) *RedisRateLimiter {
	if config == nil {
		config = DefaultRedisRateLimiterConfig()
	}

	if config.RedisConfig == nil {
		config.RedisConfig = component.DefaultRedisConfig()
	}

	if err := config.RedisConfig.Validate(); err != nil {
		log.Printf("Redis config validation failed: %v", err)
	}

	if config.WindowDuration <= 0 {
		config.WindowDuration = time.Minute
	}

	if config.KeyExtractor == nil {
		config.KeyExtractor = IPKeyExtractor
	}

	if config.Scope == "" {
		config.Scope = "default"
	}

	if config.ErrorMessage == "" {
		config.ErrorMessage = fmt.Sprintf("Rate limit exceeded for scope: %s", config.Scope)
	}

	ctx, cancel := context.WithCancel(context.Background())

	rrl := &RedisRateLimiter{
		config:          config,
		redisClient:     redisClient,
		fallbackLimiter: rate.NewLimiter(config.Rate, config.Burst),
		ctx:             ctx,
		cancel:          cancel,
		healthCheck:     make(chan bool, 1),
		isRedisHealthy:  false,
		stats: &RedisStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: AdvancedType, // Redis limiter is considered advanced
			},
			LastHealthCheck: time.Now(),
		},
	}

	// Start health check if Redis is enabled
	if config.RedisConfig.Enabled && redisClient != nil {
		go rrl.healthCheckLoop()
		go rrl.initialHealthCheck()
	}

	return rrl
}

// DefaultRedisRateLimiterConfig returns default configuration
func DefaultRedisRateLimiterConfig() *RedisRateLimiterConfig {
	return &RedisRateLimiterConfig{
		Rate:           rate.Limit(100), // 100 req/sec
		Burst:          10,              // 10 burst
		EnableHeaders:  true,
		EnableLogging:  false,
		WindowDuration: time.Minute,
		KeyExtractor:   IPKeyExtractor,
		Scope:          "ip",
		RedisConfig:    component.DefaultRedisConfig(),
	}
}

// initialHealthCheck performs initial Redis health check
func (rrl *RedisRateLimiter) initialHealthCheck() {
	if rrl.redisClient == nil || !rrl.config.RedisConfig.Enabled {
		return
	}

	ctx, cancel := context.WithTimeout(rrl.ctx, 5*time.Second)
	defer cancel()

	if err := rrl.redisClient.Ping(ctx); err != nil {
		rrl.mu.Lock()
		rrl.isRedisHealthy = false
		rrl.stats.LastRedisError = err.Error()
		atomic.AddInt64(&rrl.stats.HealthCheckFails, 1)
		rrl.mu.Unlock()

		if rrl.config.EnableLogging {
			log.Printf("[REDIS_RATE_LIMITER] Initial health check failed: %v", err)
		}
	} else {
		rrl.mu.Lock()
		rrl.isRedisHealthy = true
		rrl.stats.LastRedisError = ""
		rrl.mu.Unlock()

		if rrl.config.EnableLogging {
			log.Printf("[REDIS_RATE_LIMITER] Redis connection healthy")
		}
	}

	rrl.stats.LastHealthCheck = time.Now()
}

// healthCheckLoop periodically checks Redis health
func (rrl *RedisRateLimiter) healthCheckLoop() {
	ticker := time.NewTicker(rrl.config.RedisConfig.HealthCheckDelay)
	defer ticker.Stop()

	for {
		select {
		case <-rrl.ctx.Done():
			return
		case <-ticker.C:
			rrl.performHealthCheck()
		case <-rrl.healthCheck:
			rrl.performHealthCheck()
		}
	}
}

// performHealthCheck checks Redis connectivity
func (rrl *RedisRateLimiter) performHealthCheck() {
	if rrl.redisClient == nil || !rrl.config.RedisConfig.Enabled {
		return
	}

	ctx, cancel := context.WithTimeout(rrl.ctx, 5*time.Second)
	defer cancel()

	err := rrl.redisClient.Ping(ctx)

	rrl.mu.Lock()
	defer rrl.mu.Unlock()

	wasHealthy := rrl.isRedisHealthy
	rrl.isRedisHealthy = (err == nil)
	rrl.stats.LastHealthCheck = time.Now()

	if err != nil {
		rrl.stats.LastRedisError = err.Error()
		atomic.AddInt64(&rrl.stats.HealthCheckFails, 1)

		if wasHealthy && rrl.config.EnableLogging {
			log.Printf("[REDIS_RATE_LIMITER] Redis connection lost: %v", err)
		}
	} else {
		rrl.stats.LastRedisError = ""

		if !wasHealthy && rrl.config.EnableLogging {
			log.Printf("[REDIS_RATE_LIMITER] Redis connection restored")
		}
	}
}

// checkRateLimit checks rate limit using Redis or fallback
func (rrl *RedisRateLimiter) checkRateLimit(clientKey string) (allowed bool, remaining int, err error) {
	// Use Redis if enabled and healthy
	if rrl.config.RedisConfig.Enabled && rrl.isRedisHealthy && rrl.redisClient != nil {
		return rrl.checkRateLimitRedis(clientKey)
	}

	// Fallback to in-memory rate limiter
	return rrl.checkRateLimitFallback()
}

// checkRateLimitRedis performs rate limiting using Redis
func (rrl *RedisRateLimiter) checkRateLimitRedis(clientKey string) (allowed bool, remaining int, err error) {
	atomic.AddInt64(&rrl.stats.RedisOperations, 1)

	redisKey := fmt.Sprintf("%s:%s:%s", rrl.config.RedisConfig.KeyPrefix, rrl.config.Scope, clientKey)
	windowSeconds := int64(rrl.config.WindowDuration.Seconds())
	limit := int64(float64(rrl.config.Rate) * rrl.config.WindowDuration.Seconds())
	currentTime := time.Now().UnixMilli()

	ctx, cancel := context.WithTimeout(rrl.ctx, time.Second)
	defer cancel()

	// Execute Lua script with retries
	var result interface{}
	for i := 0; i < rrl.config.RedisConfig.MaxRetries; i++ {
		result, err = rrl.redisClient.Eval(
			ctx,
			slidingWindowLuaScript,
			[]string{redisKey},
			windowSeconds,
			limit,
			currentTime,
		)

		if err == nil {
			break
		}

		if i < rrl.config.RedisConfig.MaxRetries-1 {
			time.Sleep(rrl.config.RedisConfig.RetryDelay)
		}
	}

	if err != nil {
		atomic.AddInt64(&rrl.stats.RedisErrors, 1)
		rrl.mu.Lock()
		rrl.stats.LastRedisError = err.Error()
		rrl.mu.Unlock()

		// Trigger health check
		select {
		case rrl.healthCheck <- true:
		default:
		}

		// Fallback to in-memory if configured
		if rrl.config.RedisConfig.FallbackToMemory {
			return rrl.checkRateLimitFallback()
		}

		return false, 0, err
	}

	// Parse Lua script result
	if resultSlice, ok := result.([]interface{}); ok && len(resultSlice) == 2 {
		allowedInt, _ := resultSlice[0].(int64)
		remainingInt, _ := resultSlice[1].(int64)

		return allowedInt == 1, int(remainingInt), nil
	}

	return false, 0, fmt.Errorf("unexpected Redis response format")
}

// checkRateLimitFallback performs rate limiting using in-memory fallback
func (rrl *RedisRateLimiter) checkRateLimitFallback() (allowed bool, remaining int, err error) {
	atomic.AddInt64(&rrl.stats.FallbackOperations, 1)

	allowed = rrl.fallbackLimiter.Allow()
	remaining = rrl.config.Burst
	if !allowed {
		remaining = 0
	}

	return allowed, remaining, nil
}

// createRequestInfo creates request information
func (rrl *RedisRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool) *RedisRequestInfo {
	now := time.Now()
	windowStart := now.Add(-rrl.config.WindowDuration).UnixMilli()

	return &RedisRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: now,
			Allowed:   allowed,
		},
		ClientKey:    clientKey,
		Scope:        rrl.config.Scope,
		WindowStart:  windowStart,
		WindowEnd:    now.UnixMilli(),
		RedisEnabled: rrl.config.RedisConfig.Enabled && rrl.isRedisHealthy,
	}
}

// setHeaders sets rate limit headers
func (rrl *RedisRateLimiter) setHeaders(c *gin.Context, remaining int) {
	if !rrl.config.EnableHeaders {
		return
	}

	limit := int64(float64(rrl.config.Rate) * 60) // per minute
	resetTime := time.Now().Add(rrl.config.WindowDuration)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", resetTime.Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", rrl.config.Scope)
	c.Header("X-RateLimit-Backend", func() string {
		if rrl.config.RedisConfig.Enabled && rrl.isRedisHealthy {
			return "redis"
		}
		return "memory"
	}())
}

// logEvent logs rate limiting events
func (rrl *RedisRateLimiter) logEvent(info *RedisRequestInfo) {
	if !rrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	backend := "memory"
	if info.RedisEnabled {
		backend = "redis"
	}

	log.Printf("[REDIS_RATE_LIMITER] %s - Scope: %s, Key: %s, Method: %s, Path: %s, Backend: %s",
		status, info.Scope, info.ClientKey, info.Method, info.Path, backend)
}

// handleLimitExceeded handles rate limit exceeded cases
func (rrl *RedisRateLimiter) handleLimitExceeded(c *gin.Context, info *RedisRequestInfo) {
	// Set Retry-After header
	c.Header("Retry-After", strconv.Itoa(int(rrl.config.WindowDuration.Seconds())))

	// Call custom handler if provided
	if rrl.config.OnLimitExceeded != nil {
		rrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if rrl.config.ErrorResponse != nil {
		c.JSON(429, rrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	errorResponse := CreateStandardErrorResponse(
		rrl.config.ErrorMessage,
		rrl.config.Scope,
		info,
	)
	errorResponse["client_key"] = info.ClientKey
	errorResponse["backend"] = func() string {
		if info.RedisEnabled {
			return "redis"
		}
		return "memory"
	}()

	c.JSON(429, errorResponse)
	c.Abort()
}

// Middleware returns the Redis rate limiting middleware
func (rrl *RedisRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract client key
		clientKey := rrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = "anonymous"
		}

		// Check rate limit
		allowed, remaining, err := rrl.checkRateLimit(clientKey)

		// Update statistics
		atomic.AddInt64(&rrl.stats.BaseStats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&rrl.stats.BaseStats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&rrl.stats.BaseStats.BlockedRequests, 1)
		}

		// Handle Redis errors
		if err != nil && rrl.config.EnableLogging {
			log.Printf("[REDIS_RATE_LIMITER] Error checking rate limit: %v", err)
		}

		// Create request info
		info := rrl.createRequestInfo(c, clientKey, allowed)

		// Set headers
		rrl.setHeaders(c, remaining)

		// Log event
		rrl.logEvent(info)

		// Call request handler if provided
		if rrl.config.OnRequestProcessed != nil {
			rrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			rrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns rate limiter statistics
func (rrl *RedisRateLimiter) GetStats() Stats {
	rrl.mu.RLock()
	defer rrl.mu.RUnlock()

	// Update live counters
	rrl.stats.BaseStats.TotalRequests = atomic.LoadInt64(&rrl.stats.BaseStats.TotalRequests)
	rrl.stats.BaseStats.AllowedRequests = atomic.LoadInt64(&rrl.stats.BaseStats.AllowedRequests)
	rrl.stats.BaseStats.BlockedRequests = atomic.LoadInt64(&rrl.stats.BaseStats.BlockedRequests)
	rrl.stats.IsRedisHealthy = rrl.isRedisHealthy

	return rrl.stats
}

// ResetStats resets statistics
func (rrl *RedisRateLimiter) ResetStats() {
	atomic.StoreInt64(&rrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&rrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&rrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&rrl.stats.RedisOperations, 0)
	atomic.StoreInt64(&rrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&rrl.stats.FallbackOperations, 0)
	atomic.StoreInt64(&rrl.stats.HealthCheckFails, 0)

	rrl.stats.BaseStats.StartTime = time.Now()
	rrl.stats.LastRedisError = ""
}

// Stop gracefully stops the rate limiter
func (rrl *RedisRateLimiter) Stop() {
	rrl.cancel()
}

// Type returns the rate limiter type
func (rrl *RedisRateLimiter) Type() RateLimiterType {
	return AdvancedType
}

// Algorithm returns the algorithm used
func (rrl *RedisRateLimiter) Algorithm() Algorithm {
	return SlidingWindowAlg
}
