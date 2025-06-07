package middleware

import (
	"context"
	"fmt"
	"github.com/miraj90van/sdk_rate_limiter/component"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var _ RateLimiter = (*EnhancedBasicRateLimiter)(nil)

// Lua script for global rate limiting using Redis
const globalRateLimitLuaScript = `
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
		redis.call('ZADD', key, current_time, current_time .. ':' .. math.random())
		redis.call('EXPIRE', key, window + 1)
		return {1, limit - current_count - 1}
	else
		return {0, 0}
	end
	`

// EnhancedBasicRateLimiterConfig extends BasicRateLimiterConfig with Redis support
type EnhancedBasicRateLimiterConfig struct {
	// Basic rate limiting config (same as BasicRateLimiterConfig)
	Rate               rate.Limit  // Global requests per second (shared by ALL clients)
	Burst              int         // Global burst capacity (shared by ALL clients)
	EnableHeaders      bool        // Include rate limit headers
	EnableLogging      bool        // Enable logging for monitoring
	ErrorMessage       string      // Custom error message
	ErrorResponse      interface{} // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *EnhancedBasicRequestInfo)
	OnRequestProcessed func(*gin.Context, *EnhancedBasicRequestInfo, bool)

	// Redis-specific config for distributed rate limiting
	RedisConfig    *component.RedisConfig // Redis configuration
	WindowDuration time.Duration          // Sliding window duration (default: 1 minute)
	GlobalKey      string                 // Global key for distributed rate limiting
}

// EnhancedBasicRequestInfo contains info about request with Redis support
type EnhancedBasicRequestInfo struct {
	BaseRequestInfo
	GlobalKey    string `json:"global_key"`
	WindowStart  int64  `json:"window_start"`
	WindowEnd    int64  `json:"window_end"`
	RedisEnabled bool   `json:"redis_enabled"`
	Backend      string `json:"backend"` // "redis" or "memory"
}

// EnhancedBasicRateLimiter manages GLOBAL rate limiting with optional Redis support
type EnhancedBasicRateLimiter struct {
	config          *EnhancedBasicRateLimiterConfig
	redisClient     component.RedisClient
	fallbackLimiter *rate.Limiter // Fallback to in-memory when Redis is unavailable
	stats           *EnhancedBasicStats
	ctx             context.Context
	cancel          context.CancelFunc
	isRedisHealthy  bool
	lastHealthCheck time.Time
}

// EnhancedBasicStats extends BaseStats with Redis-specific metrics
type EnhancedBasicStats struct {
	*BaseStats
	RedisOperations    int64  `json:"redis_operations"`
	RedisErrors        int64  `json:"redis_errors"`
	FallbackOperations int64  `json:"fallback_operations"`
	HealthCheckFails   int64  `json:"health_check_fails"`
	LastRedisError     string `json:"last_redis_error"`
	IsRedisHealthy     bool   `json:"is_redis_healthy"`
}

// NewEnhancedBasicRateLimiter creates a new enhanced global rate limiter with optional Redis
func NewEnhancedBasicRateLimiter(config *EnhancedBasicRateLimiterConfig, redisClient component.RedisClient) *EnhancedBasicRateLimiter {
	if config == nil {
		config = DefaultEnhancedBasicConfig()
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

	if config.GlobalKey == "" {
		config.GlobalKey = "global"
	}

	if config.ErrorMessage == "" {
		config.ErrorMessage = "Global rate limit exceeded"
	}

	ctx, cancel := context.WithCancel(context.Background())

	ebrl := &EnhancedBasicRateLimiter{
		config:          config,
		redisClient:     redisClient,
		fallbackLimiter: rate.NewLimiter(config.Rate, config.Burst),
		ctx:             ctx,
		cancel:          cancel,
		isRedisHealthy:  false,
		lastHealthCheck: time.Now(),
		stats: &EnhancedBasicStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: BasicType,
			},
		},
	}

	// Perform initial health check if Redis is enabled
	if config.RedisConfig.Enabled && redisClient != nil {
		go ebrl.performInitialHealthCheck()
		go ebrl.startHealthCheckLoop()
	}

	return ebrl
}

// DefaultEnhancedBasicConfig returns default configuration
func DefaultEnhancedBasicConfig() *EnhancedBasicRateLimiterConfig {
	return &EnhancedBasicRateLimiterConfig{
		Rate:           rate.Limit(1000), // 1000 req/sec GLOBALLY
		Burst:          100,              // 100 burst GLOBALLY
		EnableHeaders:  true,
		EnableLogging:  false,
		ErrorMessage:   "Global rate limit exceeded",
		WindowDuration: time.Minute,
		GlobalKey:      "global",
		RedisConfig:    component.DefaultRedisConfig(),
	}
}

// performInitialHealthCheck performs initial Redis health check
func (ebrl *EnhancedBasicRateLimiter) performInitialHealthCheck() {
	if ebrl.redisClient == nil || !ebrl.config.RedisConfig.Enabled {
		return
	}

	ctx, cancel := context.WithTimeout(ebrl.ctx, 5*time.Second)
	defer cancel()

	if err := ebrl.redisClient.Ping(ctx); err != nil {
		ebrl.isRedisHealthy = false
		ebrl.stats.LastRedisError = err.Error()
		atomic.AddInt64(&ebrl.stats.HealthCheckFails, 1)

		if ebrl.config.EnableLogging {
			log.Printf("[ENHANCED_BASIC_RATE_LIMITER] Initial Redis health check failed: %v", err)
		}
	} else {
		ebrl.isRedisHealthy = true
		ebrl.stats.LastRedisError = ""

		if ebrl.config.EnableLogging {
			log.Printf("[ENHANCED_BASIC_RATE_LIMITER] Redis connection healthy")
		}
	}

	ebrl.lastHealthCheck = time.Now()
	ebrl.stats.IsRedisHealthy = ebrl.isRedisHealthy
}

// startHealthCheckLoop starts periodic health checks
func (ebrl *EnhancedBasicRateLimiter) startHealthCheckLoop() {
	ticker := time.NewTicker(ebrl.config.RedisConfig.HealthCheckDelay)
	defer ticker.Stop()

	for {
		select {
		case <-ebrl.ctx.Done():
			return
		case <-ticker.C:
			ebrl.performHealthCheck()
		}
	}
}

// performHealthCheck checks Redis connectivity
func (ebrl *EnhancedBasicRateLimiter) performHealthCheck() {
	if ebrl.redisClient == nil || !ebrl.config.RedisConfig.Enabled {
		return
	}

	ctx, cancel := context.WithTimeout(ebrl.ctx, 5*time.Second)
	defer cancel()

	err := ebrl.redisClient.Ping(ctx)
	wasHealthy := ebrl.isRedisHealthy
	ebrl.isRedisHealthy = (err == nil)
	ebrl.lastHealthCheck = time.Now()
	ebrl.stats.IsRedisHealthy = ebrl.isRedisHealthy

	if err != nil {
		ebrl.stats.LastRedisError = err.Error()
		atomic.AddInt64(&ebrl.stats.HealthCheckFails, 1)

		if wasHealthy && ebrl.config.EnableLogging {
			log.Printf("[ENHANCED_BASIC_RATE_LIMITER] Redis connection lost: %v", err)
		}
	} else {
		ebrl.stats.LastRedisError = ""

		if !wasHealthy && ebrl.config.EnableLogging {
			log.Printf("[ENHANCED_BASIC_RATE_LIMITER] Redis connection restored")
		}
	}
}

// checkGlobalRateLimit checks global rate limit using Redis or fallback
func (ebrl *EnhancedBasicRateLimiter) checkGlobalRateLimit() (allowed bool, remaining int, backend string, err error) {
	// Use Redis if enabled and healthy
	if ebrl.config.RedisConfig.Enabled && ebrl.isRedisHealthy && ebrl.redisClient != nil {
		allowed, remaining, err = ebrl.checkRateLimitRedis()
		backend = "redis"
		if err != nil && ebrl.config.RedisConfig.FallbackToMemory {
			// Fallback to memory on Redis error
			allowed, remaining, _ = ebrl.checkRateLimitFallback()
			backend = "memory"
		}
		return
	}

	// Use in-memory fallback
	allowed, remaining, err = ebrl.checkRateLimitFallback()
	backend = "memory"
	return
}

// checkRateLimitRedis performs global rate limiting using Redis
func (ebrl *EnhancedBasicRateLimiter) checkRateLimitRedis() (allowed bool, remaining int, err error) {
	atomic.AddInt64(&ebrl.stats.RedisOperations, 1)

	redisKey := fmt.Sprintf("%s:global:%s", ebrl.config.RedisConfig.KeyPrefix, ebrl.config.GlobalKey)
	windowSeconds := int64(ebrl.config.WindowDuration.Seconds())
	limit := int64(float64(ebrl.config.Rate) * ebrl.config.WindowDuration.Seconds())
	currentTime := time.Now().UnixMilli()

	ctx, cancel := context.WithTimeout(ebrl.ctx, time.Second)
	defer cancel()

	// Execute Lua script with retries
	var result interface{}
	for i := 0; i < ebrl.config.RedisConfig.MaxRetries; i++ {
		result, err = ebrl.redisClient.Eval(
			ctx,
			globalRateLimitLuaScript,
			[]string{redisKey},
			windowSeconds,
			limit,
			currentTime,
		)

		if err == nil {
			break
		}

		if i < ebrl.config.RedisConfig.MaxRetries-1 {
			time.Sleep(ebrl.config.RedisConfig.RetryDelay)
		}
	}

	if err != nil {
		atomic.AddInt64(&ebrl.stats.RedisErrors, 1)
		ebrl.stats.LastRedisError = err.Error()
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

// checkRateLimitFallback performs global rate limiting using in-memory fallback
func (ebrl *EnhancedBasicRateLimiter) checkRateLimitFallback() (allowed bool, remaining int, err error) {
	atomic.AddInt64(&ebrl.stats.FallbackOperations, 1)

	allowed = ebrl.fallbackLimiter.Allow()
	remaining = ebrl.config.Burst
	if !allowed {
		remaining = 0
	}

	return allowed, remaining, nil
}

// createRequestInfo creates request information
func (ebrl *EnhancedBasicRateLimiter) createRequestInfo(c *gin.Context, allowed bool, backend string) *EnhancedBasicRequestInfo {
	now := time.Now()
	windowStart := now.Add(-ebrl.config.WindowDuration).UnixMilli()

	return &EnhancedBasicRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: now,
			Allowed:   allowed,
		},
		GlobalKey:    ebrl.config.GlobalKey,
		WindowStart:  windowStart,
		WindowEnd:    now.UnixMilli(),
		RedisEnabled: ebrl.config.RedisConfig.Enabled && ebrl.isRedisHealthy,
		Backend:      backend,
	}
}

// setHeaders sets rate limit headers
func (ebrl *EnhancedBasicRateLimiter) setHeaders(c *gin.Context, remaining int, backend string) {
	if !ebrl.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(ebrl.config.Rate) * 60)
	resetTime := time.Now().Add(ebrl.config.WindowDuration)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", resetTime.Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", "global")
	c.Header("X-RateLimit-Backend", backend)
	c.Header("X-RateLimit-Window", ebrl.config.WindowDuration.String())
}

// logEvent logs rate limiting events
func (ebrl *EnhancedBasicRateLimiter) logEvent(info *EnhancedBasicRequestInfo) {
	if !ebrl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	log.Printf("[ENHANCED_BASIC_RATE_LIMITER] %s - Method: %s, Path: %s, IP: %s, Backend: %s",
		status, info.Method, info.Path, info.IP, info.Backend)
}

// handleLimitExceeded handles when global rate limit is exceeded
func (ebrl *EnhancedBasicRateLimiter) handleLimitExceeded(c *gin.Context, info *EnhancedBasicRequestInfo) {
	// Set Retry-After header
	c.Header("Retry-After", strconv.Itoa(int(ebrl.config.WindowDuration.Seconds())))

	// Call custom handler if provided
	if ebrl.config.OnLimitExceeded != nil {
		ebrl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if ebrl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, ebrl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	errorResponse := gin.H{
		"error":     ebrl.config.ErrorMessage,
		"message":   "Server is receiving too many requests globally",
		"scope":     "global",
		"backend":   info.Backend,
		"timestamp": info.Timestamp.Format(time.RFC3339),
		"window":    ebrl.config.WindowDuration.String(),
	}

	c.JSON(http.StatusTooManyRequests, errorResponse)
	c.Abort()
}

// Middleware returns the enhanced global rate limiting middleware
func (ebrl *EnhancedBasicRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check global rate limit
		allowed, remaining, backend, err := ebrl.checkGlobalRateLimit()

		// Update statistics
		atomic.AddInt64(&ebrl.stats.BaseStats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&ebrl.stats.BaseStats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&ebrl.stats.BaseStats.BlockedRequests, 1)
		}

		// Handle Redis errors
		if err != nil && ebrl.config.EnableLogging {
			log.Printf("[ENHANCED_BASIC_RATE_LIMITER] Error checking rate limit: %v", err)
		}

		// Create request info
		info := ebrl.createRequestInfo(c, allowed, backend)

		// Set headers
		ebrl.setHeaders(c, remaining, backend)

		// Log event
		ebrl.logEvent(info)

		// Call request handler if provided
		if ebrl.config.OnRequestProcessed != nil {
			ebrl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			ebrl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns enhanced rate limiting statistics
func (ebrl *EnhancedBasicRateLimiter) GetStats() Stats {
	// Update live counters
	ebrl.stats.BaseStats.TotalRequests = atomic.LoadInt64(&ebrl.stats.BaseStats.TotalRequests)
	ebrl.stats.BaseStats.AllowedRequests = atomic.LoadInt64(&ebrl.stats.BaseStats.AllowedRequests)
	ebrl.stats.BaseStats.BlockedRequests = atomic.LoadInt64(&ebrl.stats.BaseStats.BlockedRequests)
	ebrl.stats.IsRedisHealthy = ebrl.isRedisHealthy

	return ebrl.stats
}

// ResetStats resets statistics
func (ebrl *EnhancedBasicRateLimiter) ResetStats() {
	atomic.StoreInt64(&ebrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&ebrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&ebrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&ebrl.stats.RedisOperations, 0)
	atomic.StoreInt64(&ebrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&ebrl.stats.FallbackOperations, 0)
	atomic.StoreInt64(&ebrl.stats.HealthCheckFails, 0)

	ebrl.stats.BaseStats.StartTime = time.Now()
	ebrl.stats.LastRedisError = ""
}

// Stop gracefully stops the rate limiter
func (ebrl *EnhancedBasicRateLimiter) Stop() {
	ebrl.cancel()
}

// Type returns the rate limiter type
func (ebrl *EnhancedBasicRateLimiter) Type() RateLimiterType {
	return BasicType
}

// Algorithm returns the algorithm used
func (ebrl *EnhancedBasicRateLimiter) Algorithm() Algorithm {
	if ebrl.config.RedisConfig.Enabled {
		return SlidingWindowAlg
	}
	return TokenBucketAlg
}

// =============================================================================
// CONVENIENCE FUNCTIONS WITH REDIS SUPPORT
// =============================================================================

// EnhancedBasicRateLimitMiddleware creates an enhanced global rate limiter with optional Redis
func EnhancedBasicRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient component.RedisClient) gin.HandlerFunc {
	config := &EnhancedBasicRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		RedisConfig: &component.RedisConfig{
			Enabled:          redisClient != nil,
			FallbackToMemory: true,
		},
	}
	limiter := NewEnhancedBasicRateLimiter(config, redisClient)
	return limiter.Middleware()
}

// DistributedGlobalRateLimitMiddleware creates a Redis-backed global rate limiter
func DistributedGlobalRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient component.RedisClient) gin.HandlerFunc {
	config := &EnhancedBasicRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		RedisConfig: &component.RedisConfig{
			Enabled:          true,
			FallbackToMemory: true,
		},
	}
	limiter := NewEnhancedBasicRateLimiter(config, redisClient)
	return limiter.Middleware()
}

// ServerProtectionWithRedisMiddleware creates enhanced server protection with Redis support
func ServerProtectionWithRedisMiddleware(maxRequestsPerSecond float64, redisClient component.RedisClient) gin.HandlerFunc {
	config := &EnhancedBasicRateLimiterConfig{
		Rate:          rate.Limit(maxRequestsPerSecond),
		Burst:         int(maxRequestsPerSecond * 0.1), // 10% burst
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "Server overload protection activated",
		RedisConfig: &component.RedisConfig{
			Enabled:          redisClient != nil,
			FallbackToMemory: true,
		},
	}
	limiter := NewEnhancedBasicRateLimiter(config, redisClient)
	return limiter.Middleware()
}
