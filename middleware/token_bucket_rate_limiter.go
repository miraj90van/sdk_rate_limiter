// token_bucket_rate_limiter.go
// Purpose: Token bucket rate limiting with Redis support and fallback
// Use case: Precise rate limiting with burst support and smooth token refill

package middleware

import (
	"context"
	"fmt"
	"hash/fnv"
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

// TokenBucketError represents a token bucket rate limiting error
type TokenBucketError struct {
	Type            string        `json:"type"`
	Message         string        `json:"message"`
	ClientKey       string        `json:"client_key"`
	TokensAvailable float64       `json:"tokens_available"`
	TokensRequested int           `json:"tokens_requested"`
	BucketCapacity  int           `json:"bucket_capacity"`
	RefillRate      float64       `json:"refill_rate"`
	WaitTime        time.Duration `json:"wait_time"`
}

func (e *TokenBucketError) Error() string {
	return e.Message
}

// TokenBucketInfo provides detailed information about the current token bucket state
type TokenBucketInfo struct {
	Tokens          float64       `json:"tokens"`           // Current token count
	Capacity        int           `json:"capacity"`         // Maximum capacity
	RefillRate      float64       `json:"refill_rate"`      // Tokens per second
	Usage           float64       `json:"usage"`            // 0.0 to 1.0
	TimeToFull      time.Duration `json:"time_to_full"`     // Time to reach full capacity
	LastRefill      time.Time     `json:"last_refill"`      // Last refill timestamp
	EstimatedRefill time.Time     `json:"estimated_refill"` // Next significant refill
}

// TokenBucketConfig configuration for token bucket rate limiter
type TokenBucketConfig struct {
	Rate                rate.Limit    // Tokens per second
	Burst               int           // Bucket capacity
	RedisClient         *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix      string        // Prefix for Redis keys
	EnableFallback      bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor        KeyExtractor  // Function to extract a client key
	MaxClients          int           // Maximum clients to track (fallback mode)
	MaxTrackedClients   int           // Maximum clients to track in statistics
	CleanupInterval     time.Duration // Cleanup interval (fallback mode)
	ClientTTL           time.Duration // Client TTL (fallback mode)
	RequestTimeout      time.Duration // Timeout for Redis operations
	EnableHeaders       bool          // Include rate limit headers
	EnableLogging       bool          // Enable logging
	EnableJitter        bool          // Enable jitter to prevent synchronization
	ErrorMessage        string        // Custom error message
	ErrorResponse       interface{}   // Custom error response structure
	AllowWaiting        bool          // Allow requests to wait for tokens
	MaxWaitTime         time.Duration // Maximum wait time for tokens
	MaxTokensPerRequest int           // Maximum tokens that can be requested per request
	MetricsCollector    Metrics       // Optional metrics collector
	OnLimitExceeded     func(*gin.Context, *TokenBucketRequestInfo)
	OnRequestProcessed  func(*gin.Context, *TokenBucketRequestInfo, bool)
	OnTokensRefilled    func(clientKey string, tokensAdded float64, newTotal float64)
}

// Validate validates the configuration
func (config *TokenBucketConfig) Validate() error {
	if config.Rate <= 0 {
		return fmt.Errorf("refill rate must be positive, got %f", config.Rate)
	}
	if config.Burst <= 0 {
		return fmt.Errorf("burst capacity must be positive, got %d", config.Burst)
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
	if config.MaxWaitTime < 0 {
		return fmt.Errorf("max wait time cannot be negative, got %v", config.MaxWaitTime)
	}
	if config.MaxTokensPerRequest <= 0 {
		return fmt.Errorf("max tokens per request must be positive, got %d", config.MaxTokensPerRequest)
	}
	if float64(config.Burst) < float64(config.Rate) {
		log.Printf("WARNING: Burst capacity (%d) is less than refill rate (%.2f). Consider increasing burst capacity for optimal performance", config.Burst, config.Rate)
	}
	return nil
}

// TokenBucketRequestInfo contains request information for token bucket limiter
type TokenBucketRequestInfo struct {
	BaseRequestInfo
	ClientKey       string        `json:"client_key"`
	TokensAvailable float64       `json:"tokens_available"`
	TokensUsed      int           `json:"tokens_used"`
	TokensRequested int           `json:"tokens_requested"`
	WaitTime        time.Duration `json:"wait_time"`
	BucketCapacity  int           `json:"bucket_capacity"`
	RefillRate      float64       `json:"refill_rate"`
	WasQueued       bool          `json:"was_queued"`
	QueueTime       time.Duration `json:"queue_time"`
}

// TokenBucketStats statistics for token bucket rate limiter
type TokenBucketStats struct {
	*BaseStats
	ActiveClients     int64                   `json:"active_clients"`
	RedisMode         bool                    `json:"redis_mode"`
	FallbackMode      bool                    `json:"fallback_mode"`
	RedisErrors       int64                   `json:"redis_errors"`
	WaitingRequests   int64                   `json:"waiting_requests"`
	QueueTimeouts     int64                   `json:"queue_timeouts"`
	TokensConsumed    int64                   `json:"tokens_consumed"`
	TokensRefilled    int64                   `json:"tokens_refilled"`
	AverageWaitTime   time.Duration           `json:"average_wait_time"`
	AverageTokenUsage float64                 `json:"average_token_usage"`
	ClientStats       map[string]*ClientStats `json:"client_stats"`
	mutex             sync.RWMutex
}

// atomicFloat64 provides atomic operations for float64 values
type atomicFloat64 struct {
	bits uint64
}

func (af *atomicFloat64) Load() float64 {
	return math.Float64frombits(atomic.LoadUint64(&af.bits))
}

func (af *atomicFloat64) Store(val float64) {
	atomic.StoreUint64(&af.bits, math.Float64bits(val))
}

func (af *atomicFloat64) Add(delta float64) float64 {
	for {
		old := af.Load()
		new := old + delta
		if af.CompareAndSwap(old, new) {
			return new
		}
	}
}

func (af *atomicFloat64) CompareAndSwap(old, new float64) bool {
	return atomic.CompareAndSwapUint64(&af.bits, math.Float64bits(old), math.Float64bits(new))
}

// tokenBucketEntry represents a client's token bucket in fallback mode
type tokenBucketEntry struct {
	tokens     atomicFloat64 // Current token count (atomic for thread safety)
	lastRefill int64         // Last refill time in Unix nanoseconds (atomic)
	lastAccess int64         // Last access time in Unix nanoseconds (atomic)
	limiter    *rate.Limiter // Go's rate limiter for additional functionality
}

// TokenBucketRateLimiter implements token bucket rate limiting
type TokenBucketRateLimiter struct {
	config     *TokenBucketConfig
	stats      *TokenBucketStats
	clients    sync.Map  // map[string]*tokenBucketEntry - Better concurrent performance
	clientsLRU *lruCache // LRU cache for client statistics
	stopChan   chan struct{}
	redisMode  bool
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter
func NewTokenBucketRateLimiter(config *TokenBucketConfig) (*TokenBucketRateLimiter, error) {
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
		config.ErrorMessage = "Rate limit exceeded"
	}
	if config.MaxWaitTime == 0 {
		config.MaxWaitTime = time.Second * 5
	}
	if config.MaxTokensPerRequest == 0 {
		config.MaxTokensPerRequest = 10
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	tbrl := &TokenBucketRateLimiter{
		config:     config,
		clientsLRU: newLRUCache(config.MaxTrackedClients),
		stopChan:   make(chan struct{}),
		redisMode:  config.RedisClient != nil,
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
				return nil, fmt.Errorf("redis connection failed and fallback disabled: %w", err)
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

	return tbrl, nil
}

// DefaultTokenBucketConfig returns default configuration
func DefaultTokenBucketConfig() *TokenBucketConfig {
	return &TokenBucketConfig{
		Rate:                rate.Limit(100),
		Burst:               200,
		EnableFallback:      true,
		KeyExtractor:        IPKeyExtractor,
		MaxClients:          10000,
		MaxTrackedClients:   1000,
		CleanupInterval:     time.Minute * 5,
		ClientTTL:           time.Hour,
		RequestTimeout:      time.Second * 5,
		EnableHeaders:       true,
		EnableLogging:       false,
		EnableJitter:        false,
		ErrorMessage:        "Rate limit exceeded",
		AllowWaiting:        false,
		MaxWaitTime:         time.Second * 5,
		MaxTokensPerRequest: 10,
	}
}

// testRedisConnection tests the Redis connection
func (tbrl *TokenBucketRateLimiter) testRedisConnection() error {
	if tbrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), tbrl.config.RequestTimeout)
	defer cancel()

	return tbrl.config.RedisClient.Ping(ctx).Err()
}

// addJitter adds deterministic jitter to timing calculations
func (tbrl *TokenBucketRateLimiter) addJitter(baseTime time.Time, clientKey string) time.Time {
	if !tbrl.config.EnableJitter {
		return baseTime
	}

	hash := fnv.New32a()
	hash.Write([]byte(clientKey))
	// Add up to 100ms jitter
	jitterMs := int64(hash.Sum32() % 100)
	return baseTime.Add(time.Duration(jitterMs) * time.Millisecond)
}

// checkRateLimitRedis checks rate limit using Redis with enhanced script
func (tbrl *TokenBucketRateLimiter) checkRateLimitRedis(ctx context.Context, clientKey string, tokensRequested int) (bool, float64, time.Duration, error) {
	now := time.Now()
	// Add jitter to prevent synchronization
	jitteredNow := tbrl.addJitter(now, clientKey)
	currentTime := float64(jitteredNow.UnixMilli()) / 1000.0 // Use seconds with millisecond precision

	// Enhanced Redis Lua script for token bucket rate limiting
	script := `
		local key = KEYS[1]
		local tokens_requested = tonumber(ARGV[1])
		local capacity = tonumber(ARGV[2])
		local refill_rate = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		-- Input validation
		if not tokens_requested or tokens_requested <= 0 then
			return redis.error_reply("Invalid tokens requested: " .. tostring(ARGV[1]))
		end
		if not capacity or capacity <= 0 then
			return redis.error_reply("Invalid capacity: " .. tostring(ARGV[2]))
		end
		if not refill_rate or refill_rate <= 0 then
			return redis.error_reply("Invalid refill rate: " .. tostring(ARGV[3]))
		end
		if not now or now <= 0 then
			return redis.error_reply("Invalid current time: " .. tostring(ARGV[4]))
		end
		
		-- Get current bucket state
		local bucket_data = redis.call('HMGET', key, 'tokens', 'last_refill')
		local current_tokens = tonumber(bucket_data[1])
		local last_refill = tonumber(bucket_data[2])
		
		-- Initialize if bucket doesn't exist
		if not current_tokens then
			current_tokens = capacity
		end
		if not last_refill then
			last_refill = now
		end
		
		-- Protect against clock skew
		if last_refill > now then
			last_refill = now
		end
		
		-- Calculate time passed and tokens to add
		local time_passed = math.max(0, now - last_refill)
		local tokens_to_add = time_passed * refill_rate
		local new_tokens = math.min(capacity, current_tokens + tokens_to_add)
		
		-- Check if enough tokens available
		if new_tokens >= tokens_requested then
			-- Consume tokens
			new_tokens = new_tokens - tokens_requested
			
			-- Update bucket state
			redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
			redis.call('EXPIRE', key, 3600)
			
			-- Return: allowed(1), remaining_tokens, wait_time, tokens_added
			return {1, new_tokens, 0, tokens_to_add}
		else
			-- Calculate wait time for enough tokens
			local tokens_needed = tokens_requested - new_tokens
			local wait_time = tokens_needed / refill_rate
			
			-- Update last_refill time but don't consume tokens
			redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
			redis.call('EXPIRE', key, 3600)
			
			-- Return: allowed(0), remaining_tokens, wait_time, tokens_added
			return {0, new_tokens, wait_time, tokens_to_add}
		end
	`

	result, err := tbrl.config.RedisClient.Eval(ctx, script, []string{
		tbrl.config.RedisKeyPrefix + clientKey,
	}, tokensRequested, tbrl.config.Burst, float64(tbrl.config.Rate), currentTime).Result()

	if err != nil {
		atomic.AddInt64(&tbrl.stats.RedisErrors, 1)
		tbrl.recordMetric("redis_errors", 1, map[string]string{"client": clientKey})
		return false, 0, 0, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 4 {
		return false, 0, 0, fmt.Errorf("unexpected Redis result format: %v", result)
	}

	allowed := resultSlice[0].(int64) == 1
	remainingTokens, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[1]), 64)
	waitTimeSeconds, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[2]), 64)
	tokensAdded, _ := strconv.ParseFloat(fmt.Sprintf("%v", resultSlice[3]), 64)
	waitTime := time.Duration(waitTimeSeconds * float64(time.Second))

	// Update statistics
	if tokensAdded > 0 {
		atomic.AddInt64(&tbrl.stats.TokensRefilled, int64(tokensAdded))
	}
	if allowed {
		atomic.AddInt64(&tbrl.stats.TokensConsumed, int64(tokensRequested))
	}

	// Call refill callback if provided
	if tbrl.config.OnTokensRefilled != nil && tokensAdded > 0 {
		tbrl.config.OnTokensRefilled(clientKey, tokensAdded, remainingTokens+tokensAdded)
	}

	return allowed, remainingTokens, waitTime, nil
}

// checkRateLimitFallback checks rate limit using in-memory storage with atomic operations
func (tbrl *TokenBucketRateLimiter) checkRateLimitFallback(clientKey string, tokensRequested int) (bool, float64, time.Duration) {
	now := time.Now()
	// Add jitter to prevent synchronization
	jitteredNow := tbrl.addJitter(now, clientKey)
	nowNano := jitteredNow.UnixNano()

	// Load or create entry using sync.Map for better concurrent performance
	value, _ := tbrl.clients.LoadOrStore(clientKey, &tokenBucketEntry{
		tokens:     atomicFloat64{bits: math.Float64bits(float64(tbrl.config.Burst))},
		lastRefill: nowNano,
		lastAccess: nowNano,
		limiter:    rate.NewLimiter(tbrl.config.Rate, tbrl.config.Burst),
	})

	entry := value.(*tokenBucketEntry)

	// Update last access atomically
	atomic.StoreInt64(&entry.lastAccess, nowNano)

	// Get current state
	lastRefillNano := atomic.LoadInt64(&entry.lastRefill)
	currentTokens := entry.tokens.Load()

	// Calculate time passed and tokens to add
	timePassed := time.Duration(nowNano - lastRefillNano)
	tokensToAdd := timePassed.Seconds() * float64(tbrl.config.Rate)

	// Update tokens atomically
	newTokens := math.Min(float64(tbrl.config.Burst), currentTokens+tokensToAdd)
	entry.tokens.Store(newTokens)
	atomic.StoreInt64(&entry.lastRefill, nowNano)

	// Update statistics
	if tokensToAdd > 0 {
		atomic.AddInt64(&tbrl.stats.TokensRefilled, int64(tokensToAdd))
	}

	// Call refill callback if provided
	if tbrl.config.OnTokensRefilled != nil && tokensToAdd > 0 {
		tbrl.config.OnTokensRefilled(clientKey, tokensToAdd, newTokens)
	}

	// Check if enough tokens available
	if newTokens >= float64(tokensRequested) {
		// Consume tokens atomically
		finalTokens := entry.tokens.Add(-float64(tokensRequested))
		atomic.AddInt64(&tbrl.stats.TokensConsumed, int64(tokensRequested))
		return true, finalTokens, 0
	}

	// Calculate wait time
	tokensNeeded := float64(tokensRequested) - newTokens
	waitTime := time.Duration(tokensNeeded/float64(tbrl.config.Rate)) * time.Second

	return false, newTokens, waitTime
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
	expiry := now.Add(-tbrl.config.ClientTTL).UnixNano()
	deletedCount := 0

	tbrl.clients.Range(func(key, value interface{}) bool {
		entry := value.(*tokenBucketEntry)
		lastAccess := atomic.LoadInt64(&entry.lastAccess)

		if lastAccess < expiry {
			tbrl.clients.Delete(key)
			deletedCount++
		}
		return true
	})

	// Update metrics
	if deletedCount > 0 {
		tbrl.recordMetric("clients_cleaned", float64(deletedCount), nil)
	}

	// Update active clients count
	activeCount := int64(0)
	tbrl.clients.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	atomic.StoreInt64(&tbrl.stats.ActiveClients, activeCount)
}

// createRequestInfo creates request information
func (tbrl *TokenBucketRateLimiter) createRequestInfo(c *gin.Context, clientKey string, allowed bool, tokensAvailable float64, tokensRequested int, waitTime time.Duration) *TokenBucketRequestInfo {
	tokensUsed := 0
	if allowed {
		tokensUsed = tokensRequested
	}

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
		TokensRequested: tokensRequested,
		WaitTime:        waitTime,
		BucketCapacity:  tbrl.config.Burst,
		RefillRate:      float64(tbrl.config.Rate),
		WasQueued:       false,
		QueueTime:       0,
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

// recordMetric records a metric if metrics collector is configured
func (tbrl *TokenBucketRateLimiter) recordMetric(name string, value float64, tags map[string]string) {
	if tbrl.config.MetricsCollector != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["limiter_type"] = "token_bucket"
		tags["mode"] = "memory"
		if tbrl.redisMode {
			tags["mode"] = "redis"
		}
		tbrl.config.MetricsCollector.RecordHistogram(name, value, tags)
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

	queueInfo := ""
	if info.WasQueued {
		queueInfo = fmt.Sprintf(", Queued: %v", info.QueueTime)
	}

	log.Printf("[TOKEN_BUCKET_%s] %s - Client: %s, Method: %s, Path: %s, Tokens: %.2f/%d, Requested: %d, Used: %d, Wait: %v%s",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.TokensAvailable, info.BucketCapacity, info.TokensRequested, info.TokensUsed, info.WaitTime, queueInfo)
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

	// Create structured error response
	tokenBucketError := &TokenBucketError{
		Type:            "token_bucket_rate_limit_exceeded",
		Message:         tbrl.config.ErrorMessage,
		ClientKey:       info.ClientKey,
		TokensAvailable: info.TokensAvailable,
		TokensRequested: info.TokensRequested,
		BucketCapacity:  info.BucketCapacity,
		RefillRate:      info.RefillRate,
		WaitTime:        info.WaitTime,
	}

	// Default error response
	response := gin.H{
		"error":  tokenBucketError.Message,
		"type":   tokenBucketError.Type,
		"client": tokenBucketError.ClientKey,
		"bucket_info": gin.H{
			"tokens_available": tokenBucketError.TokensAvailable,
			"tokens_requested": tokenBucketError.TokensRequested,
			"capacity":         tokenBucketError.BucketCapacity,
			"refill_rate":      fmt.Sprintf("%.2f tokens/sec", tokenBucketError.RefillRate),
			"usage":            fmt.Sprintf("%.1f%%", (info.TokensAvailable/float64(info.BucketCapacity))*100),
		},
		"algorithm": tbrl.Algorithm().String(),
		"timestamp": info.Timestamp.Format(time.RFC3339),
	}

	if info.WaitTime > 0 {
		response["retry_after_seconds"] = info.WaitTime.Seconds()
		response["estimated_wait"] = info.WaitTime.String()
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// handleWaitingRequest handles requests that need to wait for tokens
func (tbrl *TokenBucketRateLimiter) handleWaitingRequest(ctx context.Context, info *TokenBucketRequestInfo) bool {
	if !tbrl.config.AllowWaiting || info.WaitTime <= 0 || info.WaitTime > tbrl.config.MaxWaitTime {
		return false
	}

	atomic.AddInt64(&tbrl.stats.WaitingRequests, 1)
	startWait := time.Now()

	// Add jitter to wait time
	jitteredWait := tbrl.addJitter(time.Now().Add(info.WaitTime), info.ClientKey).Sub(time.Now())

	// Wait for tokens to be available
	select {
	case <-time.After(jitteredWait):
		info.WasQueued = true
		info.QueueTime = time.Since(startWait)
		return true
	case <-ctx.Done():
		atomic.AddInt64(&tbrl.stats.QueueTimeouts, 1)
		return false
	}
}

// updateClientStats updates statistics for a specific client with LRU eviction
func (tbrl *TokenBucketRateLimiter) updateClientStats(clientKey string, allowed bool, tokenUsage float64) {
	// Check if we should evict before adding
	if tbrl.clientsLRU.shouldEvict(clientKey) {
		return // Skip tracking to prevent memory bloat
	}

	tbrl.stats.mutex.Lock()
	defer tbrl.stats.mutex.Unlock()

	clientStats, exists := tbrl.stats.ClientStats[clientKey]
	if !exists {
		// Check bounds again with lock held
		if len(tbrl.stats.ClientStats) >= tbrl.config.MaxTrackedClients {
			// Evict oldest client
			tbrl.evictOldestClientLocked()
		}

		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		tbrl.stats.ClientStats[clientKey] = clientStats
	}

	// Update LRU cache
	tbrl.clientsLRU.access(clientKey)

	clientStats.TotalRequests++
	clientStats.LastAccess = time.Now()
	clientStats.IsActive = true

	if allowed {
		clientStats.AllowedRequests++
	} else {
		clientStats.BlockedRequests++
	}

	// Update average token usage
	currentAvg := tbrl.stats.AverageTokenUsage
	totalRequests := float64(atomic.LoadInt64(&tbrl.stats.TotalRequests))
	tbrl.stats.AverageTokenUsage = (currentAvg*(totalRequests-1) + tokenUsage) / totalRequests
}

// evictOldestClientLocked evicts the oldest client from statistics (must be called with lock held)
func (tbrl *TokenBucketRateLimiter) evictOldestClientLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, stats := range tbrl.stats.ClientStats {
		if oldestKey == "" || stats.FirstSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.FirstSeen
		}
	}

	if oldestKey != "" {
		delete(tbrl.stats.ClientStats, oldestKey)
	}
}

// Middleware returns the token bucket rate limiting middleware
func (tbrl *TokenBucketRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create request-specific context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), tbrl.config.RequestTimeout)
		defer cancel()

		// Extract a client key
		clientKey := tbrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		// Default: 1 token per request
		tokensRequested := 1

		// Allow custom token consumption via header
		if tokenHeader := c.GetHeader("X-Tokens-Requested"); tokenHeader != "" {
			if tokens, err := strconv.Atoi(tokenHeader); err == nil && tokens > 0 && tokens <= tbrl.config.MaxTokensPerRequest {
				tokensRequested = tokens
			}
		}

		var allowed bool
		var tokensAvailable float64
		var waitTime time.Duration
		var err error

		startTime := time.Now()

		// Check rate limit
		if tbrl.redisMode {
			allowed, tokensAvailable, waitTime, err = tbrl.checkRateLimitRedis(ctx, clientKey, tokensRequested)
			if err != nil && tbrl.config.EnableFallback {
				log.Printf("[TOKEN_BUCKET] Redis error, falling back to memory: %v", err)
				tbrl.redisMode = false
				tbrl.stats.FallbackMode = true
				allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
			}
		} else {
			allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
		}

		// Record operation duration
		duration := time.Since(startTime)
		tbrl.recordMetric("rate_limit_check_duration_ms", float64(duration.Milliseconds()), map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		// Create request info
		info := tbrl.createRequestInfo(c, clientKey, allowed, tokensAvailable, tokensRequested, waitTime)

		// Handle waiting requests if enabled
		if !allowed && tbrl.config.AllowWaiting {
			if tbrl.handleWaitingRequest(ctx, info) {
				// Retry after waiting
				if tbrl.redisMode {
					allowed, tokensAvailable, waitTime, _ = tbrl.checkRateLimitRedis(ctx, clientKey, tokensRequested)
				} else {
					allowed, tokensAvailable, waitTime = tbrl.checkRateLimitFallback(clientKey, tokensRequested)
				}
				// Update info with new values
				info.Allowed = allowed
				info.TokensAvailable = tokensAvailable
				info.WaitTime = waitTime
				if allowed {
					info.TokensUsed = tokensRequested
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

		// Calculate token usage for statistics
		tokenUsage := float64(info.TokensUsed) / float64(tbrl.config.Burst)
		tbrl.updateClientStats(clientKey, allowed, tokenUsage)

		// Set headers
		tbrl.setHeaders(c, tokensAvailable, waitTime)

		// Log event
		tbrl.logEvent(info)

		// Record metrics
		tbrl.recordMetric("requests_total", 1, map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
			"queued":  strconv.FormatBool(info.WasQueued),
		})

		if info.TokensUsed > 0 {
			tbrl.recordMetric("tokens_consumed", float64(info.TokensUsed), map[string]string{
				"client": clientKey,
			})
		}

		if info.WasQueued {
			tbrl.recordMetric("queue_time_ms", float64(info.QueueTime.Milliseconds()), map[string]string{
				"client": clientKey,
			})
		}

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
func (tbrl *TokenBucketRateLimiter) GetStats() interface{} {
	// Update live counters
	tbrl.stats.TotalRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.TotalRequests)
	tbrl.stats.AllowedRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.AllowedRequests)
	tbrl.stats.BlockedRequests = atomic.LoadInt64(&tbrl.stats.BaseStats.BlockedRequests)
	tbrl.stats.ActiveClients = atomic.LoadInt64(&tbrl.stats.ActiveClients)
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

// GetTokenBucketInfo returns current bucket information for a client
func (tbrl *TokenBucketRateLimiter) GetTokenBucketInfo(clientKey string) *TokenBucketInfo {
	now := time.Now()

	if tbrl.redisMode {
		// For Redis mode, query the hash
		ctx, cancel := context.WithTimeout(context.Background(), tbrl.config.RequestTimeout)
		defer cancel()

		key := tbrl.config.RedisKeyPrefix + clientKey
		bucketData, err := tbrl.config.RedisClient.HMGet(ctx, key, "tokens", "last_refill").Result()
		if err != nil {
			return nil
		}

		tokens, _ := strconv.ParseFloat(fmt.Sprintf("%v", bucketData[0]), 64)
		lastRefillFloat, _ := strconv.ParseFloat(fmt.Sprintf("%v", bucketData[1]), 64)
		lastRefill := time.Unix(int64(lastRefillFloat), 0)

		if tokens == 0 {
			tokens = float64(tbrl.config.Burst)
		}
		if lastRefillFloat == 0 {
			lastRefill = now
		}

		timeToFull := time.Duration((float64(tbrl.config.Burst)-tokens)/float64(tbrl.config.Rate)) * time.Second
		if timeToFull < 0 {
			timeToFull = 0
		}

		return &TokenBucketInfo{
			Tokens:          tokens,
			Capacity:        tbrl.config.Burst,
			RefillRate:      float64(tbrl.config.Rate),
			Usage:           tokens / float64(tbrl.config.Burst),
			TimeToFull:      timeToFull,
			LastRefill:      lastRefill,
			EstimatedRefill: now.Add(time.Second / time.Duration(tbrl.config.Rate)),
		}
	} else {
		// For memory mode, access the atomic values
		value, exists := tbrl.clients.Load(clientKey)
		if !exists {
			return &TokenBucketInfo{
				Tokens:          float64(tbrl.config.Burst),
				Capacity:        tbrl.config.Burst,
				RefillRate:      float64(tbrl.config.Rate),
				Usage:           1.0,
				TimeToFull:      0,
				LastRefill:      now,
				EstimatedRefill: now.Add(time.Second / time.Duration(tbrl.config.Rate)),
			}
		}

		entry := value.(*tokenBucketEntry)
		tokens := entry.tokens.Load()
		lastRefillNano := atomic.LoadInt64(&entry.lastRefill)
		lastRefill := time.Unix(0, lastRefillNano)

		timeToFull := time.Duration((float64(tbrl.config.Burst)-tokens)/float64(tbrl.config.Rate)) * time.Second
		if timeToFull < 0 {
			timeToFull = 0
		}

		return &TokenBucketInfo{
			Tokens:          tokens,
			Capacity:        tbrl.config.Burst,
			RefillRate:      float64(tbrl.config.Rate),
			Usage:           tokens / float64(tbrl.config.Burst),
			TimeToFull:      timeToFull,
			LastRefill:      lastRefill,
			EstimatedRefill: now.Add(time.Second / time.Duration(tbrl.config.Rate)),
		}
	}
}

// ResetClient resets rate limiting for a specific client
func (tbrl *TokenBucketRateLimiter) ResetClient(clientKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), tbrl.config.RequestTimeout)
	defer cancel()

	if tbrl.redisMode {
		tbrl.config.RedisClient.Del(ctx, tbrl.config.RedisKeyPrefix+clientKey)
	} else {
		tbrl.clients.Delete(clientKey)
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

	count := 0
	tbrl.clients.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// ResetStats resets all statistics
func (tbrl *TokenBucketRateLimiter) ResetStats() {
	atomic.StoreInt64(&tbrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&tbrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&tbrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&tbrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&tbrl.stats.WaitingRequests, 0)
	atomic.StoreInt64(&tbrl.stats.QueueTimeouts, 0)
	atomic.StoreInt64(&tbrl.stats.TokensConsumed, 0)
	atomic.StoreInt64(&tbrl.stats.TokensRefilled, 0)
	tbrl.stats.BaseStats.StartTime = time.Now()
	tbrl.stats.AverageTokenUsage = 0

	tbrl.stats.mutex.Lock()
	tbrl.stats.ClientStats = make(map[string]*ClientStats)
	tbrl.stats.mutex.Unlock()

	// Reset LRU cache
	tbrl.clientsLRU = newLRUCache(tbrl.config.MaxTrackedClients)
}

// Stop gracefully stops the rate limiter
func (tbrl *TokenBucketRateLimiter) Stop() {
	close(tbrl.stopChan)
}

// Type returns the type of rate limiter
func (tbrl *TokenBucketRateLimiter) Type() RateLimiterType {
	return TokenBucketType
}

// Algorithm returns the algorithm used
func (tbrl *TokenBucketRateLimiter) Algorithm() Algorithm {
	return TokenBucketAlg
}

// EstimateRemainingFromReservation estimates remaining tokens from rate limiter (helper function)
func EstimateRemainingFromReservation(limiter *rate.Limiter, burst int) int {
	// This is a rough estimation since Go's rate.Limiter doesn't expose internal state
	// We use a test reservation to estimate
	reservation := limiter.Reserve()
	defer reservation.Cancel()

	if reservation.OK() && reservation.Delay() == 0 {
		// Tokens are available, estimate based on burst capacity
		// This is an approximation
		return burst / 2 // Conservative estimate
	}
	return 0
}
