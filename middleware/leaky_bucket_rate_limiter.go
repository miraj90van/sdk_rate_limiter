// leaky_bucket_rate_limiter.go
// Purpose: Leaky bucket rate limiting with Redis support and fallback
// Use case: Smooth rate limiting with constant outflow rate and buffer capacity

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
	"net/http"
)

var _ RateLimiter = (*LeakyBucketRateLimiter)(nil)

// LeakyBucketError represents a leaky bucket rate limiting error
type LeakyBucketError struct {
	Type          string        `json:"type"`
	Message       string        `json:"message"`
	ClientKey     string        `json:"client_key"`
	CurrentLevel  float64       `json:"current_level"`
	Capacity      int           `json:"capacity"`
	LeakRate      float64       `json:"leak_rate"`
	EstimatedWait time.Duration `json:"estimated_wait"`
	TimeToEmpty   time.Duration `json:"time_to_empty"`
}

func (e *LeakyBucketError) Error() string {
	return e.Message
}

// BucketInfo provides detailed information about the current bucket state
type BucketInfo struct {
	Level       float64       `json:"level"`
	Capacity    int           `json:"capacity"`
	LeakRate    float64       `json:"leak_rate"`
	Usage       float64       `json:"usage"`     // 0.0 to 1.0
	Remaining   int           `json:"remaining"` // Available capacity
	TimeToEmpty time.Duration `json:"time_to_empty"`
	LastUpdate  time.Time     `json:"last_update"`
}

// LeakyBucketConfig configuration for leaky bucket rate limiter
type LeakyBucketConfig struct {
	LeakRate           float64       // Requests per second that leak out
	Capacity           int           // Maximum bucket capacity (buffer size)
	RedisClient        *redis.Client // Redis client for distributed limiting
	RedisKeyPrefix     string        // Prefix for Redis keys
	EnableFallback     bool          // Enable fallback to in-memory when Redis fails
	KeyExtractor       KeyExtractor  // Function to extract a client key
	MaxClients         int           // Maximum clients to track (fallback mode)
	MaxTrackedClients  int           // Maximum clients to track in statistics
	CleanupInterval    time.Duration // Cleanup interval (fallback mode)
	ClientTTL          time.Duration // Client TTL (fallback mode)
	RequestTimeout     time.Duration // Timeout for Redis operations
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	EnableJitter       bool          // Enable jitter to prevent synchronization
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	AllowQueueing      bool          // Allow requests to wait in queue
	MaxQueueTime       time.Duration // Maximum time to wait in queue
	MetricsCollector   Metrics       // Optional metrics collector
	OnLimitExceeded    func(*gin.Context, *LeakyBucketRequestInfo)
	OnRequestProcessed func(*gin.Context, *LeakyBucketRequestInfo, bool)
	OnQueueTimeout     func(*gin.Context, *LeakyBucketRequestInfo)
}

// Validate validates the configuration
func (config *LeakyBucketConfig) Validate() error {
	if config.LeakRate <= 0 {
		return fmt.Errorf("leak rate must be positive, got %f", config.LeakRate)
	}
	if config.Capacity <= 0 {
		return fmt.Errorf("capacity must be positive, got %d", config.Capacity)
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
	if config.MaxQueueTime < 0 {
		return fmt.Errorf("max queue time cannot be negative, got %v", config.MaxQueueTime)
	}
	if config.LeakRate > float64(config.Capacity) {
		return fmt.Errorf("leak rate (%f) should not exceed capacity (%d) for optimal behavior", config.LeakRate, config.Capacity)
	}
	return nil
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
	WasQueued     bool          `json:"was_queued"`     // Whether request was queued
	QueueTime     time.Duration `json:"queue_time"`     // Actual time spent in queue
}

// LeakyBucketStats statistics for leaky bucket rate limiter
type LeakyBucketStats struct {
	*BaseStats
	ActiveClients      int64                   `json:"active_clients"`
	RedisMode          bool                    `json:"redis_mode"`
	FallbackMode       bool                    `json:"fallback_mode"`
	RedisErrors        int64                   `json:"redis_errors"`
	QueuedRequests     int64                   `json:"queued_requests"`
	DroppedRequests    int64                   `json:"dropped_requests"`
	QueueTimeouts      int64                   `json:"queue_timeouts"`
	AverageWaitTime    time.Duration           `json:"average_wait_time"`
	AverageBucketUsage float64                 `json:"average_bucket_usage"`
	ClientStats        map[string]*ClientStats `json:"client_stats"`
	mutex              sync.RWMutex
}

// leakyBucketEntry represents a client's bucket state in fallback mode
type leakyBucketEntry struct {
	level      int64 // Current bucket level (using atomic int64 for better performance)
	lastUpdate int64 // Last update time in Unix nanoseconds (atomic)
	lastAccess int64 // Last access time in Unix nanoseconds (atomic)
}

// LeakyBucketRateLimiter implements leaky bucket rate limiting
type LeakyBucketRateLimiter struct {
	config     *LeakyBucketConfig
	stats      *LeakyBucketStats
	clients    sync.Map  // map[string]*leakyBucketEntry - Better concurrent performance
	clientsLRU *lruCache // LRU cache for client statistics
	stopChan   chan struct{}
	redisMode  bool
}

// NewLeakyBucketRateLimiter creates a new leaky bucket rate limiter
func NewLeakyBucketRateLimiter(config *LeakyBucketConfig) (*LeakyBucketRateLimiter, error) {
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
	if config.MaxQueueTime == 0 {
		config.MaxQueueTime = time.Second * 10
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	lbrl := &LeakyBucketRateLimiter{
		config:     config,
		clientsLRU: newLRUCache(config.MaxTrackedClients),
		stopChan:   make(chan struct{}),
		redisMode:  config.RedisClient != nil,
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
				return nil, fmt.Errorf("redis connection failed and fallback disabled: %w", err)
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

	return lbrl, nil
}

// DefaultLeakyBucketConfig returns default configuration
func DefaultLeakyBucketConfig() *LeakyBucketConfig {
	return &LeakyBucketConfig{
		LeakRate:          10.0, // 10 requests per second
		Capacity:          100,  // 100 request buffer
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
		AllowQueueing:     false,
		MaxQueueTime:      time.Second * 10,
	}
}

// testRedisConnection tests the Redis connection
func (lbrl *LeakyBucketRateLimiter) testRedisConnection() error {
	if lbrl.config.RedisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lbrl.config.RequestTimeout)
	defer cancel()

	return lbrl.config.RedisClient.Ping(ctx).Err()
}

// addJitter adds deterministic jitter to timing calculations
func (lbrl *LeakyBucketRateLimiter) addJitter(baseTime time.Time, clientKey string) time.Time {
	if !lbrl.config.EnableJitter {
		return baseTime
	}

	hash := fnv.New32a()
	hash.Write([]byte(clientKey))
	// Add up to 100ms jitter
	jitterMs := int64(hash.Sum32() % 100)
	return baseTime.Add(time.Duration(jitterMs) * time.Millisecond)
}

// checkRateLimitRedis checks rate limit using Redis
func (lbrl *LeakyBucketRateLimiter) checkRateLimitRedis(ctx context.Context, clientKey string) (bool, float64, time.Duration, error) {
	now := time.Now()
	currentTimeMs := now.UnixMilli()

	// Enhanced Redis Lua script for leaky bucket rate limiting
	script := `
		local key = KEYS[1]
		local current_time = tonumber(ARGV[1])  -- Current time in milliseconds
		local leak_rate = tonumber(ARGV[2])     -- Leak rate per second
		local capacity = tonumber(ARGV[3])      -- Bucket capacity
		local request_cost = tonumber(ARGV[4])  -- Cost of this request (usually 1)
		
		-- Input validation
		if not current_time or current_time <= 0 then
			return redis.error_reply("Invalid current time: " .. tostring(ARGV[1]))
		end
		if not leak_rate or leak_rate <= 0 then
			return redis.error_reply("Invalid leak rate: " .. tostring(ARGV[2]))
		end
		if not capacity or capacity <= 0 then
			return redis.error_reply("Invalid capacity: " .. tostring(ARGV[3]))
		end
		if not request_cost or request_cost <= 0 then
			return redis.error_reply("Invalid request cost: " .. tostring(ARGV[4]))
		end
		
		-- Get current bucket state
		local bucket_data = redis.call('HMGET', key, 'level', 'last_update')
		local current_level = tonumber(bucket_data[1]) or 0
		local last_update = tonumber(bucket_data[2]) or current_time
		
		-- Ensure last_update is not in the future (clock skew protection)
		if last_update > current_time then
			last_update = current_time
		end
		
		-- Calculate time passed and amount leaked
		local time_passed_seconds = math.max(0, (current_time - last_update) / 1000.0)
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
			
			-- Return: allowed, level, wait_time, time_to_empty
			local time_to_empty = new_level / leak_rate
			return {0, new_level, wait_time_seconds, time_to_empty}
		else
			-- Add request to bucket
			new_level = new_level + request_cost
			
			-- Update bucket state
			redis.call('HMSET', key, 'level', new_level, 'last_update', current_time)
			redis.call('EXPIRE', key, 3600)
			
			-- Return: allowed, level, wait_time, time_to_empty
			local time_to_empty = new_level / leak_rate
			return {1, new_level, 0, time_to_empty}
		end
	`

	result, err := lbrl.config.RedisClient.Eval(ctx, script, []string{
		lbrl.config.RedisKeyPrefix + clientKey,
	}, currentTimeMs, lbrl.config.LeakRate, lbrl.config.Capacity, 1).Result()

	if err != nil {
		atomic.AddInt64(&lbrl.stats.RedisErrors, 1)
		lbrl.recordMetric("redis_errors", 1, map[string]string{"client": clientKey})
		return false, 0, 0, err
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 4 {
		return false, 0, 0, fmt.Errorf("unexpected Redis result format: %v", result)
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
	nowNano := now.UnixNano()

	// Load or create entry using sync.Map for better concurrent performance
	value, _ := lbrl.clients.LoadOrStore(clientKey, &leakyBucketEntry{
		level:      0,
		lastUpdate: nowNano,
		lastAccess: nowNano,
	})

	entry := value.(*leakyBucketEntry)

	// Update last access atomically
	atomic.StoreInt64(&entry.lastAccess, nowNano)

	// Get current state atomically
	lastUpdateNano := atomic.LoadInt64(&entry.lastUpdate)
	currentLevelInt := atomic.LoadInt64(&entry.level)

	// Calculate time passed and leak amount
	timePassed := time.Duration(nowNano - lastUpdateNano)
	leakAmount := timePassed.Seconds() * lbrl.config.LeakRate

	// Calculate new level
	currentLevel := math.Max(0, float64(currentLevelInt)/1000.0-leakAmount) // Store as millilevels for precision
	newLevelInt := int64(currentLevel * 1000.0)

	// Update atomically
	atomic.StoreInt64(&entry.level, newLevelInt)
	atomic.StoreInt64(&entry.lastUpdate, nowNano)

	// Check if request can be accommodated
	requestCost := 1.0
	if currentLevel+requestCost > float64(lbrl.config.Capacity) {
		// Bucket overflow, calculate wait time
		overflow := (currentLevel + requestCost) - float64(lbrl.config.Capacity)
		waitTime := time.Duration(overflow/lbrl.config.LeakRate) * time.Second

		return false, currentLevel, waitTime
	}

	// Add request to bucket atomically
	newLevel := currentLevel + requestCost
	atomic.StoreInt64(&entry.level, int64(newLevel*1000.0))

	return true, newLevel, 0
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
	expiry := now.Add(-lbrl.config.ClientTTL).UnixNano()
	deletedCount := 0

	lbrl.clients.Range(func(key, value interface{}) bool {
		entry := value.(*leakyBucketEntry)
		lastAccess := atomic.LoadInt64(&entry.lastAccess)

		if lastAccess < expiry {
			lbrl.clients.Delete(key)
			deletedCount++
		}
		return true
	})

	// Update metrics
	if deletedCount > 0 {
		lbrl.recordMetric("clients_cleaned", float64(deletedCount), nil)
	}

	// Update active clients count
	activeCount := int64(0)
	lbrl.clients.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	atomic.StoreInt64(&lbrl.stats.ActiveClients, activeCount)
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
		WasQueued:     false,
		QueueTime:     0,
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

// recordMetric records a metric if metrics collector is configured
func (lbrl *LeakyBucketRateLimiter) recordMetric(name string, value float64, tags map[string]string) {
	if lbrl.config.MetricsCollector != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["limiter_type"] = "leaky_bucket"
		tags["mode"] = "memory"
		if lbrl.redisMode {
			tags["mode"] = "redis"
		}
		lbrl.config.MetricsCollector.RecordHistogram(name, value, tags)
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

	queueInfo := ""
	if info.WasQueued {
		queueInfo = fmt.Sprintf(", Queued: %v", info.QueueTime)
	}

	log.Printf("[LEAKY_BUCKET_%s] %s - Client: %s, Method: %s, Path: %s, Level: %.2f/%d (%.1f%%), Wait: %v%s",
		mode, status, info.ClientKey, info.Method, info.Path,
		info.CurrentLevel, info.Capacity, info.BucketUsage*100, info.EstimatedWait, queueInfo)
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

	// Create structured error response
	leakyBucketError := &LeakyBucketError{
		Type:          "leaky_bucket_rate_limit_exceeded",
		Message:       lbrl.config.ErrorMessage,
		ClientKey:     info.ClientKey,
		CurrentLevel:  info.CurrentLevel,
		Capacity:      info.Capacity,
		LeakRate:      info.LeakRate,
		EstimatedWait: info.EstimatedWait,
		TimeToEmpty:   info.TimeToEmpty,
	}

	// Default error response
	response := gin.H{
		"error":  leakyBucketError.Message,
		"type":   leakyBucketError.Type,
		"client": leakyBucketError.ClientKey,
		"bucket_info": gin.H{
			"level":         leakyBucketError.CurrentLevel,
			"capacity":      leakyBucketError.Capacity,
			"leak_rate":     fmt.Sprintf("%.2f req/sec", leakyBucketError.LeakRate),
			"usage":         fmt.Sprintf("%.1f%%", info.BucketUsage*100),
			"time_to_empty": leakyBucketError.TimeToEmpty.String(),
		},
		"algorithm": lbrl.Algorithm().String(),
		"timestamp": info.Timestamp.Format(time.RFC3339),
	}

	if info.EstimatedWait > 0 {
		response["estimated_wait_seconds"] = info.EstimatedWait.Seconds()
		response["estimated_wait"] = info.EstimatedWait.String()
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// handleQueuedRequest handles requests that need to wait
func (lbrl *LeakyBucketRateLimiter) handleQueuedRequest(ctx context.Context, info *LeakyBucketRequestInfo) bool {
	if !lbrl.config.AllowQueueing || info.EstimatedWait <= 0 || info.EstimatedWait > lbrl.config.MaxQueueTime {
		return false
	}

	atomic.AddInt64(&lbrl.stats.QueuedRequests, 1)
	startWait := time.Now()

	// Add jitter to wait time
	jitteredWait := lbrl.addJitter(time.Now().Add(info.EstimatedWait), info.ClientKey).Sub(time.Now())

	// Wait for bucket to have space
	select {
	case <-time.After(jitteredWait):
		info.WasQueued = true
		info.QueueTime = time.Since(startWait)
		return true
	case <-ctx.Done():
		atomic.AddInt64(&lbrl.stats.QueueTimeouts, 1)
		return false
	}
}

// updateClientStats updates statistics for a specific client with LRU eviction
func (lbrl *LeakyBucketRateLimiter) updateClientStats(clientKey string, allowed bool, bucketUsage float64) {
	// Check if we should evict before adding
	if lbrl.clientsLRU.shouldEvict(clientKey) {
		return // Skip tracking to prevent memory bloat
	}

	lbrl.stats.mutex.Lock()
	defer lbrl.stats.mutex.Unlock()

	clientStats, exists := lbrl.stats.ClientStats[clientKey]
	if !exists {
		// Check bounds again with lock held
		if len(lbrl.stats.ClientStats) >= lbrl.config.MaxTrackedClients {
			// Evict oldest client
			lbrl.evictOldestClientLocked()
		}

		clientStats = &ClientStats{
			ClientKey: clientKey,
			FirstSeen: time.Now(),
			IsActive:  true,
		}
		lbrl.stats.ClientStats[clientKey] = clientStats
	}

	// Update LRU cache
	lbrl.clientsLRU.access(clientKey)

	clientStats.TotalRequests++
	clientStats.LastAccess = time.Now()
	clientStats.IsActive = true

	if allowed {
		clientStats.AllowedRequests++
	} else {
		clientStats.BlockedRequests++
	}

	// Update average bucket usage
	currentAvg := lbrl.stats.AverageBucketUsage
	totalRequests := float64(atomic.LoadInt64(&lbrl.stats.TotalRequests))
	lbrl.stats.AverageBucketUsage = (currentAvg*(totalRequests-1) + bucketUsage) / totalRequests
}

// evictOldestClientLocked evicts the oldest client from statistics (must be called with lock held)
func (lbrl *LeakyBucketRateLimiter) evictOldestClientLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, stats := range lbrl.stats.ClientStats {
		if oldestKey == "" || stats.FirstSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.FirstSeen
		}
	}

	if oldestKey != "" {
		delete(lbrl.stats.ClientStats, oldestKey)
	}
}

// Middleware returns the leaky bucket rate limiting middleware
func (lbrl *LeakyBucketRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create request-specific context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), lbrl.config.RequestTimeout)
		defer cancel()

		// Extract a client key
		clientKey := lbrl.config.KeyExtractor(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		var allowed bool
		var currentLevel float64
		var estimatedWait time.Duration
		var err error

		startTime := time.Now()

		// Check rate limit
		if lbrl.redisMode {
			allowed, currentLevel, estimatedWait, err = lbrl.checkRateLimitRedis(ctx, clientKey)
			if err != nil && lbrl.config.EnableFallback {
				log.Printf("[LEAKY_BUCKET] Redis error, falling back to memory: %v", err)
				lbrl.redisMode = false
				lbrl.stats.FallbackMode = true
				allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
			}
		} else {
			allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
		}

		// Record operation duration
		duration := time.Since(startTime)
		lbrl.recordMetric("rate_limit_check_duration_ms", float64(duration.Milliseconds()), map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
		})

		// Create request info
		info := lbrl.createRequestInfo(c, clientKey, allowed, currentLevel, estimatedWait)

		// Handle queueing if enabled and request is blocked
		if !allowed && lbrl.config.AllowQueueing {
			if lbrl.handleQueuedRequest(ctx, info) {
				// Retry after waiting
				if lbrl.redisMode {
					allowed, currentLevel, estimatedWait, _ = lbrl.checkRateLimitRedis(ctx, clientKey)
				} else {
					allowed, currentLevel, estimatedWait = lbrl.checkRateLimitFallback(clientKey)
				}
				// Update info with new values
				info.Allowed = allowed
				info.CurrentLevel = currentLevel
				info.EstimatedWait = estimatedWait
			} else if lbrl.config.OnQueueTimeout != nil {
				lbrl.config.OnQueueTimeout(c, info)
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
		lbrl.updateClientStats(clientKey, allowed, info.BucketUsage)

		// Set headers
		lbrl.setHeaders(c, currentLevel, info.TimeToEmpty)

		// Log event
		lbrl.logEvent(info)

		// Record metrics
		lbrl.recordMetric("requests_total", 1, map[string]string{
			"client":  clientKey,
			"allowed": strconv.FormatBool(allowed),
			"queued":  strconv.FormatBool(info.WasQueued),
		})

		if info.WasQueued {
			lbrl.recordMetric("queue_time_ms", float64(info.QueueTime.Milliseconds()), map[string]string{
				"client": clientKey,
			})
		}

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
func (lbrl *LeakyBucketRateLimiter) GetStats() interface{} {
	// Update live counters
	lbrl.stats.TotalRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.TotalRequests)
	lbrl.stats.AllowedRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.AllowedRequests)
	lbrl.stats.BlockedRequests = atomic.LoadInt64(&lbrl.stats.BaseStats.BlockedRequests)
	lbrl.stats.ActiveClients = atomic.LoadInt64(&lbrl.stats.ActiveClients)
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

// GetBucketInfo returns current bucket information for a client
func (lbrl *LeakyBucketRateLimiter) GetBucketInfo(clientKey string) *BucketInfo {
	if lbrl.redisMode {
		// For Redis mode, we'd need to query Redis
		ctx, cancel := context.WithTimeout(context.Background(), lbrl.config.RequestTimeout)
		defer cancel()

		bucketData, err := lbrl.config.RedisClient.HMGet(ctx,
			lbrl.config.RedisKeyPrefix+clientKey, "level", "last_update").Result()
		if err != nil {
			return nil
		}

		level, _ := strconv.ParseFloat(fmt.Sprintf("%v", bucketData[0]), 64)
		lastUpdate, _ := strconv.ParseInt(fmt.Sprintf("%v", bucketData[1]), 10, 64)

		return &BucketInfo{
			Level:       level,
			Capacity:    lbrl.config.Capacity,
			LeakRate:    lbrl.config.LeakRate,
			Usage:       level / float64(lbrl.config.Capacity),
			Remaining:   int(math.Max(0, float64(lbrl.config.Capacity)-level)),
			TimeToEmpty: time.Duration(level/lbrl.config.LeakRate) * time.Second,
			LastUpdate:  time.UnixMilli(lastUpdate),
		}
	} else {
		value, exists := lbrl.clients.Load(clientKey)
		if !exists {
			return nil
		}

		entry := value.(*leakyBucketEntry)
		level := float64(atomic.LoadInt64(&entry.level)) / 1000.0
		lastUpdate := atomic.LoadInt64(&entry.lastUpdate)

		return &BucketInfo{
			Level:       level,
			Capacity:    lbrl.config.Capacity,
			LeakRate:    lbrl.config.LeakRate,
			Usage:       level / float64(lbrl.config.Capacity),
			Remaining:   int(math.Max(0, float64(lbrl.config.Capacity)-level)),
			TimeToEmpty: time.Duration(level/lbrl.config.LeakRate) * time.Second,
			LastUpdate:  time.Unix(0, lastUpdate),
		}
	}
}

// ResetClient resets rate limiting for a specific client
func (lbrl *LeakyBucketRateLimiter) ResetClient(clientKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), lbrl.config.RequestTimeout)
	defer cancel()

	if lbrl.redisMode {
		lbrl.config.RedisClient.Del(ctx, lbrl.config.RedisKeyPrefix+clientKey)
	} else {
		lbrl.clients.Delete(clientKey)
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

	count := 0
	lbrl.clients.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// ResetStats resets all statistics
func (lbrl *LeakyBucketRateLimiter) ResetStats() {
	atomic.StoreInt64(&lbrl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&lbrl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.BaseStats.BlockedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.RedisErrors, 0)
	atomic.StoreInt64(&lbrl.stats.QueuedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.DroppedRequests, 0)
	atomic.StoreInt64(&lbrl.stats.QueueTimeouts, 0)
	lbrl.stats.BaseStats.StartTime = time.Now()
	lbrl.stats.AverageBucketUsage = 0

	lbrl.stats.mutex.Lock()
	lbrl.stats.ClientStats = make(map[string]*ClientStats)
	lbrl.stats.mutex.Unlock()

	// Reset LRU cache
	lbrl.clientsLRU = newLRUCache(lbrl.config.MaxTrackedClients)
}

// Stop gracefully stops the rate limiter
func (lbrl *LeakyBucketRateLimiter) Stop() {
	close(lbrl.stopChan)
}

// Type returns the type of rate limiter
func (lbrl *LeakyBucketRateLimiter) Type() RateLimiterType {
	return LeakyBucketType
}

// Algorithm returns the algorithm used
func (lbrl *LeakyBucketRateLimiter) Algorithm() Algorithm {
	return LeakyBucketAlg
}
