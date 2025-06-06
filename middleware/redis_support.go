// middleware/redis_support.go
// Purpose: Redis support for ALL 6 rate limiter types
// Compatible with existing middleware.go interfaces - NO BREAKING CHANGES

package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
	"net/http"

	"github.com/miraj90van/sdk_rate_limiter/storage"
)

// =============================================================================
// 1. REDIS BASIC RATE LIMITER (Global with Redis)
// =============================================================================

type redisBasicRateLimiter struct {
	rate       rate.Limit
	burst      int
	storage    storage.RateLimiterStorage
	stats      *BaseStats
	storageKey string
}

func newRedisBasicRateLimiter(requestsPerSecond float64, burst int, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisBasicRateLimiter{
		rate:       rate.Limit(requestsPerSecond),
		burst:      burst,
		storage:    redisStorage,
		storageKey: "global", // Single key for global limiting
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: BasicType,
		},
	}
}

func (rbl *redisBasicRateLimiter) checkGlobalRateLimit() (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()

	// Get current token state from Redis
	tokens, lastRefill, err := rbl.storage.GetTokens(ctx, rbl.storageKey)
	if err != nil {
		return false, 0, err
	}

	// Initialize if first time
	if lastRefill.IsZero() {
		tokens = rbl.burst
		lastRefill = now
	}

	// Calculate tokens to add based on elapsed time
	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(rbl.rate) / float64(time.Second))
	tokens += tokensToAdd

	if tokens > rbl.burst {
		tokens = rbl.burst
	}

	// Check if request can be allowed
	allowed := tokens > 0
	if allowed {
		tokens--
	}

	// Update Redis
	err = rbl.storage.SetTokens(ctx, rbl.storageKey, tokens, now, time.Hour)
	if err != nil {
		return false, 0, err
	}

	return allowed, tokens, nil
}

func (rbl *redisBasicRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		allowed, remaining, err := rbl.checkGlobalRateLimit()

		// Update statistics
		atomic.AddInt64(&rbl.stats.TotalRequests, 1)

		// Fail open on Redis errors
		if err != nil {
			log.Printf("Redis Basic Rate Limiter error: %v", err)
			allowed = true
			remaining = rbl.burst
		}

		if allowed {
			atomic.AddInt64(&rbl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&rbl.stats.BlockedRequests, 1)
		}

		// Set headers
		limitPerMinute := int64(float64(rbl.rate) * 60)
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Scope", "global-redis")

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Global rate limit exceeded (Redis-backed)",
				"scope": "global",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rbl *redisBasicRateLimiter) GetStats() Stats { return rbl.stats }
func (rbl *redisBasicRateLimiter) ResetStats() {
	atomic.StoreInt64(&rbl.stats.TotalRequests, 0)
	atomic.StoreInt64(&rbl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&rbl.stats.BlockedRequests, 0)
	rbl.stats.StartTime = time.Now()
}
func (rbl *redisBasicRateLimiter) Stop()                 { rbl.storage.Close() }
func (rbl *redisBasicRateLimiter) Type() RateLimiterType { return BasicType }
func (rbl *redisBasicRateLimiter) Algorithm() Algorithm  { return TokenBucketAlg }

// =============================================================================
// 2. REDIS IP RATE LIMITER (Per-IP with Redis)
// =============================================================================

type redisIPRateLimiter struct {
	rate           rate.Limit
	burst          int
	storage        storage.RateLimiterStorage
	stats          *BaseStats
	localCache     map[string]*ipCacheEntry
	cacheMu        sync.RWMutex
	cacheTTL       time.Duration
	trustedProxies []*net.IPNet
	whitelistIPs   []*net.IPNet
	blacklistIPs   []*net.IPNet
}

type ipCacheEntry struct {
	tokens     int
	lastRefill time.Time
	lastUpdate time.Time
	mu         sync.RWMutex
}

func newRedisIPRateLimiter(requestsPerSecond float64, burst int, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisIPRateLimiter{
		rate:       rate.Limit(requestsPerSecond),
		burst:      burst,
		storage:    redisStorage,
		localCache: make(map[string]*ipCacheEntry),
		cacheTTL:   1 * time.Minute, // Local cache for performance
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: IPType,
		},
	}
}

func (ril *redisIPRateLimiter) checkIPRateLimit(ip string) (bool, int, error) {
	// Try local cache first for performance
	if allowed, remaining, hit := ril.checkLocalCache(ip); hit {
		return allowed, remaining, nil
	}

	// Check Redis storage
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	storageKey := "ip:" + ip
	now := time.Now()

	tokens, lastRefill, err := ril.storage.GetTokens(ctx, storageKey)
	if err != nil {
		return false, 0, err
	}

	// Initialize if first time
	if lastRefill.IsZero() {
		tokens = ril.burst
		lastRefill = now
	}

	// Token bucket logic
	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(ril.rate) / float64(time.Second))
	tokens += tokensToAdd

	if tokens > ril.burst {
		tokens = ril.burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	// Update Redis
	err = ril.storage.SetTokens(ctx, storageKey, tokens, now, 2*time.Hour)
	if err != nil {
		return false, 0, err
	}

	// Update local cache
	ril.updateLocalCache(ip, tokens, now)

	return allowed, tokens, nil
}

func (ril *redisIPRateLimiter) checkLocalCache(ip string) (bool, int, bool) {
	ril.cacheMu.RLock()
	entry, exists := ril.localCache[ip]
	ril.cacheMu.RUnlock()

	if !exists {
		return false, 0, false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	// Check if cache entry is expired
	if now.Sub(entry.lastUpdate) > ril.cacheTTL {
		return false, 0, false
	}

	// Simple token bucket for cache
	elapsed := now.Sub(entry.lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(ril.rate) / float64(time.Second))
	entry.tokens += tokensToAdd

	if entry.tokens > ril.burst {
		entry.tokens = ril.burst
	}

	if entry.tokens > 0 {
		entry.tokens--
		entry.lastRefill = now
		entry.lastUpdate = now
		return true, entry.tokens, true
	}

	return false, 0, true
}

func (ril *redisIPRateLimiter) updateLocalCache(ip string, tokens int, now time.Time) {
	ril.cacheMu.Lock()
	defer ril.cacheMu.Unlock()

	entry, exists := ril.localCache[ip]
	if !exists {
		// Limit cache size
		if len(ril.localCache) >= 1000 {
			// Remove oldest entry
			var oldestIP string
			var oldestTime time.Time = now

			for cacheIP, cacheEntry := range ril.localCache {
				cacheEntry.mu.RLock()
				if cacheEntry.lastUpdate.Before(oldestTime) {
					oldestTime = cacheEntry.lastUpdate
					oldestIP = cacheIP
				}
				cacheEntry.mu.RUnlock()
			}

			if oldestIP != "" {
				delete(ril.localCache, oldestIP)
			}
		}

		entry = &ipCacheEntry{}
		ril.localCache[ip] = entry
	}

	entry.mu.Lock()
	entry.tokens = tokens
	entry.lastRefill = now
	entry.lastUpdate = now
	entry.mu.Unlock()
}

func (ril *redisIPRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		allowed, remaining, err := ril.checkIPRateLimit(clientIP)

		// Update statistics
		atomic.AddInt64(&ril.stats.TotalRequests, 1)

		// Fail open on Redis errors
		if err != nil {
			log.Printf("Redis IP Rate Limiter error: %v", err)
			allowed = true
			remaining = ril.burst
		}

		if allowed {
			atomic.AddInt64(&ril.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&ril.stats.BlockedRequests, 1)
		}

		// Set headers
		limitPerMinute := int64(float64(ril.rate) * 60)
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Scope", "per-ip-redis")
		c.Header("X-RateLimit-IP", clientIP)

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "IP rate limit exceeded (Redis-backed)",
				"ip":    clientIP,
				"scope": "per-ip",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (ril *redisIPRateLimiter) GetStats() Stats { return ril.stats }
func (ril *redisIPRateLimiter) ResetStats() {
	atomic.StoreInt64(&ril.stats.TotalRequests, 0)
	atomic.StoreInt64(&ril.stats.AllowedRequests, 0)
	atomic.StoreInt64(&ril.stats.BlockedRequests, 0)
	ril.stats.StartTime = time.Now()
}
func (ril *redisIPRateLimiter) Stop()                 { ril.storage.Close() }
func (ril *redisIPRateLimiter) Type() RateLimiterType { return IPType }
func (ril *redisIPRateLimiter) Algorithm() Algorithm  { return TokenBucketAlg }

// =============================================================================
// 3. REDIS USER RATE LIMITER (Per-User with Redis)
// =============================================================================

type redisUserRateLimiter struct {
	rate          rate.Limit
	burst         int
	storage       storage.RateLimiterStorage
	stats         *BaseStats
	localCache    map[string]*ipCacheEntry
	cacheMu       sync.RWMutex
	cacheTTL      time.Duration
	userIDHeaders []string
	fallbackToIP  bool
}

func newRedisUserRateLimiter(requestsPerSecond float64, burst int, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisUserRateLimiter{
		rate:          rate.Limit(requestsPerSecond),
		burst:         burst,
		storage:       redisStorage,
		localCache:    make(map[string]*ipCacheEntry),
		cacheTTL:      1 * time.Minute,
		userIDHeaders: []string{"X-User-ID", "User-ID", "X-UID"},
		fallbackToIP:  true,
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: UserType,
		},
	}
}

func (rul *redisUserRateLimiter) extractUserID(c *gin.Context) string {
	// Try each header in order
	for _, header := range rul.userIDHeaders {
		userID := c.GetHeader(header)
		if userID != "" {
			return "user:" + userID
		}
	}

	// Fallback to IP if enabled
	if rul.fallbackToIP {
		return "anonymous:" + c.ClientIP()
	}

	return ""
}

func (rul *redisUserRateLimiter) checkUserRateLimit(userKey string) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()

	tokens, lastRefill, err := rul.storage.GetTokens(ctx, userKey)
	if err != nil {
		return false, 0, err
	}

	if lastRefill.IsZero() {
		tokens = rul.burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(rul.rate) / float64(time.Second))
	tokens += tokensToAdd

	if tokens > rul.burst {
		tokens = rul.burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	err = rul.storage.SetTokens(ctx, userKey, tokens, now, 24*time.Hour) // Users active longer
	if err != nil {
		return false, 0, err
	}

	return allowed, tokens, nil
}

func (rul *redisUserRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userKey := rul.extractUserID(c)

		if userKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to identify user for rate limiting",
				"scope": "per-user",
			})
			c.Abort()
			return
		}

		allowed, remaining, err := rul.checkUserRateLimit(userKey)

		atomic.AddInt64(&rul.stats.TotalRequests, 1)

		if err != nil {
			log.Printf("Redis User Rate Limiter error: %v", err)
			allowed = true
			remaining = rul.burst
		}

		if allowed {
			atomic.AddInt64(&rul.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&rul.stats.BlockedRequests, 1)
		}

		limitPerMinute := int64(float64(rul.rate) * 60)
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Scope", "per-user-redis")
		c.Header("X-RateLimit-User", userKey)

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "User rate limit exceeded (Redis-backed)",
				"user":  userKey,
				"scope": "per-user",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rul *redisUserRateLimiter) GetStats() Stats { return rul.stats }
func (rul *redisUserRateLimiter) ResetStats() {
	atomic.StoreInt64(&rul.stats.TotalRequests, 0)
	atomic.StoreInt64(&rul.stats.AllowedRequests, 0)
	atomic.StoreInt64(&rul.stats.BlockedRequests, 0)
	rul.stats.StartTime = time.Now()
}
func (rul *redisUserRateLimiter) Stop()                 { rul.storage.Close() }
func (rul *redisUserRateLimiter) Type() RateLimiterType { return UserType }
func (rul *redisUserRateLimiter) Algorithm() Algorithm  { return TokenBucketAlg }

// =============================================================================
// 4. REDIS ADVANCED RATE LIMITER (Custom Key with Redis)
// =============================================================================

type redisAdvancedRateLimiter struct {
	rate           rate.Limit
	burst          int
	storage        storage.RateLimiterStorage
	stats          *BaseStats
	customKeyFunc  func(*gin.Context) string
	keyDescription string
}

func newRedisAdvancedRateLimiter(requestsPerSecond float64, burst int, keyFunc func(*gin.Context) string, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisAdvancedRateLimiter{
		rate:           rate.Limit(requestsPerSecond),
		burst:          burst,
		storage:        redisStorage,
		customKeyFunc:  keyFunc,
		keyDescription: "custom",
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: AdvancedType,
		},
	}
}

func (ral *redisAdvancedRateLimiter) checkAdvancedRateLimit(clientKey string) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()

	tokens, lastRefill, err := ral.storage.GetTokens(ctx, clientKey)
	if err != nil {
		return false, 0, err
	}

	if lastRefill.IsZero() {
		tokens = ral.burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(ral.rate) / float64(time.Second))
	tokens += tokensToAdd

	if tokens > ral.burst {
		tokens = ral.burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	err = ral.storage.SetTokens(ctx, clientKey, tokens, now, 2*time.Hour)
	if err != nil {
		return false, 0, err
	}

	return allowed, tokens, nil
}

func (ral *redisAdvancedRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientKey := ral.customKeyFunc(c)

		if clientKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to extract client key for rate limiting",
				"scope": "advanced",
			})
			c.Abort()
			return
		}

		allowed, remaining, err := ral.checkAdvancedRateLimit(clientKey)

		atomic.AddInt64(&ral.stats.TotalRequests, 1)

		if err != nil {
			log.Printf("Redis Advanced Rate Limiter error: %v", err)
			allowed = true
			remaining = ral.burst
		}

		if allowed {
			atomic.AddInt64(&ral.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&ral.stats.BlockedRequests, 1)
		}

		limitPerMinute := int64(float64(ral.rate) * 60)
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Scope", "advanced-redis")
		c.Header("X-RateLimit-Client", clientKey)
		c.Header("X-RateLimit-Key-Type", ral.keyDescription)

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":    "Advanced rate limit exceeded (Redis-backed)",
				"client":   clientKey,
				"key_type": ral.keyDescription,
				"scope":    "advanced",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (ral *redisAdvancedRateLimiter) GetStats() Stats { return ral.stats }
func (ral *redisAdvancedRateLimiter) ResetStats() {
	atomic.StoreInt64(&ral.stats.TotalRequests, 0)
	atomic.StoreInt64(&ral.stats.AllowedRequests, 0)
	atomic.StoreInt64(&ral.stats.BlockedRequests, 0)
	ral.stats.StartTime = time.Now()
}
func (ral *redisAdvancedRateLimiter) Stop()                 { ral.storage.Close() }
func (ral *redisAdvancedRateLimiter) Type() RateLimiterType { return AdvancedType }
func (ral *redisAdvancedRateLimiter) Algorithm() Algorithm  { return TokenBucketAlg }

// =============================================================================
// 5. REDIS SLIDING WINDOW RATE LIMITER
// =============================================================================

type redisSlidingWindowLimiter struct {
	limit         int
	window        time.Duration
	storage       storage.RateLimiterStorage
	stats         *BaseStats
	clientKeyFunc func(*gin.Context) string
}

func newRedisSlidingWindowLimiter(limit int, window time.Duration, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisSlidingWindowLimiter{
		limit:   limit,
		window:  window,
		storage: redisStorage,
		clientKeyFunc: func(c *gin.Context) string {
			return c.ClientIP()
		},
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: SlidingWindowType,
		},
	}
}

func (rswl *redisSlidingWindowLimiter) checkSlidingWindowLimit(clientKey string) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now()

	// Add current request to sliding window
	err := rswl.storage.AddRequest(ctx, clientKey, now, rswl.window)
	if err != nil {
		return false, 0, err
	}

	// Get current count in window
	count, err := rswl.storage.GetRequestCount(ctx, clientKey, rswl.window)
	if err != nil {
		return false, 0, err
	}

	allowed := count <= rswl.limit
	remaining := rswl.limit - count
	if remaining < 0 {
		remaining = 0
	}

	return allowed, remaining, nil
}

func (rswl *redisSlidingWindowLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientKey := rswl.clientKeyFunc(c)

		allowed, remaining, err := rswl.checkSlidingWindowLimit(clientKey)

		atomic.AddInt64(&rswl.stats.TotalRequests, 1)

		if err != nil {
			log.Printf("Redis Sliding Window Rate Limiter error: %v", err)
			allowed = true
			remaining = rswl.limit
		}

		if allowed {
			atomic.AddInt64(&rswl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&rswl.stats.BlockedRequests, 1)
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(rswl.limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Window", rswl.window.String())
		c.Header("X-RateLimit-Scope", "sliding-window-redis")
		c.Header("X-RateLimit-Algorithm", "sliding-window")

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":     "Sliding window rate limit exceeded (Redis-backed)",
				"client":    clientKey,
				"limit":     rswl.limit,
				"window":    rswl.window.String(),
				"algorithm": "sliding-window",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rswl *redisSlidingWindowLimiter) GetStats() Stats { return rswl.stats }
func (rswl *redisSlidingWindowLimiter) ResetStats() {
	atomic.StoreInt64(&rswl.stats.TotalRequests, 0)
	atomic.StoreInt64(&rswl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&rswl.stats.BlockedRequests, 0)
	rswl.stats.StartTime = time.Now()
}
func (rswl *redisSlidingWindowLimiter) Stop()                 { rswl.storage.Close() }
func (rswl *redisSlidingWindowLimiter) Type() RateLimiterType { return SlidingWindowType }
func (rswl *redisSlidingWindowLimiter) Algorithm() Algorithm  { return SlidingWindowAlg }

// =============================================================================
// 6. REDIS TOKEN BUCKET RATE LIMITER (with Wait support)
// =============================================================================

type redisTokenBucketLimiter struct {
	rate          rate.Limit
	burst         int
	waitTimeout   time.Duration
	storage       storage.RateLimiterStorage
	stats         *BaseStats
	clientKeyFunc func(*gin.Context) string
}

func newRedisTokenBucketLimiter(requestsPerSecond float64, burst int, waitTimeout time.Duration, redisStorage storage.RateLimiterStorage) RateLimiter {
	return &redisTokenBucketLimiter{
		rate:        rate.Limit(requestsPerSecond),
		burst:       burst,
		waitTimeout: waitTimeout,
		storage:     redisStorage,
		clientKeyFunc: func(c *gin.Context) string {
			return c.ClientIP()
		},
		stats: &BaseStats{
			StartTime:   time.Now(),
			LimiterType: TokenBucketType,
		},
	}
}

func (rtbl *redisTokenBucketLimiter) checkTokenBucketLimit(clientKey string) (bool, int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	now := start

	tokens, lastRefill, err := rtbl.storage.GetTokens(ctx, clientKey)
	if err != nil {
		return false, 0, 0, err
	}

	if lastRefill.IsZero() {
		tokens = rtbl.burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * float64(rtbl.rate) / float64(time.Second))
	tokens += tokensToAdd

	if tokens > rtbl.burst {
		tokens = rtbl.burst
	}

	// If no tokens available, try waiting
	if tokens <= 0 && rtbl.waitTimeout > 0 {
		waitTime := time.Duration(float64(time.Second) / float64(rtbl.rate))
		if waitTime <= rtbl.waitTimeout {
			time.Sleep(waitTime)
			tokens = 1 // Grant one token after wait
		}
	}

	allowed := tokens > 0
	waitTime := time.Since(start)

	if allowed {
		tokens--
	}

	err = rtbl.storage.SetTokens(ctx, clientKey, tokens, now, time.Hour)
	if err != nil {
		return false, 0, waitTime, err
	}

	return allowed, tokens, waitTime, nil
}

func (rtbl *redisTokenBucketLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientKey := rtbl.clientKeyFunc(c)

		allowed, remaining, waitTime, err := rtbl.checkTokenBucketLimit(clientKey)

		atomic.AddInt64(&rtbl.stats.TotalRequests, 1)

		if err != nil {
			log.Printf("Redis Token Bucket Rate Limiter error: %v", err)
			allowed = true
			remaining = rtbl.burst
		}

		if allowed {
			atomic.AddInt64(&rtbl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&rtbl.stats.BlockedRequests, 1)
		}

		limitPerMinute := int64(float64(rtbl.rate) * 60)
		c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Scope", "token-bucket-redis")
		c.Header("X-RateLimit-Algorithm", "token-bucket")
		c.Header("X-RateLimit-Burst", strconv.Itoa(rtbl.burst))

		if waitTime > 0 {
			c.Header("X-RateLimit-Wait-Time", strconv.FormatInt(int64(waitTime.Milliseconds()), 10))
		}

		if !allowed {
			response := gin.H{
				"error":     "Token bucket rate limit exceeded (Redis-backed)",
				"client":    clientKey,
				"algorithm": "token-bucket",
			}

			if waitTime > 0 {
				response["message"] = "Request timed out waiting for available tokens"
				response["wait_time"] = int64(waitTime.Milliseconds())
			} else {
				response["message"] = "No tokens available"
			}

			c.JSON(http.StatusTooManyRequests, response)
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rtbl *redisTokenBucketLimiter) GetStats() Stats { return rtbl.stats }
func (rtbl *redisTokenBucketLimiter) ResetStats() {
	atomic.StoreInt64(&rtbl.stats.TotalRequests, 0)
	atomic.StoreInt64(&rtbl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&rtbl.stats.BlockedRequests, 0)
	rtbl.stats.StartTime = time.Now()
}
func (rtbl *redisTokenBucketLimiter) Stop()                 { rtbl.storage.Close() }
func (rtbl *redisTokenBucketLimiter) Type() RateLimiterType { return TokenBucketType }
func (rtbl *redisTokenBucketLimiter) Algorithm() Algorithm  { return TokenBucketAlg }

// =============================================================================
// CONVENIENCE FUNCTIONS - STANDALONE REDIS CLIENT
// =============================================================================

// 1. Basic Rate Limiter with Redis (SDK creates Redis client)
func BasicRateLimitWithRedis(requestsPerSecond float64, burst int, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:basic:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for basic rate limiter: %v", err))
	}

	limiter := newRedisBasicRateLimiter(requestsPerSecond, burst, redisStorage)
	return limiter.Middleware()
}

// 2. IP Rate Limiter with Redis
func IPRateLimitWithRedis(requestsPerSecond float64, burst int, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:ip:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for IP rate limiter: %v", err))
	}

	limiter := newRedisIPRateLimiter(requestsPerSecond, burst, redisStorage)
	return limiter.Middleware()
}

// 3. User Rate Limiter with Redis
func UserRateLimitWithRedis(requestsPerSecond float64, burst int, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:user:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for user rate limiter: %v", err))
	}

	limiter := newRedisUserRateLimiter(requestsPerSecond, burst, redisStorage)
	return limiter.Middleware()
}

// 4. Advanced Rate Limiter with Redis
func AdvancedRateLimitWithRedis(requestsPerSecond float64, burst int, keyFunc func(*gin.Context) string, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:advanced:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for advanced rate limiter: %v", err))
	}

	limiter := newRedisAdvancedRateLimiter(requestsPerSecond, burst, keyFunc, redisStorage)
	return limiter.Middleware()
}

// 5. Sliding Window Rate Limiter with Redis
func SlidingWindowRateLimitWithRedis(limit int, window time.Duration, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:sliding:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for sliding window rate limiter: %v", err))
	}

	limiter := newRedisSlidingWindowLimiter(limit, window, redisStorage)
	return limiter.Middleware()
}

// 6. Token Bucket Rate Limiter with Redis
func TokenBucketRateLimitWithRedis(requestsPerSecond float64, burst int, waitTimeout time.Duration, redisAddr, redisPassword string) gin.HandlerFunc {
	redisStorage, err := storage.NewRedisStorage(&storage.RedisConfig{
		Addr:      redisAddr,
		Password:  redisPassword,
		KeyPrefix: "ratelimit:token:",
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis storage for token bucket rate limiter: %v", err))
	}

	limiter := newRedisTokenBucketLimiter(requestsPerSecond, burst, waitTimeout, redisStorage)
	return limiter.Middleware()
}

// =============================================================================
// CONVENIENCE FUNCTIONS - SHARED REDIS CLIENT (RECOMMENDED)
// =============================================================================

// 1. Basic Rate Limiter with Shared Redis Client
func SharedRedisBasicRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient redis.UniversalClient) gin.HandlerFunc {
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:basic:")
	limiter := newRedisBasicRateLimiter(requestsPerSecond, burst, redisStorage)
	return limiter.Middleware()
}

//// 2. IP Rate Limiter with Shared Redis Client
//func SharedRedisIPRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient redis.UniversalClient) gin.HandlerFunc {
//	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:ip:")
//	limiter := newRedisIPRateLimiter(requestsPerSecond, burst, redisStorage)
//	return limiter.Middleware()
//}

//// 3. User Rate Limiter with Shared Redis Client
//func SharedRedisUserRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient redis.UniversalClient) gin.HandlerFunc {
//	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:user:")
//	limiter := newRedisUserRateLimiter(requestsPerSecond, burst, redisStorage)
//	return limiter.Middleware()
//}

//// 4. Advanced Rate Limiter with Shared Redis Client
//func SharedRedisAdvancedRateLimitMiddleware(requestsPerSecond float64, burst int, keyFunc func(*gin.Context) string, redisClient redis.UniversalClient) gin.HandlerFunc {
//	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:advanced:")
//	limiter := newRedisAdvancedRateLimiter(requestsPerSecond, burst, keyFunc, redisStorage)
//	return limiter.Middleware()
//}

// 5. Sliding Window Rate Limiter with Shared Redis Client
func SharedRedisSlidingWindowRateLimitMiddleware(limit int, window time.Duration, redisClient redis.UniversalClient) gin.HandlerFunc {
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:sliding:")
	limiter := newRedisSlidingWindowLimiter(limit, window, redisStorage)
	return limiter.Middleware()
}

// 6. Token Bucket Rate Limiter with Shared Redis Client
func SharedRedisTokenBucketRateLimitMiddleware(requestsPerSecond float64, burst int, waitTimeout time.Duration, redisClient redis.UniversalClient) gin.HandlerFunc {
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:token:")
	limiter := newRedisTokenBucketLimiter(requestsPerSecond, burst, waitTimeout, redisStorage)
	return limiter.Middleware()
}

// =============================================================================
// LAYERED PROTECTION SETUP FUNCTION
// =============================================================================

// SetupMultiLayerRedisRateLimiting configures all 6 rate limiters with shared Redis
func SetupMultiLayerRedisRateLimiting(r *gin.Engine, redisClient redis.UniversalClient) {
	log.Println("🛡️  Setting up multi-layer rate limiting with Redis:")

	// Layer 1: Global protection (Basic)
	log.Println("  - Layer 1: Global Basic (10k req/sec)")
	r.Use(SharedRedisBasicRateLimitMiddleware(10000, 1000, redisClient))

	// Layer 2: Per-IP fairness
	log.Println("  - Layer 2: Per-IP (1k req/sec per IP)")
	r.Use(SharedRedisIPRateLimitMiddleware(1000, 100, redisClient))

	log.Println("  - Additional layers applied to specific route groups")
}

// SetupSpecificGroupRateLimiting applies specific rate limiters to route groups
func SetupSpecificGroupRateLimiting(r *gin.Engine, redisClient redis.UniversalClient) {
	// User-based rate limiting for auth routes
	auth := r.Group("/api/auth")
	auth.Use(SharedRedisUserRateLimitMiddleware(500, 50, redisClient))

	// Advanced tenant-based rate limiting
	tenant := r.Group("/api/tenant")
	tenant.Use(SharedRedisAdvancedRateLimitMiddleware(2000, 200, func(c *gin.Context) string {
		tenantID := c.GetHeader("X-Tenant-ID")
		if tenantID == "" {
			return "unknown:" + c.ClientIP()
		}
		return "tenant:" + tenantID
	}, redisClient))

	// Sliding window for critical endpoints
	critical := r.Group("/api/critical")
	critical.Use(SharedRedisSlidingWindowRateLimitMiddleware(100, time.Hour, redisClient))

	// Token bucket with waiting for premium endpoints
	premium := r.Group("/api/premium")
	premium.Use(SharedRedisTokenBucketRateLimitMiddleware(1000, 100, 2*time.Second, redisClient))
}

// =============================================================================
// EXAMPLE: IP RATE LIMITER WRAPPER
// Shows how Redis wrapper falls back to existing ip_rate_limiter.go
// =============================================================================

func SharedRedisIPRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient redis.UniversalClient) gin.HandlerFunc {
	// Create Redis storage once
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:ip:")

	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Try Redis-based rate limiting
		allowed, remaining, err := checkIPRateLimitWithRedis(redisStorage, clientIP, requestsPerSecond, burst)

		if err != nil {
			// Redis failed - fallback to existing memory-based middleware
			log.Printf("Redis IP rate limiter failed: %v, falling back to memory", err)

			// ✅ CALL EXISTING MIDDLEWARE FROM ip_rate_limiter.go
			existingMiddleware := IPRateLimitMiddleware(requestsPerSecond, burst)
			existingMiddleware(c)
			return
		}

		// Redis succeeded - handle result ourselves
		if !allowed {
			c.JSON(429, gin.H{
				"error": "IP rate limit exceeded (Redis-backed)",
				"ip":    clientIP,
				"scope": "per-ip",
			})
			c.Abort()
			return
		}

		// Set Redis-specific headers
		setRedisIPHeaders(c, requestsPerSecond, remaining, clientIP)
		c.Next()
	}
}

// Helper function: Redis-based IP rate limiting logic
func checkIPRateLimitWithRedis(storage storage.RateLimiterStorage, ip string, requestsPerSecond float64, burst int) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	storageKey := "ip:" + ip
	now := time.Now()

	// Get current token state from Redis
	tokens, lastRefill, err := storage.GetTokens(ctx, storageKey)
	if err != nil {
		return false, 0, err // This will trigger fallback to existing middleware
	}

	// Token bucket logic (same as existing middleware)
	if lastRefill.IsZero() {
		tokens = burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * requestsPerSecond / float64(time.Second))
	tokens += tokensToAdd

	if tokens > burst {
		tokens = burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	// Update Redis
	err = storage.SetTokens(ctx, storageKey, tokens, now, 2*time.Hour)
	if err != nil {
		return false, 0, err // This will trigger fallback
	}

	return allowed, tokens, nil
}

func setRedisIPHeaders(c *gin.Context, requestsPerSecond float64, remaining int, ip string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "per-ip-redis")
	c.Header("X-RateLimit-IP", ip)
	c.Header("X-RateLimit-Backend", "redis") // Indicates Redis was used
}

// =============================================================================
// EXAMPLE: USER RATE LIMITER WRAPPER
// Shows fallback to existing user_rate_limiter.go
// =============================================================================

func SharedRedisUserRateLimitMiddleware(requestsPerSecond float64, burst int, redisClient redis.UniversalClient) gin.HandlerFunc {
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:user:")

	return func(c *gin.Context) {
		// Extract user ID (reuse existing logic pattern)
		userID := extractUserID(c)
		if userID == "" {
			userID = "anonymous:" + c.ClientIP()
		}

		// Try Redis
		allowed, remaining, err := checkUserRateLimitWithRedis(redisStorage, userID, requestsPerSecond, burst)

		if err != nil {
			// Fallback to existing middleware
			log.Printf("Redis User rate limiter failed: %v, falling back to memory", err)

			// ✅ CALL EXISTING MIDDLEWARE FROM user_rate_limiter.go
			existingMiddleware := UserRateLimitMiddleware(requestsPerSecond, burst)
			existingMiddleware(c)
			return
		}

		if !allowed {
			c.JSON(429, gin.H{
				"error": "User rate limit exceeded (Redis-backed)",
				"user":  userID,
				"scope": "per-user",
			})
			c.Abort()
			return
		}

		setRedisUserHeaders(c, requestsPerSecond, remaining, userID)
		c.Next()
	}
}

// Helper functions
func extractUserID(c *gin.Context) string {
	headers := []string{"X-User-ID", "User-ID", "X-UID"}
	for _, header := range headers {
		if userID := c.GetHeader(header); userID != "" {
			return "user:" + userID
		}
	}
	return ""
}

func checkUserRateLimitWithRedis(storage storage.RateLimiterStorage, userID string, requestsPerSecond float64, burst int) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Same token bucket logic as IP, but with different TTL
	now := time.Now()
	tokens, lastRefill, err := storage.GetTokens(ctx, userID)
	if err != nil {
		return false, 0, err
	}

	if lastRefill.IsZero() {
		tokens = burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * requestsPerSecond / float64(time.Second))
	tokens += tokensToAdd

	if tokens > burst {
		tokens = burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	err = storage.SetTokens(ctx, userID, tokens, now, 24*time.Hour) // Longer TTL for users
	if err != nil {
		return false, 0, err
	}

	return allowed, tokens, nil
}

func setRedisUserHeaders(c *gin.Context, requestsPerSecond float64, remaining int, userID string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "per-user-redis")
	c.Header("X-RateLimit-User", userID)
	c.Header("X-RateLimit-Backend", "redis")
}

// =============================================================================
// EXAMPLE: ADVANCED RATE LIMITER WRAPPER
// Shows fallback to existing advance_rate_limiter.go
// =============================================================================

func SharedRedisAdvancedRateLimitMiddleware(requestsPerSecond float64, burst int, keyFunc func(*gin.Context) string, redisClient redis.UniversalClient) gin.HandlerFunc {
	redisStorage := storage.NewRedisStorageFromClient(redisClient, "ratelimit:advanced:")

	return func(c *gin.Context) {
		clientKey := keyFunc(c)
		if clientKey == "" {
			c.JSON(400, gin.H{"error": "Unable to extract client key"})
			c.Abort()
			return
		}

		// Try Redis
		allowed, remaining, err := checkAdvancedRateLimitWithRedis(redisStorage, clientKey, requestsPerSecond, burst)

		if err != nil {
			// Fallback to existing middleware
			log.Printf("Redis Advanced rate limiter failed: %v, falling back to memory", err)

			// ✅ CALL EXISTING MIDDLEWARE FROM advance_rate_limiter.go
			config := &AdvancedRateLimiterConfig{
				Rate:          rate.Limit(requestsPerSecond),
				Burst:         burst,
				CustomKeyFunc: keyFunc,
				EnableHeaders: true,
			}
			existingLimiter := NewAdvancedRateLimiter(config)
			existingMiddleware := existingLimiter.Middleware()
			existingMiddleware(c)
			return
		}

		if !allowed {
			c.JSON(429, gin.H{
				"error":  "Advanced rate limit exceeded (Redis-backed)",
				"client": clientKey,
				"scope":  "advanced",
			})
			c.Abort()
			return
		}

		setRedisAdvancedHeaders(c, requestsPerSecond, remaining, clientKey)
		c.Next()
	}
}

func checkAdvancedRateLimitWithRedis(storage storage.RateLimiterStorage, clientKey string, requestsPerSecond float64, burst int) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Same token bucket logic
	now := time.Now()
	tokens, lastRefill, err := storage.GetTokens(ctx, clientKey)
	if err != nil {
		return false, 0, err
	}

	if lastRefill.IsZero() {
		tokens = burst
		lastRefill = now
	}

	elapsed := now.Sub(lastRefill)
	tokensToAdd := int(float64(elapsed) * requestsPerSecond / float64(time.Second))
	tokens += tokensToAdd

	if tokens > burst {
		tokens = burst
	}

	allowed := tokens > 0
	if allowed {
		tokens--
	}

	err = storage.SetTokens(ctx, clientKey, tokens, now, 2*time.Hour)
	return allowed, tokens, err
}

func setRedisAdvancedHeaders(c *gin.Context, requestsPerSecond float64, remaining int, clientKey string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "advanced-redis")
	c.Header("X-RateLimit-Client", clientKey)
	c.Header("X-RateLimit-Backend", "redis")
}
