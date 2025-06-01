// token_bucket_rate_limiter_middleware.go
// Purpose: TOKEN BUCKET rate limiting with wait/timeout capability
// Use case: When you need rate limiting with graceful waiting instead of immediate rejection

package middleware

import (
	"context"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

// TokenBucketConfig for token bucket rate limiting
type TokenBucketConfig struct {
	Rate               rate.Limit                // Token refill rate (requests per second)
	Burst              int                       // Bucket capacity (max tokens)
	MaxClients         int                       // Maximum number of clients to track
	WaitTimeout        time.Duration             // Maximum time to wait for tokens (0 = no waiting)
	CleanupInterval    time.Duration             // How often to cleanup old client entries
	ClientTTL          time.Duration             // Time to live for inactive client entries
	EnableHeaders      bool                      // Include rate limit headers
	EnableLogging      bool                      // Enable logging
	ClientKeyFunc      func(*gin.Context) string // Function to extract client key
	ErrorMessage       string                    // Custom error message
	ErrorResponse      interface{}               // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *TokenBucketRequestInfo)
	OnRequestProcessed func(*gin.Context, *TokenBucketRequestInfo, bool)
	OnWaitTimeout      func(*gin.Context, *TokenBucketRequestInfo) // Called when wait times out
}

// TokenBucketRequestInfo contains information about token bucket request
type TokenBucketRequestInfo struct {
	ClientKey       string
	IP              string
	Path            string
	Method          string
	Timestamp       time.Time
	Allowed         bool
	WaitTime        time.Duration // Time spent waiting for tokens
	Remaining       int           // Estimated remaining tokens
	TimeoutOccurred bool          // Whether wait timed out
}

// TokenBucketEntry represents a token bucket for a specific client
type TokenBucketEntry struct {
	limiter      *rate.Limiter
	lastAccess   time.Time
	created      time.Time
	waitCount    int64 // Number of requests that had to wait
	timeoutCount int64 // Number of requests that timed out
}

// TokenBucketLimiter manages token bucket rate limiting
type TokenBucketLimiter struct {
	limiters      map[string]*TokenBucketEntry
	mu            sync.RWMutex
	config        *TokenBucketConfig
	stats         *TokenBucketStats
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// TokenBucketStats holds statistics about token bucket rate limiting
type TokenBucketStats struct {
	TotalClients    int64
	ActiveClients   int64
	TotalRequests   int64
	AllowedRequests int64
	BlockedRequests int64
	WaitedRequests  int64 // Requests that had to wait but succeeded
	TimeoutRequests int64 // Requests that timed out while waiting
	TotalWaitTime   int64 // Total time spent waiting (in nanoseconds)
	StartTime       time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(config *TokenBucketConfig) *TokenBucketLimiter {
	if config == nil {
		config = DefaultTokenBucketConfig()
	}

	// Set defaults
	if config.MaxClients <= 0 {
		config.MaxClients = 10000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.ClientTTL <= 0 {
		config.ClientTTL = 1 * time.Hour
	}
	if config.ClientKeyFunc == nil {
		config.ClientKeyFunc = func(c *gin.Context) string {
			return c.ClientIP() // Default to IP-based
		}
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Rate limit exceeded"
	}

	limiter := &TokenBucketLimiter{
		limiters:    make(map[string]*TokenBucketEntry),
		config:      config,
		stopCleanup: make(chan struct{}),
		stats: &TokenBucketStats{
			StartTime: time.Now(),
		},
	}

	// Start cleanup goroutine
	limiter.startCleanup()

	return limiter
}

// DefaultTokenBucketConfig returns default configuration
func DefaultTokenBucketConfig() *TokenBucketConfig {
	return &TokenBucketConfig{
		Rate:            rate.Limit(10), // 10 tokens per second
		Burst:           5,              // 5 token bucket capacity
		MaxClients:      10000,          // Track up to 10k clients
		WaitTimeout:     time.Second,    // Wait up to 1 second for tokens
		CleanupInterval: 5 * time.Minute,
		ClientTTL:       1 * time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded",
	}
}

// startCleanup starts the cleanup goroutine
func (tbl *TokenBucketLimiter) startCleanup() {
	tbl.cleanupTicker = time.NewTicker(tbl.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-tbl.cleanupTicker.C:
				tbl.cleanup()
			case <-tbl.stopCleanup:
				tbl.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old and inactive client entries
func (tbl *TokenBucketLimiter) cleanup() {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-tbl.config.ClientTTL)
	removed := 0

	for clientKey, entry := range tbl.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(tbl.limiters, clientKey)
			removed++
		}
	}

	// If still over max clients, remove oldest entries
	if len(tbl.limiters) > tbl.config.MaxClients {
		type clientEntry struct {
			clientKey string
			entry     *TokenBucketEntry
		}

		var entries []clientEntry
		for clientKey, entry := range tbl.limiters {
			entries = append(entries, clientEntry{clientKey, entry})
		}

		// Sort by last access time (oldest first)
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].entry.lastAccess.After(entries[j].entry.lastAccess) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}

		// Remove oldest entries until we're under the limit
		toRemove := len(tbl.limiters) - tbl.config.MaxClients
		for i := 0; i < toRemove && i < len(entries); i++ {
			delete(tbl.limiters, entries[i].clientKey)
			removed++
		}
	}

	if tbl.config.EnableLogging && removed > 0 {
		log.Printf("Token Bucket Limiter: Cleaned up %d client entries, active clients: %d", removed, len(tbl.limiters))
	}

	// Update stats
	atomic.StoreInt64(&tbl.stats.ActiveClients, int64(len(tbl.limiters)))
}

// Stop stops the cleanup goroutine
func (tbl *TokenBucketLimiter) Stop() {
	close(tbl.stopCleanup)
}

// getLimiterForClient gets or creates a token bucket for the specific client
func (tbl *TokenBucketLimiter) getLimiterForClient(clientKey string) *rate.Limiter {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	entry, exists := tbl.limiters[clientKey]
	if !exists {
		// Check if we're at max capacity
		if len(tbl.limiters) >= tbl.config.MaxClients {
			// Find and remove the oldest entry
			var oldestClientKey string
			var oldestTime time.Time = time.Now()

			for entryClientKey, entryData := range tbl.limiters {
				if entryData.lastAccess.Before(oldestTime) {
					oldestTime = entryData.lastAccess
					oldestClientKey = entryClientKey
				}
			}

			if oldestClientKey != "" {
				delete(tbl.limiters, oldestClientKey)
			}
		}

		// Create new token bucket for this client
		limiter := rate.NewLimiter(tbl.config.Rate, tbl.config.Burst)
		entry = &TokenBucketEntry{
			limiter:    limiter,
			lastAccess: time.Now(),
			created:    time.Now(),
		}
		tbl.limiters[clientKey] = entry

		// Update stats
		atomic.AddInt64(&tbl.stats.TotalClients, 1)
	} else {
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

// updateTokenBucketStats updates statistics for specific client
func (tbl *TokenBucketLimiter) updateTokenBucketStats(clientKey string, allowed bool, waitTime time.Duration, timedOut bool) {
	tbl.mu.RLock()
	entry := tbl.limiters[clientKey]
	tbl.mu.RUnlock()

	if entry != nil {
		if waitTime > 0 {
			atomic.AddInt64(&entry.waitCount, 1)
		}
		if timedOut {
			atomic.AddInt64(&entry.timeoutCount, 1)
		}
	}

	// Update global stats
	atomic.AddInt64(&tbl.stats.TotalRequests, 1)
	if allowed {
		atomic.AddInt64(&tbl.stats.AllowedRequests, 1)
	} else {
		atomic.AddInt64(&tbl.stats.BlockedRequests, 1)
	}

	if waitTime > 0 {
		if allowed {
			atomic.AddInt64(&tbl.stats.WaitedRequests, 1)
		}
		atomic.AddInt64(&tbl.stats.TotalWaitTime, int64(waitTime))
	}

	if timedOut {
		atomic.AddInt64(&tbl.stats.TimeoutRequests, 1)
	}
}

// estimateRemainingTokens estimates remaining tokens for specific client
func (tbl *TokenBucketLimiter) estimateRemainingTokens(clientKey string) int {
	tbl.mu.RLock()
	entry, exists := tbl.limiters[clientKey]
	tbl.mu.RUnlock()

	if !exists {
		return tbl.config.Burst
	}

	// Use reservation to peek at current state
	reservation := entry.limiter.Reserve()
	if !reservation.OK() {
		reservation.Cancel()
		return 0
	}

	delay := reservation.Delay()
	reservation.Cancel()

	if delay <= 0 {
		return tbl.config.Burst - 1
	}

	return 0
}

// waitForToken waits for a token to become available or times out
func (tbl *TokenBucketLimiter) waitForToken(limiter *rate.Limiter, timeout time.Duration) (bool, time.Duration, bool) {
	if timeout <= 0 {
		// No waiting, immediate check
		return limiter.Allow(), 0, false
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := limiter.Wait(ctx)
	waitTime := time.Since(start)

	if err != nil {
		// Timeout or context canceled
		return false, waitTime, true
	}

	// Successfully acquired token
	return true, waitTime, false
}

// createTokenBucketRequestInfo creates request info for token bucket
func (tbl *TokenBucketLimiter) createTokenBucketRequestInfo(c *gin.Context, clientKey string, allowed bool, waitTime time.Duration, timedOut bool) *TokenBucketRequestInfo {
	remaining := 0
	if allowed {
		remaining = tbl.estimateRemainingTokens(clientKey)
	}

	return &TokenBucketRequestInfo{
		ClientKey:       clientKey,
		IP:              c.ClientIP(),
		Path:            c.Request.URL.Path,
		Method:          c.Request.Method,
		Timestamp:       time.Now(),
		Allowed:         allowed,
		WaitTime:        waitTime,
		Remaining:       remaining,
		TimeoutOccurred: timedOut,
	}
}

// setHeaders sets token bucket rate limit headers
func (tbl *TokenBucketLimiter) setHeaders(c *gin.Context, info *TokenBucketRequestInfo) {
	if !tbl.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(tbl.config.Rate) * 60)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Minute).Format(time.RFC3339))
	c.Header("X-RateLimit-Algorithm", "token-bucket")
	c.Header("X-RateLimit-Burst", strconv.Itoa(tbl.config.Burst))

	if info.WaitTime > 0 {
		c.Header("X-RateLimit-Wait-Time", strconv.FormatInt(int64(info.WaitTime.Milliseconds()), 10))
	}

	if !info.Allowed {
		retryAfter := int64(time.Duration(float64(time.Second) / float64(tbl.config.Rate)).Seconds())
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

// logEvent logs token bucket events
func (tbl *TokenBucketLimiter) logEvent(info *TokenBucketRequestInfo) {
	if !tbl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if info.TimeoutOccurred {
		status = "TIMEOUT"
	} else if !info.Allowed {
		status = "BLOCKED"
	} else if info.WaitTime > 0 {
		status = "WAITED"
	}

	log.Printf("[TOKEN_BUCKET_LIMITER] %s - Client: %s, Method: %s, Path: %s, WaitTime: %s, Remaining: %d",
		status, info.ClientKey, info.Method, info.Path, info.WaitTime, info.Remaining)
}

// handleLimitExceeded handles when token bucket limit is exceeded
func (tbl *TokenBucketLimiter) handleLimitExceeded(c *gin.Context, info *TokenBucketRequestInfo) {
	// Call custom timeout handler if wait timed out
	if info.TimeoutOccurred && tbl.config.OnWaitTimeout != nil {
		tbl.config.OnWaitTimeout(c, info)
		return
	}

	// Call custom handler if provided
	if tbl.config.OnLimitExceeded != nil {
		tbl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if tbl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, tbl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	response := gin.H{
		"error":     tbl.config.ErrorMessage,
		"client":    info.ClientKey,
		"algorithm": "token-bucket",
		"timestamp": info.Timestamp.Format(time.RFC3339),
	}

	if info.TimeoutOccurred {
		response["reason"] = "wait_timeout"
		response["message"] = "Request timed out waiting for available tokens"
		response["wait_time"] = int64(info.WaitTime.Milliseconds())
		response["timeout"] = int64(tbl.config.WaitTimeout.Milliseconds())
	} else {
		response["reason"] = "no_tokens"
		response["message"] = "No tokens available in bucket"
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// Middleware returns the token bucket rate limiting middleware
func (tbl *TokenBucketLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract client key
		clientKey := tbl.config.ClientKeyFunc(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		// Get client-specific token bucket
		limiter := tbl.getLimiterForClient(clientKey)

		// Wait for token (or check immediately if no wait timeout)
		allowed, waitTime, timedOut := tbl.waitForToken(limiter, tbl.config.WaitTimeout)

		// Update statistics
		tbl.updateTokenBucketStats(clientKey, allowed, waitTime, timedOut)

		// Create request info
		info := tbl.createTokenBucketRequestInfo(c, clientKey, allowed, waitTime, timedOut)

		// Set headers
		tbl.setHeaders(c, info)

		// Log event
		tbl.logEvent(info)

		// Call request handler if provided
		if tbl.config.OnRequestProcessed != nil {
			tbl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded or timeout
		if !allowed || timedOut {
			tbl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns token bucket statistics
func (tbl *TokenBucketLimiter) GetStats() TokenBucketStats {
	tbl.mu.RLock()
	activeClients := int64(len(tbl.limiters))
	tbl.mu.RUnlock()

	return TokenBucketStats{
		TotalClients:    atomic.LoadInt64(&tbl.stats.TotalClients),
		ActiveClients:   activeClients,
		TotalRequests:   atomic.LoadInt64(&tbl.stats.TotalRequests),
		AllowedRequests: atomic.LoadInt64(&tbl.stats.AllowedRequests),
		BlockedRequests: atomic.LoadInt64(&tbl.stats.BlockedRequests),
		WaitedRequests:  atomic.LoadInt64(&tbl.stats.WaitedRequests),
		TimeoutRequests: atomic.LoadInt64(&tbl.stats.TimeoutRequests),
		TotalWaitTime:   atomic.LoadInt64(&tbl.stats.TotalWaitTime),
		StartTime:       tbl.stats.StartTime,
	}
}

// GetClientStats returns statistics for a specific client
func (tbl *TokenBucketLimiter) GetClientStats(clientKey string) map[string]interface{} {
	tbl.mu.RLock()
	entry, exists := tbl.limiters[clientKey]
	tbl.mu.RUnlock()

	if !exists {
		return map[string]interface{}{
			"exists":    false,
			"remaining": tbl.config.Burst,
		}
	}

	remaining := tbl.estimateRemainingTokens(clientKey)

	return map[string]interface{}{
		"exists":        true,
		"remaining":     remaining,
		"last_access":   entry.lastAccess,
		"created":       entry.created,
		"wait_count":    atomic.LoadInt64(&entry.waitCount),
		"timeout_count": atomic.LoadInt64(&entry.timeoutCount),
	}
}

// GetAverageWaitTime returns average wait time across all requests
func (tbl *TokenBucketLimiter) GetAverageWaitTime() time.Duration {
	totalWaitTime := atomic.LoadInt64(&tbl.stats.TotalWaitTime)
	waitedRequests := atomic.LoadInt64(&tbl.stats.WaitedRequests)

	if waitedRequests == 0 {
		return 0
	}

	return time.Duration(totalWaitTime / waitedRequests)
}

// ResetStats resets all token bucket statistics
func (tbl *TokenBucketLimiter) ResetStats() {
	atomic.StoreInt64(&tbl.stats.TotalRequests, 0)
	atomic.StoreInt64(&tbl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&tbl.stats.BlockedRequests, 0)
	atomic.StoreInt64(&tbl.stats.WaitedRequests, 0)
	atomic.StoreInt64(&tbl.stats.TimeoutRequests, 0)
	atomic.StoreInt64(&tbl.stats.TotalWaitTime, 0)
	tbl.stats.StartTime = time.Now()
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

// TokenBucketRateLimitMiddleware creates a simple token bucket rate limiter
func TokenBucketRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &TokenBucketConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		WaitTimeout:   0, // No waiting by default
		EnableHeaders: true,
	}
	limiter := NewTokenBucketLimiter(config)
	return limiter.Middleware()
}

// WaitingTokenBucketRateLimitMiddleware creates token bucket with wait capability
func WaitingTokenBucketRateLimitMiddleware(requestsPerSecond float64, burst int, waitTimeout time.Duration) gin.HandlerFunc {
	config := &TokenBucketConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		WaitTimeout:   waitTimeout,
		EnableHeaders: true,
		EnableLogging: true,
	}
	limiter := NewTokenBucketLimiter(config)
	return limiter.Middleware()
}

// GracefulTokenBucketRateLimitMiddleware creates token bucket with graceful degradation
func GracefulTokenBucketRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &TokenBucketConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		WaitTimeout:   5 * time.Second, // Wait up to 5 seconds
		EnableHeaders: true,
		EnableLogging: true,
		OnWaitTimeout: func(c *gin.Context, info *TokenBucketRequestInfo) {
			// Custom response for timeouts
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":     "Service temporarily overloaded",
				"message":   "Please try again in a few seconds",
				"waited":    int64(info.WaitTime.Milliseconds()),
				"timeout":   5000,
				"algorithm": "token-bucket-graceful",
			})
			c.Abort()
		},
	}
	limiter := NewTokenBucketLimiter(config)
	return limiter.Middleware()
}

// BurstTokenBucketRateLimitMiddleware creates token bucket optimized for burst traffic
func BurstTokenBucketRateLimitMiddleware(requestsPerSecond float64, burstMultiplier int) gin.HandlerFunc {
	burst := int(float64(burstMultiplier) * requestsPerSecond) // Large burst capacity

	config := &TokenBucketConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		WaitTimeout:   time.Second, // Short wait for burst scenarios
		EnableHeaders: true,
		OnRequestProcessed: func(c *gin.Context, info *TokenBucketRequestInfo, allowed bool) {
			// Add burst-specific headers
			if info.WaitTime > 0 {
				c.Header("X-Burst-Handled", "true")
				c.Header("X-Burst-Wait-Time", strconv.FormatInt(int64(info.WaitTime.Milliseconds()), 10))
			}
		},
	}
	limiter := NewTokenBucketLimiter(config)
	return limiter.Middleware()
}

// APITokenBucketRateLimitMiddleware creates token bucket for API endpoints
func APITokenBucketRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &TokenBucketConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		WaitTimeout:   2 * time.Second,
		EnableHeaders: true,
		EnableLogging: true,
		ClientKeyFunc: func(c *gin.Context) string {
			// Prioritize API key, fallback to user ID, then IP
			if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
				return "api:" + apiKey
			}
			if userID := c.GetHeader("X-User-ID"); userID != "" {
				return "user:" + userID
			}
			return "ip:" + c.ClientIP()
		},
		OnLimitExceeded: func(c *gin.Context, info *TokenBucketRequestInfo) {
			// API-specific error response
			response := gin.H{
				"error": gin.H{
					"code":    "RATE_LIMIT_EXCEEDED",
					"message": "API rate limit exceeded",
					"type":    "token_bucket",
				},
				"meta": gin.H{
					"client":    info.ClientKey,
					"timestamp": info.Timestamp.Format(time.RFC3339),
					"remaining": info.Remaining,
				},
			}

			if info.TimeoutOccurred {
				response["error"].(gin.H)["details"] = "Request timed out waiting for available capacity"
				response["meta"].(gin.H)["wait_time"] = int64(info.WaitTime.Milliseconds())
			}

			c.JSON(http.StatusTooManyRequests, response)
			c.Abort()
		},
	}
	limiter := NewTokenBucketLimiter(config)
	return limiter.Middleware()
}
