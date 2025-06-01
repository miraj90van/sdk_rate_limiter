// basic_rate_limiter_middleware.go
// Purpose: GLOBAL rate limiting only - all clients share the same rate limit
// Use case: Protect server from total overload

package middleware

import (
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

var _ RateLimiter = (*BasicRateLimiter)(nil)

// BasicRateLimiterConfig for global rate limiting only
type BasicRateLimiterConfig struct {
	Rate               rate.Limit  // Global requests per second (shared by ALL clients)
	Burst              int         // Global burst capacity (shared by ALL clients)
	EnableHeaders      bool        // Include rate limit headers
	EnableLogging      bool        // Enable logging for monitoring
	ErrorMessage       string      // Custom error message
	ErrorResponse      interface{} // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *BasicRequestInfo)
	OnRequestProcessed func(*gin.Context, *BasicRequestInfo, bool)
}

// BasicRequestInfo contains info about request (for logging/monitoring only)
// Note: IP is only for logging, NOT for rate limiting (global limiter doesn't care about IP)
type BasicRequestInfo struct {
	BaseRequestInfo
}

// BasicRateLimiter manages GLOBAL rate limiting (single limiter for all requests)
type BasicRateLimiter struct {
	limiter *rate.Limiter // SINGLE limiter shared by ALL clients
	config  *BasicRateLimiterConfig
	stats   *BasicStats
}

// BasicStats for global rate limiting statistics
type BasicStats struct {
	*BaseStats
}

// NewBasicRateLimiter creates a new GLOBAL rate limiter
func NewBasicRateLimiter(config *BasicRateLimiterConfig) *BasicRateLimiter {
	if config == nil {
		config = DefaultBasicConfig()
	}

	if config.ErrorMessage == "" {
		config.ErrorMessage = "Global rate limit exceeded"
	}

	return &BasicRateLimiter{
		limiter: rate.NewLimiter(config.Rate, config.Burst), // Single limiter for ALL requests
		config:  config,
		stats: &BasicStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: BasicType,
			},
		},
	}
}

// DefaultBasicConfig returns default configuration for global rate limiting
func DefaultBasicConfig() *BasicRateLimiterConfig {
	return &BasicRateLimiterConfig{
		Rate:          rate.Limit(1000), // 1000 req/sec GLOBALLY
		Burst:         100,              // 100 burst GLOBALLY
		EnableHeaders: true,
		EnableLogging: false,
		ErrorMessage:  "Global rate limit exceeded",
	}
}

// createRequestInfo creates request info for logging/monitoring only
func (brl *BasicRateLimiter) createRequestInfo(c *gin.Context, allowed bool) *BasicRequestInfo {
	return &BasicRequestInfo{
		BaseRequestInfo: BaseRequestInfo{
			IP:        c.ClientIP(),
			Path:      c.Request.URL.Path,
			Method:    c.Request.Method,
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: time.Now(),
			Allowed:   allowed,
		},
	}
}

// setHeaders sets rate limit headers
func (brl *BasicRateLimiter) setHeaders(c *gin.Context, remaining int) {
	if !brl.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(brl.config.Rate) * 60)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Minute).Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", "global") // Clearly indicate this is global limiting
}

// logEvent logs rate limiting events for monitoring
func (brl *BasicRateLimiter) logEvent(info *BasicRequestInfo) {
	if !brl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	// Log format focuses on global nature
	log.Printf("[GLOBAL_RATE_LIMITER] %s - Method: %s, Path: %s, IP: %s (for monitoring only)",
		status, info.Method, info.Path, info.IP)
}

// handleLimitExceeded handles when global rate limit is exceeded
func (brl *BasicRateLimiter) handleLimitExceeded(c *gin.Context, info *BasicRequestInfo) {
	// Call custom handler if provided
	if brl.config.OnLimitExceeded != nil {
		brl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if brl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, brl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response - clearly indicate this is global limiting
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":     brl.config.ErrorMessage,
		"message":   "Server is receiving too many requests globally",
		"scope":     "global",
		"timestamp": info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// Middleware returns the global rate limiting middleware
func (brl *BasicRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check GLOBAL rate limit (all clients share this single limiter)
		allowed := brl.limiter.Allow()

		// Update global statistics
		atomic.AddInt64(&brl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&brl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&brl.stats.BlockedRequests, 1)
		}

		// Create request info (IP is only for logging, not for limiting)
		info := brl.createRequestInfo(c, allowed)

		// Estimate remaining capacity (global)
		remaining := brl.config.Burst
		if !allowed {
			remaining = 0
		}

		// Set headers
		brl.setHeaders(c, remaining)

		// Log event
		brl.logEvent(info)

		// Call request handler if provided
		if brl.config.OnRequestProcessed != nil {
			brl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			brl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns global rate limiting statistics
func (brl *BasicRateLimiter) GetStats() Stats {
	// Update live counters
	brl.stats.TotalRequests = atomic.LoadInt64(&brl.stats.BaseStats.TotalRequests)
	brl.stats.AllowedRequests = atomic.LoadInt64(&brl.stats.BaseStats.AllowedRequests)
	brl.stats.BlockedRequests = atomic.LoadInt64(&brl.stats.BaseStats.BlockedRequests)
	return brl.stats
}

// ResetStats resets global statistics
func (brl *BasicRateLimiter) ResetStats() {
	atomic.StoreInt64(&brl.stats.BaseStats.TotalRequests, 0)
	atomic.StoreInt64(&brl.stats.BaseStats.AllowedRequests, 0)
	atomic.StoreInt64(&brl.stats.BaseStats.BlockedRequests, 0)
	brl.stats.BaseStats.StartTime = time.Now()
}

// Stop gracefully stops the rate limiter (not needed for Basic, but required by interface)
func (brl *BasicRateLimiter) Stop() {
	// No background cleanup needed for global limiter
}

// Type returns the type of rate limiter
func (brl *BasicRateLimiter) Type() RateLimiterType {
	return BasicType
}

// Algorithm returns the algorithm used (Token Bucket)
func (brl *BasicRateLimiter) Algorithm() Algorithm {
	return TokenBucketAlg
}

// =============================================================================
// CONVENIENCE FUNCTIONS - All for GLOBAL rate limiting only
// =============================================================================

// BasicRateLimitMiddleware creates a simple global rate limiter
// All clients share the specified rate limit
func BasicRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
	}
	limiter := NewBasicRateLimiter(config)
	return limiter.Middleware()
}

// GlobalRateLimitMiddleware - alias for clarity (same as BasicRateLimitMiddleware)
func GlobalRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	return BasicRateLimitMiddleware(requestsPerSecond, burst)
}

// ServerProtectionMiddleware creates a global rate limiter for server protection
func ServerProtectionMiddleware(maxRequestsPerSecond float64) gin.HandlerFunc {
	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(maxRequestsPerSecond),
		Burst:         int(maxRequestsPerSecond * 0.1), // 10% burst
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "Server overload protection activated",
	}
	limiter := NewBasicRateLimiter(config)
	return limiter.Middleware()
}

// EmergencyRateLimitMiddleware creates a very strict global rate limiter for emergencies
func EmergencyRateLimitMiddleware() gin.HandlerFunc {
	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(10), // Very low limit
		Burst:         2,              // Minimal burst
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "Emergency rate limiting activated",
		ErrorResponse: gin.H{
			"error":   "Emergency rate limiting activated",
			"message": "Server is under emergency protection",
			"scope":   "global",
			"level":   "emergency",
		},
	}
	limiter := NewBasicRateLimiter(config)
	return limiter.Middleware()
}
