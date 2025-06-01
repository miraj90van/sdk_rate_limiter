// sliding_windows_rate_limiter_middleware.go
// Purpose: SLIDING WINDOW rate limiting algorithm - more precise time-based limiting
// Use case: When you need precise time-window based limiting (e.g., exactly 100 requests per minute)

package middleware

import (
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"net/http"
)

// Ensure it implements RateLimiter interface
var _ RateLimiter = (*SlidingWindowLimiter)(nil)

// SlidingWindowConfig for sliding window rate limiting
type SlidingWindowConfig struct {
	Limit              int                       // Maximum requests allowed in the time window
	Window             time.Duration             // Time window duration (e.g., 1 minute, 1 hour)
	MaxClients         int                       // Maximum number of clients to track
	CleanupInterval    time.Duration             // How often to cleanup old client entries
	EnableHeaders      bool                      // Include rate limit headers
	EnableLogging      bool                      // Enable logging
	ClientKeyFunc      func(*gin.Context) string // Function to extract client key
	ErrorMessage       string                    // Custom error message
	ErrorResponse      interface{}               // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *SlidingWindowRequestInfo)
	OnRequestProcessed func(*gin.Context, *SlidingWindowRequestInfo, bool)
}

// SlidingWindowRequestInfo contains information about sliding window request
type SlidingWindowRequestInfo struct {
	ClientKey    string
	IP           string
	Path         string
	Method       string
	Timestamp    time.Time
	Allowed      bool
	CurrentCount int           // Current requests in window
	Limit        int           // Limit for the window
	WindowStart  time.Time     // Start of current window
	WindowEnd    time.Time     // End of current window
	RetryAfter   time.Duration // Time until window resets
}

// ClientWindowEntry represents sliding window data for a specific client
type ClientWindowEntry struct {
	requests   []time.Time  // Timestamps of requests in current window
	lastAccess time.Time    // Last access time for cleanup
	mu         sync.RWMutex // Mutex for thread-safe access to requests slice
}

// SlidingWindowLimiter manages sliding window rate limiting
type SlidingWindowLimiter struct {
	clients       map[string]*ClientWindowEntry
	mu            sync.RWMutex
	config        *SlidingWindowConfig
	stats         *SlidingWindowStats
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// SlidingWindowStats holds statistics about sliding window rate limiting
type SlidingWindowStats struct {
	*BaseStats
	TotalClients  int64
	ActiveClients int64
}

func (s *SlidingWindowStats) Clone() Stats {
	return &SlidingWindowStats{
		BaseStats: &BaseStats{
			StartTime:       s.StartTime,
			LimiterType:     s.LimiterType,
			TotalRequests:   atomic.LoadInt64(&s.TotalRequests),
			AllowedRequests: atomic.LoadInt64(&s.AllowedRequests),
			BlockedRequests: atomic.LoadInt64(&s.BlockedRequests),
		},
		TotalClients:  atomic.LoadInt64(&s.TotalClients),
		ActiveClients: atomic.LoadInt64(&s.ActiveClients),
	}
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter
func NewSlidingWindowLimiter(config *SlidingWindowConfig) *SlidingWindowLimiter {
	if config == nil {
		config = DefaultSlidingWindowConfig()
	}

	// Set defaults
	if config.MaxClients <= 0 {
		config.MaxClients = 10000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = config.Window // Cleanup every window duration
	}
	if config.ClientKeyFunc == nil {
		config.ClientKeyFunc = func(c *gin.Context) string {
			return c.ClientIP() // Default to IP-based
		}
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Rate limit exceeded"
	}

	limiter := &SlidingWindowLimiter{
		clients:     make(map[string]*ClientWindowEntry),
		config:      config,
		stopCleanup: make(chan struct{}),
		stats: &SlidingWindowStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: SlidingWindowType,
			},
		},
	}

	// Start cleanup goroutine
	limiter.startCleanup()

	return limiter
}

// DefaultSlidingWindowConfig returns default configuration
func DefaultSlidingWindowConfig() *SlidingWindowConfig {
	return &SlidingWindowConfig{
		Limit:           100,         // 100 requests
		Window:          time.Minute, // per minute
		MaxClients:      10000,       // track up to 10k clients
		CleanupInterval: time.Minute, // cleanup every minute
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded",
	}
}

// startCleanup starts the cleanup goroutine
func (swl *SlidingWindowLimiter) startCleanup() {
	swl.cleanupTicker = time.NewTicker(swl.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-swl.cleanupTicker.C:
				swl.cleanup()
			case <-swl.stopCleanup:
				swl.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old client entries and expired requests
func (swl *SlidingWindowLimiter) cleanup() {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-swl.config.Window)
	clientTTL := swl.config.Window * 2 // Keep clients for 2 window durations

	removedClients := 0
	totalRemovedRequests := 0

	for clientKey, entry := range swl.clients {
		entry.mu.Lock()

		// Remove old requests from this client's window
		validRequests := make([]time.Time, 0, len(entry.requests))
		removedRequests := 0

		for _, reqTime := range entry.requests {
			if reqTime.After(windowStart) {
				validRequests = append(validRequests, reqTime)
			} else {
				removedRequests++
			}
		}

		entry.requests = validRequests
		totalRemovedRequests += removedRequests

		// Check if client should be removed (inactive for too long)
		shouldRemoveClient := entry.lastAccess.Before(now.Add(-clientTTL)) && len(entry.requests) == 0

		entry.mu.Unlock()

		if shouldRemoveClient {
			delete(swl.clients, clientKey)
			removedClients++
		}
	}

	// If still over max clients, remove least recently used clients
	if len(swl.clients) > swl.config.MaxClients {
		type clientEntry struct {
			key   string
			entry *ClientWindowEntry
		}

		var entries []clientEntry
		for key, entry := range swl.clients {
			entries = append(entries, clientEntry{key, entry})
		}

		// Sort by last access time (oldest first)
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].entry.lastAccess.After(entries[j].entry.lastAccess) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}

		// Remove oldest clients until we're under the limit
		toRemove := len(swl.clients) - swl.config.MaxClients
		for i := 0; i < toRemove && i < len(entries); i++ {
			delete(swl.clients, entries[i].key)
			removedClients++
		}
	}

	if swl.config.EnableLogging && (removedClients > 0 || totalRemovedRequests > 0) {
		log.Printf("Sliding Window Limiter: Cleaned up %d clients, %d requests, active clients: %d",
			removedClients, totalRemovedRequests, len(swl.clients))
	}

	// Update stats
	atomic.StoreInt64(&swl.stats.ActiveClients, int64(len(swl.clients)))
}

// getAllowedForClient checks if request is allowed for specific client and updates window
func (swl *SlidingWindowLimiter) getAllowedForClient(clientKey string, now time.Time) (bool, int, time.Time) {
	swl.mu.Lock()
	entry, exists := swl.clients[clientKey]
	if !exists {
		// Create new client entry
		entry = &ClientWindowEntry{
			requests:   make([]time.Time, 0),
			lastAccess: now,
		}
		swl.clients[clientKey] = entry
		atomic.AddInt64(&swl.stats.TotalClients, 1)
	}
	swl.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	entry.lastAccess = now
	windowStart := now.Add(-swl.config.Window)

	// Remove expired requests from sliding window
	validRequests := make([]time.Time, 0, len(entry.requests))
	for _, reqTime := range entry.requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}
	entry.requests = validRequests

	// Check if we can allow this request
	currentCount := len(entry.requests)
	allowed := currentCount < swl.config.Limit

	if allowed {
		// Add current request to window
		entry.requests = append(entry.requests, now)
		currentCount++
	}

	// Calculate when window will have space (for retry-after)
	var oldestRequest time.Time
	if len(entry.requests) > 0 {
		oldestRequest = entry.requests[0]
	} else {
		oldestRequest = now
	}

	return allowed, currentCount, oldestRequest
}

// createSlidingWindowRequestInfo creates request info for sliding window
func (swl *SlidingWindowLimiter) createSlidingWindowRequestInfo(c *gin.Context, clientKey string, allowed bool, currentCount int, oldestRequest time.Time) *SlidingWindowRequestInfo {
	now := time.Now()
	windowStart := now.Add(-swl.config.Window)
	windowEnd := now

	var retryAfter time.Duration
	if !allowed && !oldestRequest.IsZero() {
		// Calculate when the oldest request will expire
		retryAfter = oldestRequest.Add(swl.config.Window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &SlidingWindowRequestInfo{
		ClientKey:    clientKey,
		IP:           c.ClientIP(),
		Path:         c.Request.URL.Path,
		Method:       c.Request.Method,
		Timestamp:    now,
		Allowed:      allowed,
		CurrentCount: currentCount,
		Limit:        swl.config.Limit,
		WindowStart:  windowStart,
		WindowEnd:    windowEnd,
		RetryAfter:   retryAfter,
	}
}

// setHeaders sets sliding window rate limit headers
func (swl *SlidingWindowLimiter) setHeaders(c *gin.Context, info *SlidingWindowRequestInfo) {
	if !swl.config.EnableHeaders {
		return
	}

	remaining := swl.config.Limit - info.CurrentCount
	if remaining < 0 {
		remaining = 0
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(swl.config.Limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", info.WindowEnd.Add(swl.config.Window).Format(time.RFC3339))
	c.Header("X-RateLimit-Window", swl.config.Window.String())
	c.Header("X-RateLimit-Algorithm", "sliding-window")

	if !info.Allowed {
		c.Header("Retry-After", strconv.FormatInt(int64(info.RetryAfter.Seconds()), 10))
	}
}

// logEvent logs sliding window events
func (swl *SlidingWindowLimiter) logEvent(info *SlidingWindowRequestInfo) {
	if !swl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	log.Printf("[SLIDING_WINDOW_LIMITER] %s - Client: %s, Method: %s, Path: %s, Count: %d/%d, Window: %s",
		status, info.ClientKey, info.Method, info.Path, info.CurrentCount, info.Limit, swl.config.Window)
}

// handleLimitExceeded handles when sliding window limit is exceeded
func (swl *SlidingWindowLimiter) handleLimitExceeded(c *gin.Context, info *SlidingWindowRequestInfo) {
	// Call custom handler if provided
	if swl.config.OnLimitExceeded != nil {
		swl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if swl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, swl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":         swl.config.ErrorMessage,
		"client":        info.ClientKey,
		"limit":         info.Limit,
		"window":        swl.config.Window.String(),
		"current_count": info.CurrentCount,
		"retry_after":   int64(info.RetryAfter.Seconds()),
		"algorithm":     "sliding-window",
		"timestamp":     info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// Middleware returns the sliding window rate limiting middleware
func (swl *SlidingWindowLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()

		// Extract client key
		clientKey := swl.config.ClientKeyFunc(c)
		if clientKey == "" {
			clientKey = c.ClientIP() // Fallback to IP
		}

		// Check if request is allowed
		allowed, currentCount, oldestRequest := swl.getAllowedForClient(clientKey, now)

		// Update statistics
		atomic.AddInt64(&swl.stats.TotalRequests, 1)
		if allowed {
			atomic.AddInt64(&swl.stats.AllowedRequests, 1)
		} else {
			atomic.AddInt64(&swl.stats.BlockedRequests, 1)
		}

		// Create request info
		info := swl.createSlidingWindowRequestInfo(c, clientKey, allowed, currentCount, oldestRequest)

		// Set headers
		swl.setHeaders(c, info)

		// Log event
		swl.logEvent(info)

		// Call request handler if provided
		if swl.config.OnRequestProcessed != nil {
			swl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			swl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns sliding window statistics
func (swl *SlidingWindowLimiter) GetStats() Stats {
	atomic.StoreInt64(&swl.stats.ActiveClients, int64(len(swl.clients)))
	return swl.stats.Clone()
}

// GetClientStats returns current window statistics for a specific client
func (swl *SlidingWindowLimiter) GetClientStats(clientKey string) map[string]interface{} {
	swl.mu.RLock()
	entry, exists := swl.clients[clientKey]
	swl.mu.RUnlock()

	if !exists {
		return map[string]interface{}{
			"exists":        false,
			"current_count": 0,
			"limit":         swl.config.Limit,
			"window":        swl.config.Window.String(),
		}
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-swl.config.Window)

	// Count valid requests in current window
	validCount := 0
	for _, reqTime := range entry.requests {
		if reqTime.After(windowStart) {
			validCount++
		}
	}

	return map[string]interface{}{
		"exists":        true,
		"current_count": validCount,
		"limit":         swl.config.Limit,
		"window":        swl.config.Window.String(),
		"last_access":   entry.lastAccess,
		"remaining":     swl.config.Limit - validCount,
	}
}

// ResetClientWindow resets the sliding window for a specific client
func (swl *SlidingWindowLimiter) ResetClientWindow(clientKey string) {
	swl.mu.RLock()
	entry, exists := swl.clients[clientKey]
	swl.mu.RUnlock()

	if exists {
		entry.mu.Lock()
		entry.requests = make([]time.Time, 0)
		entry.mu.Unlock()
	}
}

// ResetStats resets all sliding window statistics
func (swl *SlidingWindowLimiter) ResetStats() {
	atomic.StoreInt64(&swl.stats.TotalRequests, 0)
	atomic.StoreInt64(&swl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&swl.stats.BlockedRequests, 0)
	swl.stats.StartTime = time.Now()
}

func (swl *SlidingWindowLimiter) Stop() {
	close(swl.stopCleanup)
}

func (swl *SlidingWindowLimiter) Type() RateLimiterType {
	return SlidingWindowType
}

func (swl *SlidingWindowLimiter) Algorithm() Algorithm {
	return SlidingWindowAlg
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

// SlidingWindowRateLimitMiddleware creates a simple sliding window rate limiter
func SlidingWindowRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	config := &SlidingWindowConfig{
		Limit:         limit,
		Window:        window,
		EnableHeaders: true,
	}
	limiter := NewSlidingWindowLimiter(config)
	return limiter.Middleware()
}

// IPSlidingWindowRateLimitMiddleware creates IP-based sliding window rate limiter
func IPSlidingWindowRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	config := &SlidingWindowConfig{
		Limit:         limit,
		Window:        window,
		EnableHeaders: true,
		ClientKeyFunc: func(c *gin.Context) string {
			return "ip:" + c.ClientIP()
		},
	}
	limiter := NewSlidingWindowLimiter(config)
	return limiter.Middleware()
}

// UserSlidingWindowRateLimitMiddleware creates user-based sliding window rate limiter
func UserSlidingWindowRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	config := &SlidingWindowConfig{
		Limit:         limit,
		Window:        window,
		EnableHeaders: true,
		EnableLogging: true,
		ClientKeyFunc: func(c *gin.Context) string {
			userID := c.GetHeader("X-User-ID")
			if userID == "" {
				return "anonymous:" + c.ClientIP()
			}
			return "user:" + userID
		},
	}
	limiter := NewSlidingWindowLimiter(config)
	return limiter.Middleware()
}

// PreciseSlidingWindowRateLimitMiddleware creates precise time-based sliding window limiter
func (swl *SlidingWindowLimiter) PreciseSlidingWindowRateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
	config := &SlidingWindowConfig{
		Limit:         limit,
		Window:        window,
		EnableHeaders: true,
		EnableLogging: true,
		ClientKeyFunc: func(c *gin.Context) string {
			return c.ClientIP()
		},
		OnLimitExceeded: func(c *gin.Context, info *SlidingWindowRequestInfo) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Precise rate limit exceeded",
				"details": gin.H{
					"limit":         info.Limit,
					"window":        swl.config.Window.String(),
					"current_count": info.CurrentCount,
					"window_start":  info.WindowStart.Format(time.RFC3339),
					"window_end":    info.WindowEnd.Format(time.RFC3339),
					"retry_after":   int64(info.RetryAfter.Seconds()),
					"algorithm":     "sliding-window",
				},
			})
			c.Abort()
		},
	}
	limiter := NewSlidingWindowLimiter(config)
	return limiter.Middleware()
}
