// advance_rate_limiter_middleware.go
// Purpose: FLEXIBLE per-client rate limiting with custom key extraction
// Use case: Complex scenarios requiring custom client identification logic

package middleware

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

var _ RateLimiter = (*AdvancedRateLimiter)(nil)

// AdvancedRateLimiterConfig for flexible per-client rate limiting
type AdvancedRateLimiterConfig struct {
	Rate               rate.Limit                // Requests per second PER CLIENT
	Burst              int                       // Burst capacity PER CLIENT
	MaxClients         int                       // Maximum number of clients to track
	CleanupInterval    time.Duration             // How often to cleanup old client entries
	ClientTTL          time.Duration             // Time to live for inactive client entries
	EnableHeaders      bool                      // Include rate limit headers
	EnableLogging      bool                      // Enable logging
	CustomKeyFunc      func(*gin.Context) string // REQUIRED: Custom function to extract client key
	KeyDescription     string                    // Description of what the key represents (for headers/logs)
	ErrorMessage       string                    // Custom error message
	ErrorResponse      interface{}               // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *AdvancedRequestInfo)
	OnRequestProcessed func(*gin.Context, *AdvancedRequestInfo, bool)
	OnClientCreated    func(string) // Called when new client is tracked
}

// AdvancedRequestInfo contains information about advanced rate limiting request
type AdvancedRequestInfo struct {
	ClientKey string
	IP        string
	UserAgent string
	Path      string
	Method    string
	Timestamp time.Time
	Allowed   bool
	Remaining int
	KeyType   string // Description of key type
}

// AdvancedLimiterEntry represents a rate limiter entry for a specific client
type AdvancedLimiterEntry struct {
	limiter      *rate.Limiter
	lastAccess   time.Time
	created      time.Time
	requestCount int64
	blockedCount int64
	metadata     map[string]string // Store additional client metadata
}

// AdvancedRateLimiter manages flexible per-client rate limiting
type AdvancedRateLimiter struct {
	limiters      map[string]*AdvancedLimiterEntry // Map: ClientKey -> RateLimiter
	mu            sync.RWMutex
	config        *AdvancedRateLimiterConfig
	stats         *AdvancedStats
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// AdvancedStats holds statistics about advanced rate limiting
type AdvancedStats struct {
	*BaseStats
	TotalClients  int64
	ActiveClients int64
}

// NewAdvancedRateLimiter creates a new advanced rate limiter
func NewAdvancedRateLimiter(config *AdvancedRateLimiterConfig) *AdvancedRateLimiter {
	if config == nil {
		panic("AdvancedRateLimiterConfig is required and cannot be nil")
	}

	if config.CustomKeyFunc == nil {
		panic("CustomKeyFunc is required for AdvancedRateLimiter")
	}

	// Set defaults
	if config.MaxClients <= 0 {
		config.MaxClients = 100000 // Large default for flexible scenarios
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.ClientTTL <= 0 {
		config.ClientTTL = 2 * time.Hour
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Rate limit exceeded for this client"
	}
	if config.KeyDescription == "" {
		config.KeyDescription = "custom-client"
	}

	limiter := &AdvancedRateLimiter{
		limiters:    make(map[string]*AdvancedLimiterEntry),
		config:      config,
		stopCleanup: make(chan struct{}),

		stats: &AdvancedStats{
			BaseStats: &BaseStats{
				StartTime: time.Now(),
			},
		},
	}

	// Start cleanup goroutine
	limiter.startCleanup()

	return limiter
}

// DefaultAdvancedConfig returns a template configuration (CustomKeyFunc must be set)
func DefaultAdvancedConfig() *AdvancedRateLimiterConfig {
	return &AdvancedRateLimiterConfig{
		Rate:            rate.Limit(50), // 50 req/sec per client
		Burst:           10,             // 10 burst per client
		MaxClients:      100000,         // Track up to 100k clients
		CleanupInterval: 5 * time.Minute,
		ClientTTL:       2 * time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		KeyDescription:  "custom-client",
		ErrorMessage:    "Rate limit exceeded for this client",
		// CustomKeyFunc must be set by caller
	}
}

// startCleanup starts the cleanup goroutine for removing old client entries
func (arl *AdvancedRateLimiter) startCleanup() {
	arl.cleanupTicker = time.NewTicker(arl.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-arl.cleanupTicker.C:
				arl.cleanup()
			case <-arl.stopCleanup:
				arl.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old and inactive client entries
func (arl *AdvancedRateLimiter) cleanup() {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-arl.config.ClientTTL)
	removed := 0

	// Remove clients that haven't been active recently
	for clientKey, entry := range arl.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(arl.limiters, clientKey)
			removed++
		}
	}

	// If still over max clients, remove oldest entries
	if len(arl.limiters) > arl.config.MaxClients {
		type clientEntry struct {
			clientKey string
			entry     *AdvancedLimiterEntry
		}

		var entries []clientEntry
		for clientKey, entry := range arl.limiters {
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
		toRemove := len(arl.limiters) - arl.config.MaxClients
		for i := 0; i < toRemove && i < len(entries); i++ {
			delete(arl.limiters, entries[i].clientKey)
			removed++
		}
	}

	if arl.config.EnableLogging && removed > 0 {
		fmt.Printf("Advanced Rate Limiter: Cleaned up %d client entries, active clients: %d\n", removed, len(arl.limiters))
	}

	// Update stats
	atomic.StoreInt64(&arl.stats.ActiveClients, int64(len(arl.limiters)))
}

// Stop stops the cleanup goroutine
func (arl *AdvancedRateLimiter) Stop() {
	close(arl.stopCleanup)
}

// getLimiterForClient gets or creates a rate limiter for the specific client
func (arl *AdvancedRateLimiter) getLimiterForClient(clientKey string) *rate.Limiter {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	entry, exists := arl.limiters[clientKey]
	if !exists {
		// Check if we're at max capacity
		if len(arl.limiters) >= arl.config.MaxClients {
			// Find and remove the oldest entry
			var oldestClientKey string
			var oldestTime time.Time = time.Now()

			for entryClientKey, entryData := range arl.limiters {
				if entryData.lastAccess.Before(oldestTime) {
					oldestTime = entryData.lastAccess
					oldestClientKey = entryClientKey
				}
			}

			if oldestClientKey != "" {
				delete(arl.limiters, oldestClientKey)
			}
		}

		// Create new limiter for this client
		limiter := rate.NewLimiter(arl.config.Rate, arl.config.Burst)
		entry = &AdvancedLimiterEntry{
			limiter:    limiter,
			lastAccess: time.Now(),
			created:    time.Now(),
			metadata:   make(map[string]string),
		}
		arl.limiters[clientKey] = entry

		// Update stats and call callback
		atomic.AddInt64(&arl.stats.TotalClients, 1)

		if arl.config.OnClientCreated != nil {
			arl.config.OnClientCreated(clientKey)
		}
	} else {
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

// updateAdvancedStats updates statistics for specific client
func (arl *AdvancedRateLimiter) updateAdvancedStats(clientKey string, allowed bool) {
	arl.mu.RLock()
	entry := arl.limiters[clientKey]
	arl.mu.RUnlock()

	if entry != nil {
		if allowed {
			atomic.AddInt64(&entry.requestCount, 1)
		} else {
			atomic.AddInt64(&entry.blockedCount, 1)
		}
	}

	// Update global stats
	atomic.AddInt64(&arl.stats.TotalRequests, 1)
	if allowed {
		atomic.AddInt64(&arl.stats.AllowedRequests, 1)
	} else {
		atomic.AddInt64(&arl.stats.BlockedRequests, 1)
	}
}

// estimateRemainingForClient estimates remaining requests for specific client
func (arl *AdvancedRateLimiter) estimateRemainingForClient(clientKey string) int {
	arl.mu.RLock()
	entry, exists := arl.limiters[clientKey]
	arl.mu.RUnlock()

	if !exists {
		return arl.config.Burst
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
		return arl.config.Burst - 1
	}

	return 0
}

// createAdvancedRequestInfo creates AdvancedRequestInfo for the current request
func (arl *AdvancedRateLimiter) createAdvancedRequestInfo(c *gin.Context, clientKey string, allowed bool) *AdvancedRequestInfo {
	remaining := 0
	if allowed {
		remaining = arl.estimateRemainingForClient(clientKey)
	}

	return &AdvancedRequestInfo{
		ClientKey: clientKey,
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
		Timestamp: time.Now(),
		Allowed:   allowed,
		Remaining: remaining,
		KeyType:   arl.config.KeyDescription,
	}
}

// setHeaders sets advanced rate limit headers
func (arl *AdvancedRateLimiter) setHeaders(c *gin.Context, info *AdvancedRequestInfo) {
	if !arl.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(arl.config.Rate) * 60)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Minute).Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", "per-client-advanced")
	c.Header("X-RateLimit-Client", info.ClientKey)
	c.Header("X-RateLimit-Key-Type", info.KeyType)

	if !info.Allowed {
		retryAfter := int64(time.Duration(float64(time.Second) / float64(arl.config.Rate)).Seconds())
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

// logEvent logs advanced rate limiting events
func (arl *AdvancedRateLimiter) logEvent(info *AdvancedRequestInfo) {
	if !arl.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	fmt.Printf("[ADVANCED_RATE_LIMITER] %s - Client: %s (%s), Method: %s, Path: %s, Remaining: %d\n",
		status, info.ClientKey, info.KeyType, info.Method, info.Path, info.Remaining)
}

// handleLimitExceeded handles when advanced rate limit is exceeded
func (arl *AdvancedRateLimiter) handleLimitExceeded(c *gin.Context, info *AdvancedRequestInfo) {
	// Call custom handler if provided
	if arl.config.OnLimitExceeded != nil {
		arl.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if arl.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, arl.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":     arl.config.ErrorMessage,
		"client":    info.ClientKey,
		"key_type":  info.KeyType,
		"scope":     "per-client-advanced",
		"timestamp": info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// Middleware returns the advanced rate limiting middleware
func (arl *AdvancedRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract client key using custom function
		clientKey := arl.config.CustomKeyFunc(c)

		if clientKey == "" {
			// Handle empty client key
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to identify client for rate limiting",
				"scope": "per-client-advanced",
			})
			c.Abort()
			return
		}

		// Get client-specific rate limiter
		limiter := arl.getLimiterForClient(clientKey)

		// Check rate limit for this specific client
		allowed := limiter.Allow()

		// Update statistics
		arl.updateAdvancedStats(clientKey, allowed)

		// Create request info
		info := arl.createAdvancedRequestInfo(c, clientKey, allowed)

		// Set headers
		arl.setHeaders(c, info)

		// Log event
		arl.logEvent(info)

		// Call request handler if provided
		if arl.config.OnRequestProcessed != nil {
			arl.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			arl.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns advanced rate limiting statistics
func (arl *AdvancedRateLimiter) GetStats() Stats {
	arl.mu.RLock()
	activeClients := int64(len(arl.limiters))
	arl.mu.RUnlock()

	return AdvancedStats{
		BaseStats: &BaseStats{
			TotalRequests:   atomic.LoadInt64(&arl.stats.TotalRequests),
			AllowedRequests: atomic.LoadInt64(&arl.stats.AllowedRequests),
			BlockedRequests: atomic.LoadInt64(&arl.stats.BlockedRequests),
			StartTime:       arl.stats.StartTime,
			LimiterType:     AdvancedType,
		},
		TotalClients:  atomic.LoadInt64(&arl.stats.TotalClients),
		ActiveClients: activeClients,
	}
}

// GetClientStats returns statistics for a specific client
func (arl *AdvancedRateLimiter) GetClientStats(clientKey string) *AdvancedLimiterEntry {
	arl.mu.RLock()
	defer arl.mu.RUnlock()

	if entry, exists := arl.limiters[clientKey]; exists {
		return &AdvancedLimiterEntry{
			lastAccess:   entry.lastAccess,
			created:      entry.created,
			requestCount: atomic.LoadInt64(&entry.requestCount),
			blockedCount: atomic.LoadInt64(&entry.blockedCount),
			metadata:     entry.metadata,
		}
	}
	return nil
}

// SetClientMetadata sets metadata for a specific client
func (arl *AdvancedRateLimiter) SetClientMetadata(clientKey, key, value string) {
	arl.mu.RLock()
	defer arl.mu.RUnlock()

	if entry, exists := arl.limiters[clientKey]; exists {
		entry.metadata[key] = value
	}
}

// ResetStats resets all advanced rate limiting statistics
func (arl *AdvancedRateLimiter) ResetStats() {
	atomic.StoreInt64(&arl.stats.TotalRequests, 0)
	atomic.StoreInt64(&arl.stats.AllowedRequests, 0)
	atomic.StoreInt64(&arl.stats.BlockedRequests, 0)
	arl.stats.StartTime = time.Now()
}

// =============================================================================
// CONVENIENCE FUNCTIONS - Pre-built key extractors for common scenarios
// =============================================================================

// TenantBasedKeyExtractor extracts tenant ID for multi-tenant applications
func TenantBasedKeyExtractor(c *gin.Context) string {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		tenantID = c.Query("tenant")
	}
	if tenantID == "" {
		return "tenant:unknown:" + c.ClientIP()
	}
	return "tenant:" + tenantID
}

// CompositeKeyExtractor combines multiple identification methods
func CompositeKeyExtractor(extractors ...func(*gin.Context) string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		var parts []string
		for _, extractor := range extractors {
			part := extractor(c)
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) == 0 {
			return "composite:unknown:" + c.ClientIP()
		}
		return fmt.Sprintf("composite:%v", parts)
	}
}

// TierBasedKeyExtractor creates keys based on user tier/subscription level
func TierBasedKeyExtractor(c *gin.Context) string {
	userID := c.GetHeader("X-User-ID")
	tier := c.GetHeader("X-User-Tier")

	if userID == "" {
		return "tier:anonymous:" + c.ClientIP()
	}
	if tier == "" {
		tier = "free"
	}
	return fmt.Sprintf("tier:%s:user:%s", tier, userID)
}

// RegionBasedKeyExtractor creates keys based on geographic region
func RegionBasedKeyExtractor(c *gin.Context) string {
	region := c.GetHeader("X-User-Region")
	userID := c.GetHeader("X-User-ID")

	if region == "" {
		region = "unknown"
	}
	if userID == "" {
		return "region:" + region + ":ip:" + c.ClientIP()
	}
	return fmt.Sprintf("region:%s:user:%s", region, userID)
}

func (arl *AdvancedRateLimiter) Type() RateLimiterType {
	return AdvancedType
}

func (arl *AdvancedRateLimiter) Algorithm() Algorithm {
	return LeakyBucketAlg
}

// =============================================================================
// CONVENIENCE MIDDLEWARE FUNCTIONS
// =============================================================================

// TenantRateLimitMiddleware creates rate limiter for multi-tenant applications
func TenantRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &AdvancedRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		CustomKeyFunc:  TenantBasedKeyExtractor,
		KeyDescription: "tenant",
		ErrorMessage:   "Rate limit exceeded for this tenant",
	}
	limiter := NewAdvancedRateLimiter(config)
	return limiter.Middleware()
}

// TierBasedRateLimitMiddleware creates rate limiter based on user subscription tier
func TierBasedRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &AdvancedRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		EnableLogging:  true,
		CustomKeyFunc:  TierBasedKeyExtractor,
		KeyDescription: "user-tier",
		ErrorMessage:   "Rate limit exceeded for your subscription tier",
		OnLimitExceeded: func(c *gin.Context, info *AdvancedRequestInfo) {
			tier := c.GetHeader("X-User-Tier")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Tier rate limit exceeded",
				"tier":        tier,
				"client":      info.ClientKey,
				"message":     "Consider upgrading your subscription for higher limits",
				"upgrade_url": "https://your-app.com/upgrade",
			})
			c.Abort()
		},
	}
	limiter := NewAdvancedRateLimiter(config)
	return limiter.Middleware()
}

// CustomAdvancedRateLimitMiddleware creates rate limiter with custom key function
func CustomAdvancedRateLimitMiddleware(requestsPerSecond float64, burst int, keyFunc func(*gin.Context) string, keyDescription string) gin.HandlerFunc {
	config := &AdvancedRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		CustomKeyFunc:  keyFunc,
		KeyDescription: keyDescription,
		ErrorMessage:   "Rate limit exceeded for this client",
	}
	limiter := NewAdvancedRateLimiter(config)
	return limiter.Middleware()
}
