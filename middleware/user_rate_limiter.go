// user_rate_limiter.go
// Purpose: PER-USER rate limiting only - each user gets their own rate limit
// Use case: Fair limiting per authenticated user, SaaS applications, user-facing APIs

package middleware

import (
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

// Ensure it implements RateLimiter interface
var _ RateLimiter = (*UserRateLimiter)(nil)

// UserRateLimiterConfig for user-based rate limiting
type UserRateLimiterConfig struct {
	Rate               rate.Limit    // Requests per second PER USER
	Burst              int           // Burst capacity PER USER
	MaxUsers           int           // Maximum number of users to track
	CleanupInterval    time.Duration // How often to cleanup old user entries
	UserTTL            time.Duration // Time to live for inactive user entries
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	UserIDHeaders      []string      // Headers to check for user ID (in order of priority)
	FallbackToIP       bool          // Whether to fallback to IP if no user ID found
	RequireAuth        bool          // Whether to require authentication (reject if no user ID)
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *UserRequestInfo)
	OnRequestProcessed func(*gin.Context, *UserRequestInfo, bool)
	OnUserExtracted    func(*gin.Context, string) // Called when user ID is extracted
}

// UserRequestInfo contains information about user-based request
type UserRequestInfo struct {
	UserID      string
	IP          string // Fallback identification
	UserAgent   string
	Path        string
	Method      string
	Timestamp   time.Time
	Allowed     bool
	Remaining   int
	IsAnonymous bool   // True if fallback to IP was used
	AuthMethod  string // How user was identified (header name, ip, etc.)
}

// UserLimiterEntry represents a rate limiter entry for a specific user
type UserLimiterEntry struct {
	limiter      *rate.Limiter
	lastAccess   time.Time
	created      time.Time
	requestCount int64
	blockedCount int64
	userAgent    string // Track user agent for monitoring
}

// UserRateLimiter manages rate limiting per user
type UserRateLimiter struct {
	limiters      map[string]*UserLimiterEntry // Map: UserID -> RateLimiter
	mu            sync.RWMutex
	config        *UserRateLimiterConfig
	stats         *UserStats
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

func (url *UserRateLimiter) Type() RateLimiterType {
	return UserType
}

func (url *UserRateLimiter) Algorithm() Algorithm {
	return TokenBucketAlg
}

// UserStats holds statistics about user rate limiting
type UserStats struct {
	*BaseStats
	TotalUsers     int64
	ActiveUsers    int64
	AnonymousUsers int64
	UnauthRequests int64 // Requests rejected due to missing auth
}

// NewUserRateLimiter creates a new user-based rate limiter
func NewUserRateLimiter(config *UserRateLimiterConfig) *UserRateLimiter {
	if config == nil {
		config = DefaultUserConfig()
	}

	// Set defaults
	if config.MaxUsers <= 0 {
		config.MaxUsers = 50000 // Users typically fewer than IPs but need larger tracking
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 10 * time.Minute
	}
	if config.UserTTL <= 0 {
		config.UserTTL = 24 * time.Hour // Users stay active longer than IPs
	}
	if len(config.UserIDHeaders) == 0 {
		config.UserIDHeaders = []string{"X-User-ID", "User-ID", "X-UID", "Authorization"}
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Rate limit exceeded for this user"
	}

	limiter := &UserRateLimiter{
		limiters:    make(map[string]*UserLimiterEntry),
		config:      config,
		stopCleanup: make(chan struct{}),
		stats: &UserStats{
			BaseStats: &BaseStats{
				StartTime: time.Now(),
			},
		},
	}

	// Start cleanup goroutine
	limiter.startCleanup()

	return limiter
}

// DefaultUserConfig returns default configuration for user rate limiter
func DefaultUserConfig() *UserRateLimiterConfig {
	return &UserRateLimiterConfig{
		Rate:            rate.Limit(100), // 100 req/sec per user
		Burst:           20,              // 20 burst per user
		MaxUsers:        50000,           // Track up to 50k users
		CleanupInterval: 10 * time.Minute,
		UserTTL:         24 * time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		UserIDHeaders:   []string{"X-User-ID", "User-ID", "X-UID"},
		FallbackToIP:    true,  // Allow fallback to IP
		RequireAuth:     false, // Don't require authentication
		ErrorMessage:    "Rate limit exceeded for this user",
	}
}

// extractUserID extracts user ID from request headers
func (url *UserRateLimiter) extractUserID(c *gin.Context) (string, string, bool) {
	// Try each header in order of priority
	for _, header := range url.config.UserIDHeaders {
		userID := c.GetHeader(header)
		if userID != "" {
			// Handle Authorization header specially
			if header == "Authorization" {
				// Extract user ID from JWT token or Bearer token
				userID = url.extractUserFromAuth(userID)
				if userID == "" {
					continue
				}
			}

			// Call user extracted callback if provided
			if url.config.OnUserExtracted != nil {
				url.config.OnUserExtracted(c, userID)
			}

			return "user:" + userID, header, false
		}
	}

	// No user ID found
	if url.config.RequireAuth {
		return "", "", false // Reject request
	}

	if url.config.FallbackToIP {
		return "anonymous:" + c.ClientIP(), "ip-fallback", true
	}

	return "", "", false // No identification possible
}

// extractUserFromAuth extracts user ID from Authorization header
func (url *UserRateLimiter) extractUserFromAuth(authHeader string) string {
	// This is a simplified example - implement according to your auth system
	// For JWT tokens, you would parse and extract user ID from the token

	// Example for Bearer tokens: "Bearer user123"
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token := authHeader[7:]
		// Parse JWT token here and extract user ID
		// For now, return a mock user ID
		return token // Simplified - replace with actual JWT parsing
	}

	// For other auth schemes, implement accordingly
	return ""
}

// startCleanup starts the cleanup goroutine for removing old user entries
func (url *UserRateLimiter) startCleanup() {
	url.cleanupTicker = time.NewTicker(url.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-url.cleanupTicker.C:
				url.cleanup()
			case <-url.stopCleanup:
				url.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old and inactive user entries
func (url *UserRateLimiter) cleanup() {
	url.mu.Lock()
	defer url.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-url.config.UserTTL)
	removed := 0

	// Remove users that haven't been active recently
	for userID, entry := range url.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(url.limiters, userID)
			removed++
		}
	}

	// If still over max users, remove oldest entries
	if len(url.limiters) > url.config.MaxUsers {
		type userEntry struct {
			userID string
			entry  *UserLimiterEntry
		}

		var entries []userEntry
		for userID, entry := range url.limiters {
			entries = append(entries, userEntry{userID, entry})
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
		toRemove := len(url.limiters) - url.config.MaxUsers
		for i := 0; i < toRemove && i < len(entries); i++ {
			delete(url.limiters, entries[i].userID)
			removed++
		}
	}

	if url.config.EnableLogging && removed > 0 {
		log.Printf("User Rate Limiter: Cleaned up %d user entries, active users: %d", removed, len(url.limiters))
	}

	// Update stats
	atomic.StoreInt64(&url.stats.ActiveUsers, int64(len(url.limiters)))
}

// Stop stops the cleanup goroutine
func (url *UserRateLimiter) Stop() {
	close(url.stopCleanup)
}

// getLimiterForUser gets or creates a rate limiter for the specific user
func (url *UserRateLimiter) getLimiterForUser(userID string, userAgent string) *rate.Limiter {
	url.mu.Lock()
	defer url.mu.Unlock()

	entry, exists := url.limiters[userID]
	if !exists {
		// Check if we're at max capacity
		if len(url.limiters) >= url.config.MaxUsers {
			// Find and remove the oldest entry
			var oldestUserID string
			var oldestTime time.Time = time.Now()

			for entryUserID, entryData := range url.limiters {
				if entryData.lastAccess.Before(oldestTime) {
					oldestTime = entryData.lastAccess
					oldestUserID = entryUserID
				}
			}

			if oldestUserID != "" {
				delete(url.limiters, oldestUserID)
			}
		}

		// Create new limiter for this user
		limiter := rate.NewLimiter(url.config.Rate, url.config.Burst)
		entry = &UserLimiterEntry{
			limiter:    limiter,
			lastAccess: time.Now(),
			created:    time.Now(),
			userAgent:  userAgent,
		}
		url.limiters[userID] = entry

		// Update stats
		atomic.AddInt64(&url.stats.TotalUsers, 1)
	} else {
		entry.lastAccess = time.Now()
		entry.userAgent = userAgent // Update user agent
	}

	return entry.limiter
}

// updateUserStats updates statistics for specific user
func (url *UserRateLimiter) updateUserStats(userID string, allowed bool, isAnonymous bool) {
	url.mu.RLock()
	entry := url.limiters[userID]
	url.mu.RUnlock()

	if entry != nil {
		if allowed {
			atomic.AddInt64(&entry.requestCount, 1)
		} else {
			atomic.AddInt64(&entry.blockedCount, 1)
		}
	}

	// Update global stats
	atomic.AddInt64(&url.stats.TotalRequests, 1)
	if allowed {
		atomic.AddInt64(&url.stats.AllowedRequests, 1)
	} else {
		atomic.AddInt64(&url.stats.BlockedRequests, 1)
	}

	if isAnonymous {
		atomic.AddInt64(&url.stats.AnonymousUsers, 1)
	}
}

// estimateRemainingForUser estimates remaining requests for specific user
func (url *UserRateLimiter) estimateRemainingForUser(userID string) int {
	url.mu.RLock()
	entry, exists := url.limiters[userID]
	url.mu.RUnlock()

	if !exists {
		return url.config.Burst
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
		return url.config.Burst - 1
	}

	return 0
}

// createUserRequestInfo creates UserRequestInfo for the current request
func (url *UserRateLimiter) createUserRequestInfo(c *gin.Context, userID, authMethod string, isAnonymous, allowed bool) *UserRequestInfo {
	remaining := 0
	if allowed {
		remaining = url.estimateRemainingForUser(userID)
	}

	return &UserRequestInfo{
		UserID:      userID,
		IP:          c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		Path:        c.Request.URL.Path,
		Method:      c.Request.Method,
		Timestamp:   time.Now(),
		Allowed:     allowed,
		Remaining:   remaining,
		IsAnonymous: isAnonymous,
		AuthMethod:  authMethod,
	}
}

// setHeaders sets user-specific rate limit headers
func (url *UserRateLimiter) setHeaders(c *gin.Context, info *UserRequestInfo) {
	if !url.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(url.config.Rate) * 60)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Minute).Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", "per-user")
	c.Header("X-RateLimit-User", info.UserID)
	c.Header("X-RateLimit-Auth-Method", info.AuthMethod)

	if !info.Allowed {
		retryAfter := int64(time.Duration(float64(time.Second) / float64(url.config.Rate)).Seconds())
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

// logEvent logs user rate limiting events
func (url *UserRateLimiter) logEvent(info *UserRequestInfo) {
	if !url.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if !info.Allowed {
		status = "BLOCKED"
	}

	userType := "AUTHENTICATED"
	if info.IsAnonymous {
		userType = "ANONYMOUS"
	}

	log.Printf("[USER_RATE_LIMITER] %s - User: %s (%s), Method: %s, Path: %s, Auth: %s, Remaining: %d",
		status, info.UserID, userType, info.Method, info.Path, info.AuthMethod, info.Remaining)
}

// handleLimitExceeded handles when user rate limit is exceeded
func (url *UserRateLimiter) handleLimitExceeded(c *gin.Context, info *UserRequestInfo) {
	// Call custom handler if provided
	if url.config.OnLimitExceeded != nil {
		url.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if url.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, url.config.ErrorResponse)
		c.Abort()
		return
	}

	// Default error response
	response := gin.H{
		"error":       url.config.ErrorMessage,
		"user":        info.UserID,
		"scope":       "per-user",
		"auth_method": info.AuthMethod,
		"timestamp":   info.Timestamp.Format(time.RFC3339),
	}

	if info.IsAnonymous {
		response["message"] = "Rate limit exceeded for anonymous user (consider authentication for higher limits)"
		response["suggestion"] = "Authenticate to get higher rate limits"
	} else {
		response["message"] = "Rate limit exceeded for authenticated user"
	}

	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// handleUnauthenticated handles requests without user identification when required
func (url *UserRateLimiter) handleUnauthenticated(c *gin.Context) {
	atomic.AddInt64(&url.stats.UnauthRequests, 1)

	c.JSON(http.StatusUnauthorized, gin.H{
		"error":   "Authentication required",
		"message": "User identification is required for this endpoint",
		"scope":   "per-user",
	})
	c.Abort()
}

// Middleware returns the user rate limiting middleware
func (url *UserRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user ID from request
		userID, authMethod, isAnonymous := url.extractUserID(c)

		// Handle cases where user ID couldn't be extracted
		if userID == "" {
			url.handleUnauthenticated(c)
			return
		}

		// Get user-specific rate limiter
		limiter := url.getLimiterForUser(userID, c.GetHeader("User-Agent"))

		// Check rate limit for this specific user
		allowed := limiter.Allow()

		// Update statistics
		url.updateUserStats(userID, allowed, isAnonymous)

		// Create request info
		info := url.createUserRequestInfo(c, userID, authMethod, isAnonymous, allowed)

		// Set headers
		url.setHeaders(c, info)

		// Log event
		url.logEvent(info)

		// Call request handler if provided
		if url.config.OnRequestProcessed != nil {
			url.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			url.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns user rate limiting statistics
func (url *UserRateLimiter) GetStats() Stats {
	url.mu.RLock()
	activeUsers := int64(len(url.limiters))
	url.mu.RUnlock()

	return UserStats{
		BaseStats: &BaseStats{
			TotalRequests:   atomic.LoadInt64(&url.stats.TotalRequests),
			AllowedRequests: atomic.LoadInt64(&url.stats.AllowedRequests),
			BlockedRequests: atomic.LoadInt64(&url.stats.BlockedRequests),
			StartTime:       url.stats.StartTime,
			LimiterType:     UserType,
		},
		TotalUsers:     atomic.LoadInt64(&url.stats.TotalUsers),
		ActiveUsers:    activeUsers,
		AnonymousUsers: atomic.LoadInt64(&url.stats.AnonymousUsers),
		UnauthRequests: atomic.LoadInt64(&url.stats.UnauthRequests),
	}
}

// GetUserStats returns statistics for a specific user
func (url *UserRateLimiter) GetUserStats(userID string) *UserLimiterEntry {
	url.mu.RLock()
	defer url.mu.RUnlock()

	if entry, exists := url.limiters[userID]; exists {
		return &UserLimiterEntry{
			lastAccess:   entry.lastAccess,
			created:      entry.created,
			requestCount: atomic.LoadInt64(&entry.requestCount),
			blockedCount: atomic.LoadInt64(&entry.blockedCount),
			userAgent:    entry.userAgent,
		}
	}
	return nil
}

// ResetStats resets all user rate limiting statistics
func (url *UserRateLimiter) ResetStats() {
	atomic.StoreInt64(&url.stats.TotalRequests, 0)
	atomic.StoreInt64(&url.stats.AllowedRequests, 0)
	atomic.StoreInt64(&url.stats.BlockedRequests, 0)
	atomic.StoreInt64(&url.stats.UnauthRequests, 0)
	atomic.StoreInt64(&url.stats.AnonymousUsers, 0)
	url.stats.StartTime = time.Now()
}

// =============================================================================
// CONVENIENCE FUNCTIONS - All for PER-USER rate limiting only
// =============================================================================

// UserRateLimitMiddleware creates a simple user-based rate limiter
// Each user gets their own rate limit
func UserRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &UserRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		FallbackToIP:  true,
	}
	limiter := NewUserRateLimiter(config)
	return limiter.Middleware()
}

// AuthenticatedUserRateLimitMiddleware requires authentication
func AuthenticatedUserRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &UserRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		RequireAuth:   true,  // Require authentication
		FallbackToIP:  false, // No fallback to IP
	}
	limiter := NewUserRateLimiter(config)
	return limiter.Middleware()
}

// SaaSUserRateLimitMiddleware for SaaS applications with tier-based limiting
func SaaSUserRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &UserRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		RequireAuth:   true,
		FallbackToIP:  false,
		UserIDHeaders: []string{"X-User-ID", "Authorization"},
		OnLimitExceeded: func(c *gin.Context, info *UserRequestInfo) {
			// SaaS-specific response with upgrade suggestions
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":        "User rate limit exceeded",
				"user":         info.UserID,
				"message":      "You have exceeded your plan's rate limit",
				"upgrade_url":  "https://your-app.com/upgrade",
				"current_plan": c.GetHeader("X-User-Plan"),
			})
			c.Abort()
		},
	}
	limiter := NewUserRateLimiter(config)
	return limiter.Middleware()
}

// FlexibleUserRateLimitMiddleware allows both authenticated and anonymous users
func FlexibleUserRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &UserRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		RequireAuth:   false,
		FallbackToIP:  true,
		UserIDHeaders: []string{"X-User-ID", "User-ID", "Authorization"},
		OnRequestProcessed: func(c *gin.Context, info *UserRequestInfo, allowed bool) {
			// Set user context for downstream handlers
			if !info.IsAnonymous {
				c.Set("authenticated_user", info.UserID)
			}
			c.Set("rate_limit_info", info)
		},
	}
	limiter := NewUserRateLimiter(config)
	return limiter.Middleware()
}
