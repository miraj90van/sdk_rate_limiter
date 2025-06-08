package middleware

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

// SecurityConfig contains all security-related configurations
type SecurityConfig struct {
	// IP-based security
	IPWhitelist []string `json:"ip_whitelist"` // Allowed IPs (bypass rate limiting)
	IPBlacklist []string `json:"ip_blacklist"` // Blocked IPs (immediately reject)

	// Request validation
	MaxRequestSize int64 `json:"max_request_size"` // Maximum request body size in bytes
	MaxHeaderSize  int   `json:"max_header_size"`  // Maximum header size

	// Authentication
	RequireAuth  bool     `json:"require_auth"`   // Require authentication
	ValidAPIKeys []string `json:"valid_api_keys"` // Valid API keys
	JWTSecret    string   `json:"jwt_secret"`     // JWT secret for validation

	// Rate limiting security
	EnableStrictMode    bool          `json:"enable_strict_mode"`   // Strict rate limiting mode
	SuspiciousThreshold int           `json:"suspicious_threshold"` // Threshold for suspicious activity
	BanDuration         time.Duration `json:"ban_duration"`         // Duration to ban suspicious IPs

	// Headers and CORS
	EnableSecurityHeaders bool     `json:"enable_security_headers"` // Add security headers
	AllowedOrigins        []string `json:"allowed_origins"`         // CORS allowed origins

	// Anti-abuse
	EnableHoneypot     bool `json:"enable_honeypot"`         // Enable honeypot endpoints
	EnableBotDetection bool `json:"enable_bot_detection"`    // Basic bot detection
	MaxConcurrentReqs  int  `json:"max_concurrent_requests"` // Max concurrent requests per IP
}

// DefaultSecurityConfig returns secure default configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxRequestSize:        10 * 1024 * 1024, // 10MB
		MaxHeaderSize:         8192,             // 8KB
		RequireAuth:           false,
		EnableStrictMode:      false,
		SuspiciousThreshold:   1000,      // 1000 requests
		BanDuration:           time.Hour, // 1 hour ban
		EnableSecurityHeaders: true,
		EnableHoneypot:        false,
		EnableBotDetection:    true,
		MaxConcurrentReqs:     100, // 100 concurrent requests per IP
	}
}

// =============================================================================
// SECURITY MIDDLEWARE
// =============================================================================

// SecurityMiddleware provides comprehensive security features
type SecurityMiddleware struct {
	config         *SecurityConfig
	ipWhitelistMap map[string]bool
	ipBlacklistMap map[string]bool
	apiKeyMap      map[string]bool
	bannedIPs      sync.Map // IP -> ban expiry time
	suspiciousIPs  sync.Map // IP -> request count
	concurrentReqs sync.Map // IP -> current request count
	mutex          sync.RWMutex
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config *SecurityConfig) *SecurityMiddleware {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	sm := &SecurityMiddleware{
		config:         config,
		ipWhitelistMap: make(map[string]bool),
		ipBlacklistMap: make(map[string]bool),
		apiKeyMap:      make(map[string]bool),
	}

	// Build lookup maps for performance
	sm.buildLookupMaps()

	// Start cleanup routine
	go sm.cleanupRoutine()

	return sm
}

// buildLookupMaps builds lookup maps for fast IP and API key validation
func (sm *SecurityMiddleware) buildLookupMaps() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Build IP whitelist map
	for _, ip := range sm.config.IPWhitelist {
		sm.ipWhitelistMap[ip] = true
	}

	// Build IP blacklist map
	for _, ip := range sm.config.IPBlacklist {
		sm.ipBlacklistMap[ip] = true
	}

	// Build API key map
	for _, key := range sm.config.ValidAPIKeys {
		sm.apiKeyMap[key] = true
	}
}

// =============================================================================
// SECURITY CHECKS
// =============================================================================

// isIPWhitelisted checks if IP is in whitelist
func (sm *SecurityMiddleware) isIPWhitelisted(ip string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Direct IP check
	if sm.ipWhitelistMap[ip] {
		return true
	}

	// CIDR range check
	for whitelistedIP := range sm.ipWhitelistMap {
		if sm.isIPInCIDR(ip, whitelistedIP) {
			return true
		}
	}

	return false
}

// isIPBlacklisted checks if IP is in blacklist
func (sm *SecurityMiddleware) isIPBlacklisted(ip string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Direct IP check
	if sm.ipBlacklistMap[ip] {
		return true
	}

	// CIDR range check
	for blacklistedIP := range sm.ipBlacklistMap {
		if sm.isIPInCIDR(ip, blacklistedIP) {
			return true
		}
	}

	return false
}

// isIPBanned checks if IP is temporarily banned
func (sm *SecurityMiddleware) isIPBanned(ip string) bool {
	if banExpiry, exists := sm.bannedIPs.Load(ip); exists {
		if time.Now().Before(banExpiry.(time.Time)) {
			return true
		}
		// Ban expired, remove it
		sm.bannedIPs.Delete(ip)
	}
	return false
}

// isIPInCIDR checks if IP is in CIDR range
func (sm *SecurityMiddleware) isIPInCIDR(ip, cidr string) bool {
	if !strings.Contains(cidr, "/") {
		return ip == cidr
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	return network.Contains(clientIP)
}

// validateAPIKey validates API key from request
func (sm *SecurityMiddleware) validateAPIKey(c *gin.Context) bool {
	if !sm.config.RequireAuth {
		return true
	}

	// Check X-API-Key header
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		// Check Authorization header
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			apiKey = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if apiKey == "" {
		return false
	}

	sm.mutex.RLock()
	valid := sm.apiKeyMap[apiKey]
	sm.mutex.RUnlock()

	return valid
}

// trackSuspiciousActivity tracks potentially suspicious activity
func (sm *SecurityMiddleware) trackSuspiciousActivity(ip string) {
	if !sm.config.EnableStrictMode {
		return
	}

	// Increment suspicious activity counter
	count := int64(1)
	if existing, exists := sm.suspiciousIPs.Load(ip); exists {
		count = existing.(int64) + 1
	}
	sm.suspiciousIPs.Store(ip, count)

	// Ban IP if threshold exceeded
	if count >= int64(sm.config.SuspiciousThreshold) {
		banExpiry := time.Now().Add(sm.config.BanDuration)
		sm.bannedIPs.Store(ip, banExpiry)
		sm.suspiciousIPs.Delete(ip) // Reset counter after ban
	}
}

// =============================================================================
// BOT DETECTION
// =============================================================================

// detectBot performs basic bot detection
func (sm *SecurityMiddleware) detectBot(c *gin.Context) bool {
	if !sm.config.EnableBotDetection {
		return false
	}

	userAgent := c.GetHeader("User-Agent")

	// Common bot patterns
	botPatterns := []string{
		`(?i)bot`,
		`(?i)crawler`,
		`(?i)spider`,
		`(?i)scraper`,
		`(?i)curl`,
		`(?i)wget`,
		`(?i)python-requests`,
		`(?i)go-http-client`,
	}

	for _, pattern := range botPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return true
		}
	}

	// Check for missing common headers
	if userAgent == "" || c.GetHeader("Accept") == "" {
		return true
	}

	return false
}

// =============================================================================
// CONCURRENT REQUEST TRACKING
// =============================================================================

// trackConcurrentRequest tracks concurrent requests per IP
func (sm *SecurityMiddleware) trackConcurrentRequest(ip string) bool {
	if sm.config.MaxConcurrentReqs <= 0 {
		return true
	}

	count := int64(1)
	if existing, exists := sm.concurrentReqs.Load(ip); exists {
		count = existing.(int64) + 1
	}

	if count > int64(sm.config.MaxConcurrentReqs) {
		return false
	}

	sm.concurrentReqs.Store(ip, count)
	return true
}

// releaseConcurrentRequest releases a concurrent request slot
func (sm *SecurityMiddleware) releaseConcurrentRequest(ip string) {
	if existing, exists := sm.concurrentReqs.Load(ip); exists {
		count := existing.(int64) - 1
		if count <= 0 {
			sm.concurrentReqs.Delete(ip)
		} else {
			sm.concurrentReqs.Store(ip, count)
		}
	}
}

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// setSecurityHeaders sets common security headers
func (sm *SecurityMiddleware) setSecurityHeaders(c *gin.Context) {
	if !sm.config.EnableSecurityHeaders {
		return
	}

	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'",
	}

	for header, value := range headers {
		c.Header(header, value)
	}
}

// =============================================================================
// MIDDLEWARE IMPLEMENTATION
// =============================================================================

// Middleware returns the security middleware function
func (sm *SecurityMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Set security headers first
		sm.setSecurityHeaders(c)

		// 1. Check IP blacklist
		if sm.isIPBlacklisted(clientIP) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "IP address is blacklisted",
				"code":  "BLACKLISTED_IP",
			})
			c.Abort()
			return
		}

		// 2. Check if IP is banned
		if sm.isIPBanned(clientIP) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "IP address is temporarily banned",
				"code":  "BANNED_IP",
			})
			c.Abort()
			return
		}

		// 3. Check concurrent request limit
		if !sm.trackConcurrentRequest(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many concurrent requests",
				"code":  "CONCURRENT_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}

		// Ensure we release the concurrent request slot
		defer sm.releaseConcurrentRequest(clientIP)

		// 4. Skip further checks for whitelisted IPs
		if sm.isIPWhitelisted(clientIP) {
			c.Set("security_whitelisted", true)
			c.Next()
			return
		}

		// 5. Check request size
		if c.Request.ContentLength > sm.config.MaxRequestSize {
			sm.trackSuspiciousActivity(clientIP)
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "Request entity too large",
				"code":     "REQUEST_TOO_LARGE",
				"max_size": sm.config.MaxRequestSize,
			})
			c.Abort()
			return
		}

		// 6. Check header size
		headerSize := 0
		for name, values := range c.Request.Header {
			headerSize += len(name)
			for _, value := range values {
				headerSize += len(value)
			}
		}
		if headerSize > sm.config.MaxHeaderSize {
			sm.trackSuspiciousActivity(clientIP)
			c.JSON(http.StatusRequestHeaderFieldsTooLarge, gin.H{
				"error": "Request header too large",
				"code":  "HEADER_TOO_LARGE",
			})
			c.Abort()
			return
		}

		// 7. Validate API key if required
		if !sm.validateAPIKey(c) {
			sm.trackSuspiciousActivity(clientIP)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or missing API key",
				"code":  "INVALID_API_KEY",
			})
			c.Abort()
			return
		}

		// 8. Bot detection
		if sm.detectBot(c) {
			c.Set("security_bot_detected", true)
			// Don't block bots immediately, just mark them
			// Rate limiting might handle them differently
		}

		// 9. Honeypot check
		if sm.config.EnableHoneypot && sm.isHoneypotRequest(c) {
			sm.trackSuspiciousActivity(clientIP)
			// Log but don't respond to avoid revealing honeypot
			c.Status(http.StatusNotFound)
			c.Abort()
			return
		}

		c.Next()
	}
}

// =============================================================================
// HONEYPOT IMPLEMENTATION
// =============================================================================

// isHoneypotRequest checks if request is targeting honeypot endpoints
func (sm *SecurityMiddleware) isHoneypotRequest(c *gin.Context) bool {
	honeypotPaths := []string{
		"/admin",
		"/administrator",
		"/wp-admin",
		"/wp-login.php",
		"/.env",
		"/config.php",
		"/phpmyadmin",
		"/mysql",
		"/login.php",
		"/admin.php",
	}

	requestPath := c.Request.URL.Path
	for _, path := range honeypotPaths {
		if strings.Contains(requestPath, path) {
			return true
		}
	}

	return false
}

// =============================================================================
// CLEANUP ROUTINE
// =============================================================================

// cleanupRoutine periodically cleans up expired data
func (sm *SecurityMiddleware) cleanupRoutine() {
	ticker := time.NewTicker(time.Minute * 5) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanup()
		}
	}
}

// cleanup removes expired bans and resets suspicious activity counters
func (sm *SecurityMiddleware) cleanup() {
	now := time.Now()

	// Clean up expired bans
	sm.bannedIPs.Range(func(key, value interface{}) bool {
		if banExpiry := value.(time.Time); now.After(banExpiry) {
			sm.bannedIPs.Delete(key)
		}
		return true
	})

	// Reset suspicious activity counters every hour
	sm.suspiciousIPs.Range(func(key, value interface{}) bool {
		// Reset counter to give IPs a fresh start
		sm.suspiciousIPs.Delete(key)
		return true
	})
}

// =============================================================================
// ENHANCED RATE LIMITER WITH SECURITY
// =============================================================================

// SecureRateLimiterConfig extends rate limiter config with security features
type SecureRateLimiterConfig struct {
	*TokenBucketConfig
	Security *SecurityConfig
}

// SecureTokenBucketRateLimiter combines rate limiting with security features
type SecureTokenBucketRateLimiter struct {
	*TokenBucketRateLimiter
	security *SecurityMiddleware
}

// NewSecureTokenBucketRateLimiter creates a secure rate limiter
func NewSecureTokenBucketRateLimiter(config *SecureRateLimiterConfig) *SecureTokenBucketRateLimiter {
	if config == nil {
		config = &SecureRateLimiterConfig{
			TokenBucketConfig: DefaultTokenBucketConfig(),
			Security:          DefaultSecurityConfig(),
		}
	}

	rateLimiter := NewTokenBucketRateLimiter(config.TokenBucketConfig)
	securityMiddleware := NewSecurityMiddleware(config.Security)

	return &SecureTokenBucketRateLimiter{
		TokenBucketRateLimiter: rateLimiter,
		security:               securityMiddleware,
	}
}

// Middleware returns combined security and rate limiting middleware
func (srl *SecureTokenBucketRateLimiter) Middleware() gin.HandlerFunc {
	securityMiddleware := srl.security.Middleware()
	rateLimitMiddleware := srl.TokenBucketRateLimiter.Middleware()

	return func(c *gin.Context) {
		// Apply security checks first
		securityMiddleware(c)
		if c.IsAborted() {
			return
		}

		// Skip rate limiting for whitelisted IPs
		if whitelisted, exists := c.Get("security_whitelisted"); exists && whitelisted.(bool) {
			c.Next()
			return
		}

		// Apply different rate limits for bots
		if botDetected, exists := c.Get("security_bot_detected"); exists && botDetected.(bool) {
			// Apply stricter rate limiting for bots
			// Could implement different rate limit here
		}

		// Apply rate limiting
		rateLimitMiddleware(c)
	}
}

// =============================================================================
// SECURITY MANAGEMENT ENDPOINTS
// =============================================================================

// SecurityManager provides endpoints for security management
type SecurityManager struct {
	security *SecurityMiddleware
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(security *SecurityMiddleware) *SecurityManager {
	return &SecurityManager{security: security}
}

// GetSecurityStats returns security statistics
func (sm *SecurityManager) GetSecurityStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := map[string]interface{}{
			"banned_ips":      sm.getBannedIPs(),
			"suspicious_ips":  sm.getSuspiciousIPs(),
			"concurrent_reqs": sm.getConcurrentRequests(),
			"config":          sm.security.config,
		}
		c.JSON(http.StatusOK, stats)
	}
}

// BanIP bans an IP address
func (sm *SecurityManager) BanIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			IP       string        `json:"ip" binding:"required"`
			Duration time.Duration `json:"duration"`
			Reason   string        `json:"reason"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if request.Duration == 0 {
			request.Duration = sm.security.config.BanDuration
		}

		banExpiry := time.Now().Add(request.Duration)
		sm.security.bannedIPs.Store(request.IP, banExpiry)

		c.JSON(http.StatusOK, gin.H{
			"message":    "IP banned successfully",
			"ip":         request.IP,
			"ban_expiry": banExpiry,
			"reason":     request.Reason,
		})
	}
}

// UnbanIP removes IP from ban list
func (sm *SecurityManager) UnbanIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "IP address required"})
			return
		}

		sm.security.bannedIPs.Delete(ip)
		c.JSON(http.StatusOK, gin.H{
			"message": "IP unbanned successfully",
			"ip":      ip,
		})
	}
}

// Helper methods for getting statistics
func (sm *SecurityManager) getBannedIPs() []map[string]interface{} {
	var banned []map[string]interface{}
	sm.security.bannedIPs.Range(func(key, value interface{}) bool {
		banned = append(banned, map[string]interface{}{
			"ip":         key.(string),
			"ban_expiry": value.(time.Time),
		})
		return true
	})
	return banned
}

func (sm *SecurityManager) getSuspiciousIPs() []map[string]interface{} {
	var suspicious []map[string]interface{}
	sm.security.suspiciousIPs.Range(func(key, value interface{}) bool {
		suspicious = append(suspicious, map[string]interface{}{
			"ip":    key.(string),
			"count": value.(int64),
		})
		return true
	})
	return suspicious
}

func (sm *SecurityManager) getConcurrentRequests() []map[string]interface{} {
	var concurrent []map[string]interface{}
	sm.security.concurrentReqs.Range(func(key, value interface{}) bool {
		concurrent = append(concurrent, map[string]interface{}{
			"ip":    key.(string),
			"count": value.(int64),
		})
		return true
	})
	return concurrent
}

// =============================================================================
// USAGE EXAMPLE
// =============================================================================

/*
func main() {
	// Create secure rate limiter
	config := &SecureRateLimiterConfig{
		TokenBucketConfig: &TokenBucketConfig{
			Rate:  rate.Limit(100),
			Burst: 200,
		},
		Security: &SecurityConfig{
			IPWhitelist:         []string{"127.0.0.1", "192.168.1.0/24"},
			IPBlacklist:         []string{"10.0.0.1"},
			MaxRequestSize:      1024 * 1024, // 1MB
			RequireAuth:         false,
			EnableStrictMode:    true,
			SuspiciousThreshold: 500,
			BanDuration:         time.Hour,
			EnableSecurityHeaders: true,
			EnableBotDetection:  true,
		},
	}

	secureRateLimiter := NewSecureTokenBucketRateLimiter(config)
	defer secureRateLimiter.Stop()

	// Setup Gin router
	r := gin.Default()

	// Apply secure rate limiting middleware
	r.Use(secureRateLimiter.Middleware())

	// Security management endpoints
	securityManager := NewSecurityManager(secureRateLimiter.security)
	admin := r.Group("/admin")
	{
		admin.GET("/security/stats", securityManager.GetSecurityStats())
		admin.POST("/security/ban", securityManager.BanIP())
		admin.DELETE("/security/ban/:ip", securityManager.UnbanIP())
	}

	// Your API endpoints
	r.GET("/api/data", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": "secure data"})
	})

	r.Run(":8080")
}
*/
