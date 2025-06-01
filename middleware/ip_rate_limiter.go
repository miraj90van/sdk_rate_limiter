// ip_rate_limiter_middleware.go
// Purpose: PER-IP rate limiting only - each IP gets its own rate limit
// Use case: Fair limiting per IP address, prevent single IP from hogging resources

package middleware

import (
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

// IPRateLimiterConfig for IP-based rate limiting
type IPRateLimiterConfig struct {
	Rate               rate.Limit    // Requests per second PER IP
	Burst              int           // Burst capacity PER IP
	MaxIPs             int           // Maximum number of IPs to track
	CleanupInterval    time.Duration // How often to cleanup old IP entries
	IPTTL              time.Duration // Time to live for inactive IP entries
	EnableHeaders      bool          // Include rate limit headers
	EnableLogging      bool          // Enable logging
	TrustedProxies     []string      // List of trusted proxy CIDRs for real IP extraction
	WhitelistIPs       []string      // IPs to whitelist (no rate limiting)
	BlacklistIPs       []string      // IPs to blacklist (always block)
	ErrorMessage       string        // Custom error message
	ErrorResponse      interface{}   // Custom error response structure
	OnLimitExceeded    func(*gin.Context, *IPRequestInfo)
	OnRequestProcessed func(*gin.Context, *IPRequestInfo, bool)
}

// IPRequestInfo contains information about IP-based request
type IPRequestInfo struct {
	IP            string
	OriginalIP    string // Before proxy processing
	UserAgent     string
	Path          string
	Method        string
	Timestamp     time.Time
	Allowed       bool
	Remaining     int
	IsWhitelisted bool
	IsBlacklisted bool
}

// IPLimiterEntry represents a rate limiter entry for a specific IP
type IPLimiterEntry struct {
	limiter      *rate.Limiter
	lastAccess   time.Time
	created      time.Time
	requestCount int64
	blockedCount int64
}

// IPRateLimiter manages rate limiting per IP address
type IPRateLimiter struct {
	limiters       map[string]*IPLimiterEntry // Map: IP -> RateLimiter
	mu             sync.RWMutex
	config         *IPRateLimiterConfig
	stats          *IPStats
	cleanupTicker  *time.Ticker
	stopCleanup    chan struct{}
	trustedProxies []*net.IPNet
	whitelistIPs   []*net.IPNet
	blacklistIPs   []*net.IPNet
}

// IPStats holds statistics about IP rate limiting
type IPStats struct {
	*BaseStats
	ActiveIPs       int64
	TotalIPs        int64
	WhitelistedReqs int64
	BlacklistedReqs int64
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(config *IPRateLimiterConfig) *IPRateLimiter {
	if config == nil {
		config = DefaultIPConfig()
	}

	// Set defaults
	if config.MaxIPs <= 0 {
		config.MaxIPs = 10000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.IPTTL <= 0 {
		config.IPTTL = 1 * time.Hour
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Rate limit exceeded for this IP"
	}

	limiter := &IPRateLimiter{
		limiters:    make(map[string]*IPLimiterEntry),
		config:      config,
		stopCleanup: make(chan struct{}),
		stats: &IPStats{
			BaseStats: &BaseStats{
				StartTime:   time.Now(),
				LimiterType: IPType,
			},
		},
	}

	// Parse IP ranges
	limiter.trustedProxies = parseIPRanges(config.TrustedProxies)
	limiter.whitelistIPs = parseIPRanges(config.WhitelistIPs)
	limiter.blacklistIPs = parseIPRanges(config.BlacklistIPs)

	// Start cleanup goroutine
	limiter.startCleanup()

	return limiter
}

// DefaultIPConfig returns default configuration for IP rate limiter
func DefaultIPConfig() *IPRateLimiterConfig {
	return &IPRateLimiterConfig{
		Rate:            rate.Limit(100), // 100 req/sec per IP
		Burst:           20,              // 20 burst per IP
		MaxIPs:          10000,           // Track up to 10k IPs
		CleanupInterval: 5 * time.Minute,
		IPTTL:           1 * time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Rate limit exceeded for this IP",
	}
}

// parseIPRanges parses string IP ranges into net.IPNet slices
func parseIPRanges(ipRanges []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, ipRange := range ipRanges {
		if ipRange == "" {
			continue
		}

		// If it's not a CIDR, treat as single IP
		if !strings.Contains(ipRange, "/") {
			if strings.Contains(ipRange, ":") {
				ipRange += "/128" // IPv6 single host
			} else {
				ipRange += "/32" // IPv4 single host
			}
		}

		_, net, err := net.ParseCIDR(ipRange)
		if err != nil {
			log.Printf("Invalid IP range %s: %v", ipRange, err)
			continue
		}
		nets = append(nets, net)
	}
	return nets
}

// isIPInRanges checks if an IP is in any of the given ranges
func isIPInRanges(ip string, ranges []*net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range ranges {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// extractClientIP extracts the real client IP considering trusted proxies
func (ipr *IPRateLimiter) extractClientIP(c *gin.Context) (string, string) {
	originalIP := c.Request.RemoteAddr

	// Remove port if present
	if host, _, err := net.SplitHostPort(originalIP); err == nil {
		originalIP = host
	}

	clientIP := originalIP

	// Check if request comes from trusted proxy
	if isIPInRanges(originalIP, ipr.trustedProxies) {
		// Extract real IP from headers
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			// Take the first IP from X-Forwarded-For
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
			}
		} else if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
			clientIP = realIP
		}
	}

	return clientIP, originalIP
}

// startCleanup starts the cleanup goroutine for removing old IP entries
func (ipr *IPRateLimiter) startCleanup() {
	ipr.cleanupTicker = time.NewTicker(ipr.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-ipr.cleanupTicker.C:
				ipr.cleanup()
			case <-ipr.stopCleanup:
				ipr.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old and inactive IP entries
func (ipr *IPRateLimiter) cleanup() {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-ipr.config.IPTTL)
	removed := 0

	// Remove IPs that haven't been accessed recently
	for ip, entry := range ipr.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(ipr.limiters, ip)
			removed++
		}
	}

	// If still over max IPs, remove oldest entries
	if len(ipr.limiters) > ipr.config.MaxIPs {
		type ipEntry struct {
			ip    string
			entry *IPLimiterEntry
		}

		var entries []ipEntry
		for ip, entry := range ipr.limiters {
			entries = append(entries, ipEntry{ip, entry})
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
		toRemove := len(ipr.limiters) - ipr.config.MaxIPs
		for i := 0; i < toRemove && i < len(entries); i++ {
			delete(ipr.limiters, entries[i].ip)
			removed++
		}
	}

	if ipr.config.EnableLogging && removed > 0 {
		log.Printf("IP Rate Limiter: Cleaned up %d IP entries, active IPs: %d", removed, len(ipr.limiters))
	}

	// Update stats
	atomic.StoreInt64(&ipr.stats.ActiveIPs, int64(len(ipr.limiters)))
}

// Stop stops the cleanup goroutine
func (ipr *IPRateLimiter) Stop() {
	close(ipr.stopCleanup)
}

// getLimiterForIP gets or creates a rate limiter for the specific IP
func (ipr *IPRateLimiter) getLimiterForIP(ip string) *rate.Limiter {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	entry, exists := ipr.limiters[ip]
	if !exists {
		// Check if we're at max capacity
		if len(ipr.limiters) >= ipr.config.MaxIPs {
			// Find and remove the oldest entry
			var oldestIP string
			var oldestTime time.Time = time.Now()

			for entryIP, entryData := range ipr.limiters {
				if entryData.lastAccess.Before(oldestTime) {
					oldestTime = entryData.lastAccess
					oldestIP = entryIP
				}
			}

			if oldestIP != "" {
				delete(ipr.limiters, oldestIP)
			}
		}

		// Create new limiter for this IP
		limiter := rate.NewLimiter(ipr.config.Rate, ipr.config.Burst)
		entry = &IPLimiterEntry{
			limiter:    limiter,
			lastAccess: time.Now(),
			created:    time.Now(),
		}
		ipr.limiters[ip] = entry

		// Update stats
		atomic.AddInt64(&ipr.stats.TotalIPs, 1)
		atomic.StoreInt64(&ipr.stats.ActiveIPs, int64(len(ipr.limiters)))
	} else {
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

// updateIPStats updates statistics for specific IP
func (ipr *IPRateLimiter) updateIPStats(ip string, allowed bool) {
	ipr.mu.RLock()
	entry := ipr.limiters[ip]
	ipr.mu.RUnlock()

	if entry != nil {
		if allowed {
			atomic.AddInt64(&entry.requestCount, 1)
		} else {
			atomic.AddInt64(&entry.blockedCount, 1)
		}
	}

	// Update global stats
	atomic.AddInt64(&ipr.stats.TotalRequests, 1)
	if allowed {
		atomic.AddInt64(&ipr.stats.AllowedRequests, 1)
	} else {
		atomic.AddInt64(&ipr.stats.BlockedRequests, 1)
	}
}

// estimateRemainingForIP estimates remaining requests for specific IP
func (ipr *IPRateLimiter) estimateRemainingForIP(ip string) int {
	ipr.mu.RLock()
	entry, exists := ipr.limiters[ip]
	ipr.mu.RUnlock()

	if !exists {
		return ipr.config.Burst
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
		return ipr.config.Burst - 1
	}

	return 0
}

// createIPRequestInfo creates IPRequestInfo for the current request
func (ipr *IPRateLimiter) createIPRequestInfo(c *gin.Context, ip, originalIP string, allowed bool) *IPRequestInfo {
	remaining := 0
	if allowed {
		remaining = ipr.estimateRemainingForIP(ip)
	}

	return &IPRequestInfo{
		IP:            ip,
		OriginalIP:    originalIP,
		UserAgent:     c.GetHeader("User-Agent"),
		Path:          c.Request.URL.Path,
		Method:        c.Request.Method,
		Timestamp:     time.Now(),
		Allowed:       allowed,
		Remaining:     remaining,
		IsWhitelisted: isIPInRanges(ip, ipr.whitelistIPs),
		IsBlacklisted: isIPInRanges(ip, ipr.blacklistIPs),
	}
}

// setHeaders sets IP-specific rate limit headers
func (ipr *IPRateLimiter) setHeaders(c *gin.Context, info *IPRequestInfo) {
	if !ipr.config.EnableHeaders {
		return
	}

	limitPerMinute := int64(float64(ipr.config.Rate) * 60)

	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	c.Header("X-RateLimit-Reset", time.Now().Add(time.Minute).Format(time.RFC3339))
	c.Header("X-RateLimit-Scope", "per-ip")
	c.Header("X-RateLimit-IP", info.IP)

	if !info.Allowed {
		retryAfter := int64(time.Duration(float64(time.Second) / float64(ipr.config.Rate)).Seconds())
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

// logEvent logs IP rate limiting events
func (ipr *IPRateLimiter) logEvent(info *IPRequestInfo) {
	if !ipr.config.EnableLogging {
		return
	}

	status := "ALLOWED"
	if info.IsBlacklisted {
		status = "BLACKLISTED"
	} else if info.IsWhitelisted {
		status = "WHITELISTED"
	} else if !info.Allowed {
		status = "BLOCKED"
	}

	log.Printf("[IP_RATE_LIMITER] %s - IP: %s, Method: %s, Path: %s, Remaining: %d",
		status, info.IP, info.Method, info.Path, info.Remaining)
}

// handleLimitExceeded handles when IP rate limit is exceeded
func (ipr *IPRateLimiter) handleLimitExceeded(c *gin.Context, info *IPRequestInfo) {
	// Call custom handler if provided
	if ipr.config.OnLimitExceeded != nil {
		ipr.config.OnLimitExceeded(c, info)
		return
	}

	// Use custom error response if provided
	if ipr.config.ErrorResponse != nil {
		c.JSON(http.StatusTooManyRequests, ipr.config.ErrorResponse)
		c.Abort()
		return
	}

	// Determine reason for blocking
	reason := "rate_limit_exceeded"
	if info.IsBlacklisted {
		reason = "ip_blacklisted"
	}

	// Default error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":     ipr.config.ErrorMessage,
		"reason":    reason,
		"ip":        info.IP,
		"scope":     "per-ip",
		"timestamp": info.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// Middleware returns the IP rate limiting middleware
func (ipr *IPRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract client IP (considering trusted proxies)
		clientIP, originalIP := ipr.extractClientIP(c)

		// Create request info
		info := ipr.createIPRequestInfo(c, clientIP, originalIP, true)

		// Check blacklist first
		if info.IsBlacklisted {
			info.Allowed = false
			atomic.AddInt64(&ipr.stats.BlacklistedReqs, 1)
			ipr.logEvent(info)
			ipr.handleLimitExceeded(c, info)
			return
		}

		// Check whitelist
		if info.IsWhitelisted {
			atomic.AddInt64(&ipr.stats.WhitelistedReqs, 1)
			ipr.setHeaders(c, info)
			ipr.logEvent(info)

			if ipr.config.OnRequestProcessed != nil {
				ipr.config.OnRequestProcessed(c, info, true)
			}

			c.Next()
			return
		}

		// Get IP-specific rate limiter
		limiter := ipr.getLimiterForIP(clientIP)

		// Check rate limit for this specific IP
		allowed := limiter.Allow()
		info.Allowed = allowed

		// Update statistics
		ipr.updateIPStats(clientIP, allowed)

		// Set headers
		ipr.setHeaders(c, info)

		// Log event
		ipr.logEvent(info)

		// Call request handler if provided
		if ipr.config.OnRequestProcessed != nil {
			ipr.config.OnRequestProcessed(c, info, allowed)
		}

		// Handle rate limit exceeded
		if !allowed {
			ipr.handleLimitExceeded(c, info)
			return
		}

		c.Next()
	}
}

// GetStats returns IP rate limiting statistics
func (ipr *IPRateLimiter) GetStats() Stats {
	ipr.stats.TotalRequests = atomic.LoadInt64(&ipr.stats.BaseStats.TotalRequests)
	ipr.stats.AllowedRequests = atomic.LoadInt64(&ipr.stats.BaseStats.AllowedRequests)
	ipr.stats.BlockedRequests = atomic.LoadInt64(&ipr.stats.BaseStats.BlockedRequests)
	return ipr.stats
}

// GetIPStats returns statistics for a specific IP
func (ipr *IPRateLimiter) GetIPStats(ip string) *IPLimiterEntry {
	ipr.mu.RLock()
	defer ipr.mu.RUnlock()

	if entry, exists := ipr.limiters[ip]; exists {
		return &IPLimiterEntry{
			lastAccess:   entry.lastAccess,
			created:      entry.created,
			requestCount: atomic.LoadInt64(&entry.requestCount),
			blockedCount: atomic.LoadInt64(&entry.blockedCount),
		}
	}
	return nil
}

// ResetStats resets all IP rate limiting statistics
func (ipr *IPRateLimiter) ResetStats() {
	atomic.StoreInt64(&ipr.stats.TotalRequests, 0)
	atomic.StoreInt64(&ipr.stats.AllowedRequests, 0)
	atomic.StoreInt64(&ipr.stats.BlockedRequests, 0)
	atomic.StoreInt64(&ipr.stats.WhitelistedReqs, 0)
	atomic.StoreInt64(&ipr.stats.BlacklistedReqs, 0)
	ipr.stats.StartTime = time.Now()
}

func (ipr *IPRateLimiter) Type() RateLimiterType {
	return IPType
}

func (ipr *IPRateLimiter) Algorithm() Algorithm {
	return TokenBucketAlg
}

// =============================================================================
// CONVENIENCE FUNCTIONS - All for PER-IP rate limiting only
// =============================================================================

// IPRateLimitMiddleware creates a simple IP-based rate limiter
// Each IP gets its own rate limit
func IPRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &IPRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
	}
	limiter := NewIPRateLimiter(config)
	return limiter.Middleware()
}

// StrictIPRateLimitMiddleware creates a strict IP rate limiter with logging
func StrictIPRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	config := &IPRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		MaxIPs:        5000, // Smaller cache for strict limiting
		IPTTL:         30 * time.Minute,
	}
	limiter := NewIPRateLimiter(config)
	return limiter.Middleware()
}

// TrustedProxyIPRateLimitMiddleware creates IP rate limiter that respects trusted proxies
func TrustedProxyIPRateLimitMiddleware(requestsPerSecond float64, burst int, trustedProxies []string) gin.HandlerFunc {
	config := &IPRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		TrustedProxies: trustedProxies,
	}
	limiter := NewIPRateLimiter(config)
	return limiter.Middleware()
}

// WhitelistIPRateLimitMiddleware creates IP rate limiter with whitelist/blacklist support
func WhitelistIPRateLimitMiddleware(requestsPerSecond float64, burst int, whitelistIPs, blacklistIPs []string) gin.HandlerFunc {
	config := &IPRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		WhitelistIPs:  whitelistIPs,
		BlacklistIPs:  blacklistIPs,
	}
	limiter := NewIPRateLimiter(config)
	return limiter.Middleware()
}

// DDoSProtectionMiddleware creates aggressive IP rate limiter for DDoS protection
func DDoSProtectionMiddleware() gin.HandlerFunc {
	config := &IPRateLimiterConfig{
		Rate:          rate.Limit(10), // Very strict: 10 req/sec per IP
		Burst:         2,              // Minimal burst
		EnableHeaders: true,
		EnableLogging: true,
		MaxIPs:        50000,            // Track many IPs during attack
		IPTTL:         10 * time.Minute, // Shorter TTL during DDoS
		ErrorMessage:  "DDoS protection activated",
		ErrorResponse: gin.H{
			"error":   "DDoS protection activated",
			"message": "Your IP is temporarily rate limited",
			"scope":   "per-ip",
			"level":   "ddos-protection",
		},
	}
	limiter := NewIPRateLimiter(config)
	return limiter.Middleware()
}
