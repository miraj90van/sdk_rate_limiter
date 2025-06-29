// middleware/middleware.go
// Purpose: Common types, interfaces, and utilities shared across all rate limiters
// This file defines the contracts and common functionality for the rate limiting SDK
// Updated to support optimized rate limiter implementations

package middleware

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// =============================================================================
// ENUMS & CONSTANTS
// =============================================================================

// RateLimiterType defines the type of rate limiter algorithm
type RateLimiterType int

const (
	BasicType         RateLimiterType = iota // Global rate limiting
	SlidingWindowType                        // Sliding window algorithm
	TokenBucketType                          // Token bucket with waiting
	FixedWindowType                          // Fixed window counter
	LeakyBucketType                          // Leaky bucket algorithm
)

// String returns the string representation of RateLimiterType
func (r RateLimiterType) String() string {
	switch r {
	case BasicType:
		return "basic"
	case SlidingWindowType:
		return "sliding-window"
	case TokenBucketType:
		return "token-bucket"
	case FixedWindowType:
		return "fixed-window"
	case LeakyBucketType:
		return "leaky-bucket"
	default:
		return "unknown"
	}
}

// Algorithm defines the rate limiting algorithm used
type Algorithm int

const (
	TokenBucketAlg   Algorithm = iota // Token bucket algorithm (default in golang.org/x/time/rate)
	SlidingWindowAlg                  // Sliding window algorithm
	FixedWindowAlg                    // Fixed window algorithm
	LeakyBucketAlg                    // Leaky bucket algorithm
)

// String returns the string representation of Algorithm
func (a Algorithm) String() string {
	switch a {
	case TokenBucketAlg:
		return "token-bucket"
	case SlidingWindowAlg:
		return "sliding-window"
	case FixedWindowAlg:
		return "fixed-window"
	case LeakyBucketAlg:
		return "leaky-bucket"
	default:
		return "unknown"
	}
}

// =============================================================================
// CORE INTERFACES - UPDATED FOR FLEXIBILITY
// =============================================================================

// Stats is the base interface for all rate limiter statistics
type Stats interface {
	// GetTotalRequests returns total number of requests processed
	GetTotalRequests() int64

	// GetAllowedRequests returns number of allowed requests
	GetAllowedRequests() int64

	// GetBlockedRequests returns number of blocked requests
	GetBlockedRequests() int64

	// GetStartTime returns when the rate limiter started
	GetStartTime() time.Time

	// GetUptime returns how long the rate limiter has been running
	GetUptime() time.Duration

	// GetSuccessRate returns the success rate (0.0 to 1.0)
	GetSuccessRate() float64

	// GetType returns the rate limiter type
	GetType() RateLimiterType
}

// RateLimiter is the common interface that all rate limiters must implement
// Updated to support flexible stats return types
type RateLimiter interface {
	// Middleware returns the Gin middleware function
	Middleware() gin.HandlerFunc

	// GetStats returns statistics about the rate limiter (flexible return type)
	GetStats() interface{}

	// ResetStats resets all statistics
	ResetStats()

	// Stop gracefully stops the rate limiter (cleanup goroutines, etc.)
	Stop()

	// Type returns the type of rate limiter
	Type() RateLimiterType

	// Algorithm returns the algorithm used
	Algorithm() Algorithm
}

// ExtendedRateLimiter provides additional functionality for client management
type ExtendedRateLimiter interface {
	RateLimiter

	// Client management methods
	GetClientStats(clientKey string) ClientStats
	ResetClient(clientKey string)
	ListActiveClients() []string
	GetClientCount() int
}

// =============================================================================
// COMMON TYPES & STRUCTS
// =============================================================================

// BaseStats provides a common implementation of Stats interface
type BaseStats struct {
	TotalRequests   int64           `json:"total_requests"`
	AllowedRequests int64           `json:"allowed_requests"`
	BlockedRequests int64           `json:"blocked_requests"`
	StartTime       time.Time       `json:"start_time"`
	LimiterType     RateLimiterType `json:"limiter_type"`
}

func (s *BaseStats) GetTotalRequests() int64   { return s.TotalRequests }
func (s *BaseStats) GetAllowedRequests() int64 { return s.AllowedRequests }
func (s *BaseStats) GetBlockedRequests() int64 { return s.BlockedRequests }
func (s *BaseStats) GetStartTime() time.Time   { return s.StartTime }
func (s *BaseStats) GetType() RateLimiterType  { return s.LimiterType }
func (s *BaseStats) GetUptime() time.Duration  { return time.Since(s.StartTime) }
func (s *BaseStats) GetSuccessRate() float64 {
	if s.TotalRequests == 0 {
		return 1.0
	}
	return float64(s.AllowedRequests) / float64(s.TotalRequests)
}

// ClientStats represents statistics for a specific client
type ClientStats struct {
	ClientKey       string    `json:"client_key"`
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	LastAccess      time.Time `json:"last_access"`
	FirstSeen       time.Time `json:"first_seen"`
	IsActive        bool      `json:"is_active"`
}

// GetSuccessRate returns the success rate for this client
func (cs *ClientStats) GetSuccessRate() float64 {
	if cs.TotalRequests == 0 {
		return 1.0
	}
	return float64(cs.AllowedRequests) / float64(cs.TotalRequests)
}

// =============================================================================
// STATS ADAPTER FOR FLEXIBILITY
// =============================================================================

// StatsAdapter adapts any stats struct to the Stats interface
type StatsAdapter struct {
	rawStats        interface{}
	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
	startTime       time.Time
	limiterType     RateLimiterType
}

// NewStatsAdapter creates a new stats adapter from any stats object
func NewStatsAdapter(rawStats interface{}) *StatsAdapter {
	adapter := &StatsAdapter{
		rawStats: rawStats,
	}

	// Use reflection or type assertions to extract common fields
	adapter.extractCommonFields()
	return adapter
}

// extractCommonFields extracts common statistics fields from the raw stats
func (sa *StatsAdapter) extractCommonFields() {
	switch stats := sa.rawStats.(type) {
	case *FixedWindowStats:
		if stats.BaseStats != nil {
			sa.totalRequests = stats.BaseStats.TotalRequests
			sa.allowedRequests = stats.BaseStats.AllowedRequests
			sa.blockedRequests = stats.BaseStats.BlockedRequests
			sa.startTime = stats.BaseStats.StartTime
			sa.limiterType = stats.BaseStats.LimiterType
		}
	case *SlidingWindowStats:
		if stats.BaseStats != nil {
			sa.totalRequests = stats.BaseStats.TotalRequests
			sa.allowedRequests = stats.BaseStats.AllowedRequests
			sa.blockedRequests = stats.BaseStats.BlockedRequests
			sa.startTime = stats.BaseStats.StartTime
			sa.limiterType = stats.BaseStats.LimiterType
		}
	case *LeakyBucketStats:
		if stats.BaseStats != nil {
			sa.totalRequests = stats.BaseStats.TotalRequests
			sa.allowedRequests = stats.BaseStats.AllowedRequests
			sa.blockedRequests = stats.BaseStats.BlockedRequests
			sa.startTime = stats.BaseStats.StartTime
			sa.limiterType = stats.BaseStats.LimiterType
		}
	case *TokenBucketStats:
		if stats.BaseStats != nil {
			sa.totalRequests = stats.BaseStats.TotalRequests
			sa.allowedRequests = stats.BaseStats.AllowedRequests
			sa.blockedRequests = stats.BaseStats.BlockedRequests
			sa.startTime = stats.BaseStats.StartTime
			sa.limiterType = stats.BaseStats.LimiterType
		}
	case Stats:
		// Already implements Stats interface
		sa.totalRequests = stats.GetTotalRequests()
		sa.allowedRequests = stats.GetAllowedRequests()
		sa.blockedRequests = stats.GetBlockedRequests()
		sa.startTime = stats.GetStartTime()
		sa.limiterType = stats.GetType()
	default:
		// Unknown type, use defaults
		sa.limiterType = BasicType
		sa.startTime = time.Now()
	}
}

// Implement Stats interface
func (sa *StatsAdapter) GetTotalRequests() int64   { return sa.totalRequests }
func (sa *StatsAdapter) GetAllowedRequests() int64 { return sa.allowedRequests }
func (sa *StatsAdapter) GetBlockedRequests() int64 { return sa.blockedRequests }
func (sa *StatsAdapter) GetStartTime() time.Time   { return sa.startTime }
func (sa *StatsAdapter) GetType() RateLimiterType  { return sa.limiterType }
func (sa *StatsAdapter) GetUptime() time.Duration  { return time.Since(sa.startTime) }
func (sa *StatsAdapter) GetSuccessRate() float64 {
	if sa.totalRequests == 0 {
		return 1.0
	}
	return float64(sa.allowedRequests) / float64(sa.totalRequests)
}

// GetRawStats returns the original stats object
func (sa *StatsAdapter) GetRawStats() interface{} {
	return sa.rawStats
}

// =============================================================================
// FORWARD DECLARATIONS FOR SPECIFIC STATS TYPES
// =============================================================================

// These types will be defined in the individual rate limiter files
// Here we just provide type declarations for the adapter

//type FixedWindowStats struct {
//	*BaseStats
//	ActiveClients      int64                   `json:"active_clients"`
//	RedisMode          bool                    `json:"redis_mode"`
//	FallbackMode       bool                    `json:"fallback_mode"`
//	RedisErrors        int64                   `json:"redis_errors"`
//	WindowsProcessed   int64                   `json:"windows_processed"`
//	ClientStats        map[string]*ClientStats `json:"client_stats"`
//}
//
//type SlidingWindowStats struct {
//	*BaseStats
//	ActiveClients      int64                   `json:"active_clients"`
//	RedisMode          bool                    `json:"redis_mode"`
//	FallbackMode       bool                    `json:"fallback_mode"`
//	RedisErrors        int64                   `json:"redis_errors"`
//	TimestampsStored   int64                   `json:"timestamps_stored"`
//	MemoryUsageBytes   int64                   `json:"memory_usage_bytes"`
//	AverageWindowUsage float64                 `json:"average_window_usage"`
//	ClientStats        map[string]*ClientStats `json:"client_stats"`
//}
//
//type LeakyBucketStats struct {
//	*BaseStats
//	ActiveClients      int64                   `json:"active_clients"`
//	RedisMode          bool                    `json:"redis_mode"`
//	FallbackMode       bool                    `json:"fallback_mode"`
//	RedisErrors        int64                   `json:"redis_errors"`
//	QueuedRequests     int64                   `json:"queued_requests"`
//	DroppedRequests    int64                   `json:"dropped_requests"`
//	QueueTimeouts      int64                   `json:"queue_timeouts"`
//	AverageWaitTime    time.Duration           `json:"average_wait_time"`
//	AverageBucketUsage float64                 `json:"average_bucket_usage"`
//	ClientStats        map[string]*ClientStats `json:"client_stats"`
//}
//
//type TokenBucketStats struct {
//	*BaseStats
//	ActiveClients      int64                   `json:"active_clients"`
//	RedisMode          bool                    `json:"redis_mode"`
//	FallbackMode       bool                    `json:"fallback_mode"`
//	RedisErrors        int64                   `json:"redis_errors"`
//	WaitingRequests    int64                   `json:"waiting_requests"`
//	QueueTimeouts      int64                   `json:"queue_timeouts"`
//	TokensConsumed     int64                   `json:"tokens_consumed"`
//	TokensRefilled     int64                   `json:"tokens_refilled"`
//	AverageWaitTime    time.Duration           `json:"average_wait_time"`
//	AverageTokenUsage  float64                 `json:"average_token_usage"`
//	ClientStats        map[string]*ClientStats `json:"client_stats"`
//}

// =============================================================================
// COMMON CONFIGURATION TYPES
// =============================================================================

// BaseConfig contains common configuration options for all rate limiters
type BaseConfig struct {
	Rate          rate.Limit  `json:"rate"`           // Requests per second
	Burst         int         `json:"burst"`          // Burst capacity
	EnableHeaders bool        `json:"enable_headers"` // Include rate limit headers
	EnableLogging bool        `json:"enable_logging"` // Enable logging
	ErrorMessage  string      `json:"error_message"`  // Custom error message
	ErrorResponse interface{} `json:"error_response"` // Custom error response
}

// Validate validates the base configuration
func (bc *BaseConfig) Validate() error {
	if bc.Rate <= 0 {
		return ErrInvalidRate
	}
	if bc.Burst <= 0 {
		return ErrInvalidBurst
	}
	return nil
}

// ClientAwareConfig extends BaseConfig for per-client rate limiters
type ClientAwareConfig struct {
	BaseConfig
	MaxClients      int           `json:"max_clients"`      // Maximum clients to track
	CleanupInterval time.Duration `json:"cleanup_interval"` // Cleanup frequency
	ClientTTL       time.Duration `json:"client_ttl"`       // Client entry TTL
}

// Validate validates the client-aware configuration
func (cac *ClientAwareConfig) Validate() error {
	if err := cac.BaseConfig.Validate(); err != nil {
		return err
	}
	if cac.MaxClients <= 0 {
		return ErrInvalidMaxClients
	}
	if cac.CleanupInterval <= 0 {
		return ErrInvalidCleanupInterval
	}
	if cac.ClientTTL <= 0 {
		return ErrInvalidClientTTL
	}
	return nil
}

// =============================================================================
// COMMON ERRORS
// =============================================================================

// Common errors used across all rate limiters
var (
	ErrInvalidRate            = NewRateLimiterError("INVALID_RATE", "invalid rate: must be greater than 0")
	ErrInvalidBurst           = NewRateLimiterError("INVALID_BURST", "invalid burst: must be greater than 0")
	ErrInvalidMaxClients      = NewRateLimiterError("INVALID_MAX_CLIENTS", "invalid max_clients: must be greater than 0")
	ErrInvalidCleanupInterval = NewRateLimiterError("INVALID_CLEANUP_INTERVAL", "invalid cleanup_interval: must be greater than 0")
	ErrInvalidClientTTL       = NewRateLimiterError("INVALID_CLIENT_TTL", "invalid client_ttl: must be greater than 0")
)

// RateLimiterError represents an error from the rate limiter
type RateLimiterError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *RateLimiterError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// NewRateLimiterError creates a new rate limiter error
func NewRateLimiterError(code, message string) *RateLimiterError {
	return &RateLimiterError{
		Code:    code,
		Message: message,
	}
}

// =============================================================================
// COMMON REQUEST INFO TYPES
// =============================================================================

// RequestInfo is the base interface for request information
type RequestInfo interface {
	GetIP() string
	GetPath() string
	GetMethod() string
	GetTimestamp() time.Time
	IsAllowed() bool
}

// BaseRequestInfo provides common request information
type BaseRequestInfo struct {
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Allowed   bool      `json:"allowed"`
}

// Implement RequestInfo interface
func (ri *BaseRequestInfo) GetIP() string           { return ri.IP }
func (ri *BaseRequestInfo) GetPath() string         { return ri.Path }
func (ri *BaseRequestInfo) GetMethod() string       { return ri.Method }
func (ri *BaseRequestInfo) GetTimestamp() time.Time { return ri.Timestamp }
func (ri *BaseRequestInfo) IsAllowed() bool         { return ri.Allowed }

// =============================================================================
// COMMON UTILITY FUNCTIONS
// =============================================================================

// KeyExtractor defines a function type for extracting client keys from requests
type KeyExtractor func(*gin.Context) string

// Common key extractors
var (
	// IPKeyExtractor extracts client IP address
	IPKeyExtractor KeyExtractor = func(c *gin.Context) string {
		return c.ClientIP()
	}

	// UserIDKeyExtractor extracts user ID from X-User-ID header
	UserIDKeyExtractor KeyExtractor = func(c *gin.Context) string {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			return ""
		}
		return "user:" + userID
	}

	// APIKeyExtractor extracts API key from X-API-Key header
	APIKeyExtractor KeyExtractor = func(c *gin.Context) string {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			return ""
		}
		return "api:" + apiKey
	}
)

// CreateCompositeKeyExtractor creates a key extractor that combines multiple extractors
func CreateCompositeKeyExtractor(extractors ...KeyExtractor) KeyExtractor {
	return func(c *gin.Context) string {
		var parts []string
		for _, extractor := range extractors {
			if key := extractor(c); key != "" {
				parts = append(parts, key)
			}
		}
		if len(parts) == 0 {
			return IPKeyExtractor(c) // Fallback to IP
		}
		return strings.Join(parts, ":")
	}
}

// =============================================================================
// ENHANCED MIDDLEWARE REGISTRY
// =============================================================================

// MiddlewareRegistry manages registered rate limiters
type MiddlewareRegistry struct {
	limiters map[string]RateLimiter
	mu       sync.RWMutex
}

// NewMiddlewareRegistry creates a new middleware registry
func NewMiddlewareRegistry() *MiddlewareRegistry {
	return &MiddlewareRegistry{
		limiters: make(map[string]RateLimiter),
	}
}

// Register registers a rate limiter with a name
func (mr *MiddlewareRegistry) Register(name string, limiter RateLimiter) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.limiters[name] = limiter
}

// Unregister removes a rate limiter by name
func (mr *MiddlewareRegistry) Unregister(name string) bool {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if limiter, exists := mr.limiters[name]; exists {
		limiter.Stop() // Stop the limiter before removing
		delete(mr.limiters, name)
		return true
	}
	return false
}

// Get retrieves a rate limiter by name
func (mr *MiddlewareRegistry) Get(name string) (RateLimiter, bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	limiter, exists := mr.limiters[name]
	return limiter, exists
}

// List returns all registered rate limiter names
func (mr *MiddlewareRegistry) List() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	names := make([]string, 0, len(mr.limiters))
	for name := range mr.limiters {
		names = append(names, name)
	}
	return names
}

// GetAllStats returns statistics for all registered rate limiters
// Updated to handle flexible stats return types
func (mr *MiddlewareRegistry) GetAllStats() map[string]Stats {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	stats := make(map[string]Stats)
	for name, limiter := range mr.limiters {
		rawStats := limiter.GetStats()

		// Convert to Stats interface using adapter
		if statsInterface, ok := rawStats.(Stats); ok {
			// Already implements Stats interface
			stats[name] = statsInterface
		} else {
			// Use adapter to convert
			adapter := NewStatsAdapter(rawStats)
			stats[name] = adapter
		}
	}
	return stats
}

// GetAllRawStats returns raw statistics for all registered rate limiters
func (mr *MiddlewareRegistry) GetAllRawStats() map[string]interface{} {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	stats := make(map[string]interface{})
	for name, limiter := range mr.limiters {
		stats[name] = limiter.GetStats()
	}
	return stats
}

// GetSummaryStats returns a summary of all rate limiters
func (mr *MiddlewareRegistry) GetSummaryStats() map[string]interface{} {
	allStats := mr.GetAllStats()
	summary := make(map[string]interface{})

	var totalRequests, totalAllowed, totalBlocked int64
	typeCount := make(map[string]int)

	for name, stat := range allStats {
		totalRequests += stat.GetTotalRequests()
		totalAllowed += stat.GetAllowedRequests()
		totalBlocked += stat.GetBlockedRequests()

		limiterType := stat.GetType().String()
		typeCount[limiterType]++

		summary[name] = map[string]interface{}{
			"type":         limiterType,
			"requests":     stat.GetTotalRequests(),
			"success_rate": stat.GetSuccessRate(),
			"uptime":       stat.GetUptime().String(),
		}
	}

	summary["_total"] = map[string]interface{}{
		"total_requests":   totalRequests,
		"allowed_requests": totalAllowed,
		"blocked_requests": totalBlocked,
		"success_rate": func() float64 {
			if totalRequests == 0 {
				return 1.0
			}
			return float64(totalAllowed) / float64(totalRequests)
		}(),
		"active_limiters": len(mr.limiters),
		"types":           typeCount,
	}

	return summary
}

// GetExtendedLimiter retrieves a rate limiter as ExtendedRateLimiter if supported
func (mr *MiddlewareRegistry) GetExtendedLimiter(name string) (ExtendedRateLimiter, bool) {
	if limiter, exists := mr.Get(name); exists {
		if extended, ok := limiter.(ExtendedRateLimiter); ok {
			return extended, true
		}
	}
	return nil, false
}

// Stop stops all registered rate limiters
func (mr *MiddlewareRegistry) Stop() {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	for _, limiter := range mr.limiters {
		limiter.Stop()
	}
	// Clear the map
	mr.limiters = make(map[string]RateLimiter)
}

// =============================================================================
// TYPE ASSERTION HELPERS
// =============================================================================

// GetSpecificStats safely extracts specific stats types
func GetSpecificStats(stats interface{}) (Stats, interface{}) {
	switch s := stats.(type) {
	case *FixedWindowStats:
		return NewStatsAdapter(s), s
	case *SlidingWindowStats:
		return NewStatsAdapter(s), s
	case *LeakyBucketStats:
		return NewStatsAdapter(s), s
	case *TokenBucketStats:
		return NewStatsAdapter(s), s
	case Stats:
		return s, s
	default:
		return NewStatsAdapter(s), s
	}
}

// =============================================================================
// GLOBAL REGISTRY INSTANCE
// =============================================================================

// RateLimitRegistry is the global registry instance that can be used throughout the application
var RateLimitRegistry = NewMiddlewareRegistry()

// =============================================================================
// UTILITY HELPER FUNCTIONS
// =============================================================================

// SetRetryAfterHeader sets the Retry-After header
func SetRetryAfterHeader(c *gin.Context, retryAfter time.Duration) {
	c.Header("Retry-After", fmt.Sprintf("%d", int64(retryAfter.Seconds())))
}

// Metrics interface for external metrics collection
type Metrics interface {
	IncrementCounter(name string, tags map[string]string)
	RecordHistogram(name string, value float64, tags map[string]string)
	SetGauge(name string, value float64, tags map[string]string)
}

// =============================================================================
// ENHANCED HELPER FUNCTIONS
// =============================================================================

// GetDetailedInfo retrieves detailed information for a rate limiter
func GetDetailedInfo(limiter RateLimiter, clientKey string) interface{} {
	// Try to get detailed info based on limiter type
	switch limiter.Type() {
	case SlidingWindowType:
		// Try to call GetWindowInfo if available
		if v := tryCallMethod(limiter, "GetWindowInfo", clientKey); v != nil {
			return v
		}
	case LeakyBucketType:
		// Try to call GetBucketInfo if available
		if v := tryCallMethod(limiter, "GetBucketInfo", clientKey); v != nil {
			return v
		}
	case TokenBucketType:
		// Try to call GetBucketInfo if available
		if v := tryCallMethod(limiter, "GetBucketInfo", clientKey); v != nil {
			return v
		}
	}

	// Fallback to ExtendedRateLimiter interface
	if extended, ok := limiter.(ExtendedRateLimiter); ok {
		return extended.GetClientStats(clientKey)
	}

	// Last resort: return basic info
	return map[string]interface{}{
		"message": "Detailed info not available",
		"type":    limiter.Type().String(),
		"stats":   limiter.GetStats(),
	}
}

// tryCallMethod attempts to call a method on an interface using reflection
func tryCallMethod(obj interface{}, methodName string, args ...interface{}) interface{} {
	// This is a simplified version - in a real implementation you might use reflection
	// For now, we'll use type assertions for known types

	switch v := obj.(type) {
	case interface{ GetWindowInfo(string) interface{} }:
		if methodName == "GetWindowInfo" && len(args) == 1 {
			if clientKey, ok := args[0].(string); ok {
				return v.GetWindowInfo(clientKey)
			}
		}
	case interface{ GetBucketInfo(string) interface{} }:
		if methodName == "GetBucketInfo" && len(args) == 1 {
			if clientKey, ok := args[0].(string); ok {
				return v.GetBucketInfo(clientKey)
			}
		}
	}

	return nil
}

// ResetLimiterClient resets a specific client for a rate limiter
func ResetLimiterClient(limiter RateLimiter, clientKey string) error {
	if extended, ok := limiter.(ExtendedRateLimiter); ok {
		extended.ResetClient(clientKey)
		return nil
	}
	return NewRateLimiterError("OPERATION_NOT_SUPPORTED", "client reset not supported for this limiter type")
}
