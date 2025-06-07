package middleware

import (
	"github.com/miraj90van/sdk_rate_limiter/component"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiterFactory helps create different types of rate limiters
type RateLimiterFactory struct {
	redisClient component.RedisClient
	redisConfig *component.RedisConfig
}

// NewRateLimiterFactory creates a new rate limiter factory
func NewRateLimiterFactory(redisClient component.RedisClient, redisConfig *component.RedisConfig) *RateLimiterFactory {
	if redisConfig == nil {
		redisConfig = component.DefaultRedisConfig()
	}

	return &RateLimiterFactory{
		redisClient: redisClient,
		redisConfig: redisConfig,
	}
}

// NewRateLimiterFactoryWithoutRedis creates a factory without Redis support
func NewRateLimiterFactoryWithoutRedis() *RateLimiterFactory {
	return &RateLimiterFactory{
		redisClient: nil,
		redisConfig: &component.RedisConfig{
			Enabled: false,
		},
	}
}

// =============================================================================
// GLOBAL RATE LIMITERS
// =============================================================================

// CreateGlobalRateLimiter creates a global rate limiter (all clients share the same limit)
func (factory *RateLimiterFactory) CreateGlobalRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	if factory.redisClient != nil && factory.redisConfig.Enabled {
		// Use Redis-backed enhanced basic rate limiter
		config := &EnhancedBasicRateLimiterConfig{
			Rate:           rate.Limit(requestsPerSecond),
			Burst:          burst,
			EnableHeaders:  true,
			WindowDuration: time.Second,
			RedisConfig:    factory.redisConfig,
		}
		return NewEnhancedBasicRateLimiter(config, factory.redisClient)
	}

	// Use in-memory basic rate limiter
	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
	}
	return NewBasicRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateTokenBucketRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	config := &TokenBucketConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		EnableFallback: true,
		RedisClient:    factory.redisClient.GetRedisClient(),
		RedisConfig:    factory.redisConfig,
		ErrorMessage:   "Token Bucket Rate limit exceeded",
	}
	return NewTokenBucketRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateSlidingWindowsRateLimiter(requestsPerSecond int, burst int) RateLimiter {
	config := &SlidingWindowConfig{
		Rate:            requestsPerSecond,
		RedisClient:     factory.redisClient.GetRedisClient(),
		WindowSize:      time.Minute,
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Sliding Windows Rate limit exceeded",
	}
	return NewSlidingWindowRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateFixedWindowRateLimiter(requestsPerSecond int, burst int) RateLimiter {
	config := &FixedWindowConfig{
		Rate:            requestsPerSecond,
		RedisClient:     factory.redisClient.GetRedisClient(),
		WindowSize:      time.Minute,
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Fixed Window Rate limit exceeded",
	}
	return NewFixedWindowRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateLeakyBucketRateLimiter(requestsPerSecond float64, buffer int) RateLimiter {
	config := &LeakyBucketConfig{
		RedisClient:     factory.redisClient.GetRedisClient(),
		LeakRate:        requestsPerSecond,
		Capacity:        buffer,
		EnableFallback:  true,
		KeyExtractor:    IPKeyExtractor,
		MaxClients:      10000,
		CleanupInterval: time.Minute * 5,
		ClientTTL:       time.Hour,
		EnableHeaders:   true,
		EnableLogging:   false,
		ErrorMessage:    "Leaky Bucket Rate limit exceeded",
		AllowQueueing:   false,
		MaxQueueTime:    time.Second * 10,
	}
	return NewLeakyBucketRateLimiter(config)
}

// CreateServerProtection creates a rate limiter for server protection
func (factory *RateLimiterFactory) CreateServerProtection(maxRequestsPerSecond float64) RateLimiter {
	burst := int(maxRequestsPerSecond * 0.1) // 10% burst capacity
	if burst < 1 {
		burst = 1
	}

	if factory.redisClient != nil && factory.redisConfig.Enabled {
		config := &EnhancedBasicRateLimiterConfig{
			Rate:           rate.Limit(maxRequestsPerSecond),
			Burst:          burst,
			EnableHeaders:  true,
			EnableLogging:  true,
			ErrorMessage:   "Server overload protection activated",
			WindowDuration: time.Minute,
			RedisConfig:    factory.redisConfig,
		}
		return NewEnhancedBasicRateLimiter(config, factory.redisClient)
	}

	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(maxRequestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "Server overload protection activated",
	}
	return NewBasicRateLimiter(config)
}

// =============================================================================
// PER-CLIENT RATE LIMITERS
// =============================================================================

// CreateIPRateLimiter creates a per-IP rate limiter
func (factory *RateLimiterFactory) CreateIPRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	config := &RedisRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		WindowDuration: time.Minute,
		KeyExtractor:   IPKeyExtractor,
		Scope:          "ip",
		RedisConfig:    factory.redisConfig,
	}
	return NewRedisRateLimiter(config, factory.redisClient)
}

// CreateUserRateLimiter creates a per-user rate limiter
func (factory *RateLimiterFactory) CreateUserRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	config := &RedisRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		WindowDuration: time.Minute,
		KeyExtractor:   UserIDKeyExtractor,
		Scope:          "user",
		RedisConfig:    factory.redisConfig,
	}
	return NewRedisRateLimiter(config, factory.redisClient)
}

// CreateAPIKeyRateLimiter creates a per-API-key rate limiter
func (factory *RateLimiterFactory) CreateAPIKeyRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	config := &RedisRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		WindowDuration: time.Minute,
		KeyExtractor:   APIKeyExtractor,
		Scope:          "api_key",
		RedisConfig:    factory.redisConfig,
	}
	return NewRedisRateLimiter(config, factory.redisClient)
}

// CreateCustomRateLimiter creates a rate limiter with custom key extraction
func (factory *RateLimiterFactory) CreateCustomRateLimiter(
	requestsPerSecond float64,
	burst int,
	keyExtractor KeyExtractor,
	scope string,
) RateLimiter {
	config := &RedisRateLimiterConfig{
		Rate:           rate.Limit(requestsPerSecond),
		Burst:          burst,
		EnableHeaders:  true,
		WindowDuration: time.Minute,
		KeyExtractor:   keyExtractor,
		Scope:          scope,
		RedisConfig:    factory.redisConfig,
	}
	return NewRedisRateLimiter(config, factory.redisClient)
}

// =============================================================================
// MIDDLEWARE BUILDERS
// =============================================================================

// GlobalMiddleware creates global rate limiting middleware
func (factory *RateLimiterFactory) GlobalMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	limiter := factory.CreateGlobalRateLimiter(requestsPerSecond, burst)
	return limiter.Middleware()
}

// IPMiddleware creates per-IP rate limiting middleware
func (factory *RateLimiterFactory) IPMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	limiter := factory.CreateIPRateLimiter(requestsPerSecond, burst)
	return limiter.Middleware()
}

// UserMiddleware creates per-user rate limiting middleware
func (factory *RateLimiterFactory) UserMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	limiter := factory.CreateUserRateLimiter(requestsPerSecond, burst)
	return limiter.Middleware()
}

// APIKeyMiddleware creates per-API-key rate limiting middleware
func (factory *RateLimiterFactory) APIKeyMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	limiter := factory.CreateAPIKeyRateLimiter(requestsPerSecond, burst)
	return limiter.Middleware()
}

// ServerProtectionMiddleware creates server protection middleware
func (factory *RateLimiterFactory) ServerProtectionMiddleware(maxRequestsPerSecond float64) gin.HandlerFunc {
	limiter := factory.CreateServerProtection(maxRequestsPerSecond)
	return limiter.Middleware()
}

// =============================================================================
// LAYERED RATE LIMITING
// =============================================================================

// LayeredRateLimitConfig defines configuration for layered rate limiting
type LayeredRateLimitConfig struct {
	Global struct {
		Enabled           bool    `json:"enabled"`
		RequestsPerSecond float64 `json:"requests_per_second"`
		Burst             int     `json:"burst"`
	} `json:"global"`

	PerIP struct {
		Enabled           bool    `json:"enabled"`
		RequestsPerSecond float64 `json:"requests_per_second"`
		Burst             int     `json:"burst"`
	} `json:"per_ip"`

	PerUser struct {
		Enabled           bool    `json:"enabled"`
		RequestsPerSecond float64 `json:"requests_per_second"`
		Burst             int     `json:"burst"`
	} `json:"per_user"`

	PerAPIKey struct {
		Enabled           bool    `json:"enabled"`
		RequestsPerSecond float64 `json:"requests_per_second"`
		Burst             int     `json:"burst"`
	} `json:"per_api_key"`
}

// CreateLayeredMiddleware creates layered rate limiting (multiple rate limiters)
func (factory *RateLimiterFactory) CreateLayeredMiddleware(config *LayeredRateLimitConfig) []gin.HandlerFunc {
	var middlewares []gin.HandlerFunc

	// Add global rate limiting first (most restrictive)
	if config.Global.Enabled {
		middlewares = append(middlewares,
			factory.GlobalMiddleware(config.Global.RequestsPerSecond, config.Global.Burst))
	}

	// Add per-IP rate limiting
	if config.PerIP.Enabled {
		middlewares = append(middlewares,
			factory.IPMiddleware(config.PerIP.RequestsPerSecond, config.PerIP.Burst))
	}

	// Add per-user rate limiting
	if config.PerUser.Enabled {
		middlewares = append(middlewares,
			factory.UserMiddleware(config.PerUser.RequestsPerSecond, config.PerUser.Burst))
	}

	// Add per-API-key rate limiting
	if config.PerAPIKey.Enabled {
		middlewares = append(middlewares,
			factory.APIKeyMiddleware(config.PerAPIKey.RequestsPerSecond, config.PerAPIKey.Burst))
	}

	return middlewares
}

// =============================================================================
// CONVENIENCE BUILDER PATTERNS
// =============================================================================

// RateLimiterBuilder provides a fluent interface for building rate limiters
type RateLimiterBuilder struct {
	factory      *RateLimiterFactory
	ratePerSec   float64
	burst        int
	keyExtractor KeyExtractor
	scope        string
	enableLog    bool
	enableHeader bool
	windowDur    time.Duration
	errorMsg     string
}

// NewBuilder creates a new rate limiter builder
func (factory *RateLimiterFactory) NewBuilder() *RateLimiterBuilder {
	return &RateLimiterBuilder{
		factory:      factory,
		ratePerSec:   100,         // Default: 100 req/sec
		burst:        10,          // Default: 10 burst
		enableHeader: true,        // Default: enable headers
		enableLog:    false,       // Default: disable logging
		windowDur:    time.Minute, // Default: 1 minute window
	}
}

// Rate sets the rate limit (requests per second)
func (b *RateLimiterBuilder) Rate(requestsPerSecond float64) *RateLimiterBuilder {
	b.ratePerSec = requestsPerSecond
	return b
}

// Burst sets the burst capacity
func (b *RateLimiterBuilder) Burst(burst int) *RateLimiterBuilder {
	b.burst = burst
	return b
}

// WithIPKey sets IP-based rate limiting
func (b *RateLimiterBuilder) WithIPKey() *RateLimiterBuilder {
	b.keyExtractor = IPKeyExtractor
	b.scope = "ip"
	return b
}

// WithUserKey sets user-based rate limiting
func (b *RateLimiterBuilder) WithUserKey() *RateLimiterBuilder {
	b.keyExtractor = UserIDKeyExtractor
	b.scope = "user"
	return b
}

// WithAPIKey sets API key-based rate limiting
func (b *RateLimiterBuilder) WithAPIKey() *RateLimiterBuilder {
	b.keyExtractor = APIKeyExtractor
	b.scope = "api_key"
	return b
}

// WithCustomKey sets custom key extraction
func (b *RateLimiterBuilder) WithCustomKey(extractor KeyExtractor, scope string) *RateLimiterBuilder {
	b.keyExtractor = extractor
	b.scope = scope
	return b
}

// EnableLogging enables request logging
func (b *RateLimiterBuilder) EnableLogging() *RateLimiterBuilder {
	b.enableLog = true
	return b
}

// DisableHeaders disables rate limit headers
func (b *RateLimiterBuilder) DisableHeaders() *RateLimiterBuilder {
	b.enableHeader = false
	return b
}

// Window sets the sliding window duration
func (b *RateLimiterBuilder) Window(duration time.Duration) *RateLimiterBuilder {
	b.windowDur = duration
	return b
}

// ErrorMessage sets custom error message
func (b *RateLimiterBuilder) ErrorMessage(message string) *RateLimiterBuilder {
	b.errorMsg = message
	return b
}

// BuildGlobal builds a global rate limiter
func (b *RateLimiterBuilder) BuildGlobal() RateLimiter {
	if b.factory.redisClient != nil && b.factory.redisConfig.Enabled {
		config := &EnhancedBasicRateLimiterConfig{
			Rate:           rate.Limit(b.ratePerSec),
			Burst:          b.burst,
			EnableHeaders:  b.enableHeader,
			EnableLogging:  b.enableLog,
			WindowDuration: b.windowDur,
			RedisConfig:    b.factory.redisConfig,
		}
		if b.errorMsg != "" {
			config.ErrorMessage = b.errorMsg
		}
		return NewEnhancedBasicRateLimiter(config, b.factory.redisClient)
	}

	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(b.ratePerSec),
		Burst:         b.burst,
		EnableHeaders: b.enableHeader,
		EnableLogging: b.enableLog,
	}
	if b.errorMsg != "" {
		config.ErrorMessage = b.errorMsg
	}
	return NewBasicRateLimiter(config)
}

// BuildPerClient builds a per-client rate limiter
func (b *RateLimiterBuilder) BuildPerClient() RateLimiter {
	if b.keyExtractor == nil {
		b.keyExtractor = IPKeyExtractor
		b.scope = "ip"
	}

	config := &RedisRateLimiterConfig{
		Rate:           rate.Limit(b.ratePerSec),
		Burst:          b.burst,
		EnableHeaders:  b.enableHeader,
		EnableLogging:  b.enableLog,
		WindowDuration: b.windowDur,
		KeyExtractor:   b.keyExtractor,
		Scope:          b.scope,
		RedisConfig:    b.factory.redisConfig,
	}
	if b.errorMsg != "" {
		config.ErrorMessage = b.errorMsg
	}
	return NewRedisRateLimiter(config, b.factory.redisClient)
}

// BuildMiddleware builds and returns middleware
func (b *RateLimiterBuilder) BuildMiddleware() gin.HandlerFunc {
	if b.keyExtractor != nil {
		// Per-client rate limiting
		limiter := b.BuildPerClient()
		return limiter.Middleware()
	}

	// Global rate limiting
	limiter := b.BuildGlobal()
	return limiter.Middleware()
}

// =============================================================================
// GLOBAL FACTORY INSTANCE
// =============================================================================

// GlobalFactory is a global factory instance that can be used throughout the application
var GlobalFactory *RateLimiterFactory

// InitializeGlobalFactory initializes the global factory with a Redis client
func InitializeGlobalFactory(redisClient component.RedisClient, redisConfig *component.RedisConfig) {
	GlobalFactory = NewRateLimiterFactory(redisClient, redisConfig)
}

// InitializeGlobalFactoryWithoutRedis initializes the global factory without Redis
func InitializeGlobalFactoryWithoutRedis() {
	GlobalFactory = NewRateLimiterFactoryWithoutRedis()
}
