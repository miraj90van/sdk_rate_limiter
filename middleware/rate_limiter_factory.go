package middleware

import (
	"github.com/go-redis/redis/v8"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiterFactory helps create different types of rate limiters
type RateLimiterFactory struct {
	redisClient *redis.Client
}

// NewRateLimiterFactory creates a new rate limiter factory
func NewRateLimiterFactory(redisClient *redis.Client) *RateLimiterFactory {
	return &RateLimiterFactory{
		redisClient: redisClient,
	}
}

// NewRateLimiterFactoryWithoutRedis creates a factory without Redis support
func NewRateLimiterFactoryWithoutRedis() *RateLimiterFactory {
	return &RateLimiterFactory{
		redisClient: nil,
	}
}

func (factory *RateLimiterFactory) CreateBasicRateLimiter(requestsPerSecond float64, burst int) RateLimiter {
	config := &BasicRateLimiterConfig{
		Rate:          rate.Limit(requestsPerSecond),
		Burst:         burst,
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "basic rate limit exceeded",
	}
	return NewBasicRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateTokenBucketRateLimiter(requestsPerSecond float64, burst int) (RateLimiter, error) {
	config := &TokenBucketConfig{
		Rate:                rate.Limit(requestsPerSecond),
		Burst:               burst,
		KeyExtractor:        IPKeyExtractor,
		EnableHeaders:       true,
		EnableFallback:      true,
		RedisClient:         factory.getRedisClient(),
		ErrorMessage:        "Token Bucket Rate limit exceeded",
		RedisKeyPrefix:      "rate_limit:token:",
		MaxClients:          10000,
		MaxTrackedClients:   1000,
		CleanupInterval:     time.Minute * 5,
		ClientTTL:           time.Hour,
		RequestTimeout:      time.Second * 5,
		EnableLogging:       true,
		EnableJitter:        true,
		AllowWaiting:        false, // Set to true to enable request waiting
		MaxWaitTime:         time.Second * 5,
		MaxTokensPerRequest: 10, // Maximum tokens per request
		MetricsCollector:    nil,
	}
	return NewTokenBucketRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateSlidingWindowsRateLimiter(requestsPerSecond int, burst int) (RateLimiter, error) {
	config := &SlidingWindowConfig{
		Rate:                   requestsPerSecond,
		RedisClient:            factory.getRedisClient(),
		WindowSize:             time.Minute,
		EnableFallback:         true,
		KeyExtractor:           IPKeyExtractor,
		MaxClients:             10000,
		CleanupInterval:        time.Minute * 5,
		ClientTTL:              time.Hour,
		EnableHeaders:          true,
		EnableLogging:          false,
		ErrorMessage:           "Sliding Windows Rate limit exceeded",
		RedisKeyPrefix:         "rate_limit:sliding:",
		MaxTrackedClients:      1000,
		RequestTimeout:         time.Second * 5,
		EnableJitter:           true,
		MaxTimestampsPerClient: 200, // 2x rate for burst handling
		MetricsCollector:       nil, // Add your metrics collector here if needed
	}
	return NewSlidingWindowRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateFixedWindowRateLimiter(requestsPerSecond int, burst int) (RateLimiter, error) {
	config := &FixedWindowConfig{
		Rate:              requestsPerSecond,
		RedisClient:       factory.getRedisClient(),
		WindowSize:        time.Minute,
		EnableFallback:    true,
		KeyExtractor:      IPKeyExtractor,
		MaxClients:        10000,
		CleanupInterval:   time.Minute * 5,
		ClientTTL:         time.Hour,
		EnableHeaders:     true,
		EnableLogging:     true,
		ErrorMessage:      "Fixed Window Rate limit exceeded",
		RedisKeyPrefix:    "rate_limit:fixed:",
		MaxTrackedClients: 1000,
		RequestTimeout:    time.Second * 5,
		EnableJitter:      true,
		MetricsCollector:  nil, // Add your metrics collector here if needed
	}
	return NewFixedWindowRateLimiter(config)
}

func (factory *RateLimiterFactory) CreateLeakyBucketRateLimiter(requestsPerSecond float64, buffer int) (RateLimiter, error) {
	config := &LeakyBucketConfig{
		RedisClient:       factory.getRedisClient(),
		LeakRate:          requestsPerSecond,
		Capacity:          buffer,
		EnableFallback:    true,
		KeyExtractor:      IPKeyExtractor,
		MaxClients:        10000,
		CleanupInterval:   time.Minute * 5,
		ClientTTL:         time.Hour,
		EnableHeaders:     true,
		EnableLogging:     true,
		AllowQueueing:     false,
		MaxQueueTime:      time.Second * 10,
		ErrorMessage:      "Leaky Bucket Rate limit exceeded",
		RedisKeyPrefix:    "rate_limit:leaky:",
		MaxTrackedClients: 1000,
		RequestTimeout:    time.Second * 5,
		EnableJitter:      true,
		MetricsCollector:  nil, // Add your metrics collector here if needed
	}
	return NewLeakyBucketRateLimiter(config)
}

// getRedisClient, check redis connection is available or not
func (factory *RateLimiterFactory) getRedisClient() *redis.Client {
	var redisClient *redis.Client
	redisComponent := factory.redisClient

	if redisComponent != nil {
		redisClient = redisComponent
	}

	return redisClient
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
		windowDur:    time.Minute, // Default: 1-minute window
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

// =============================================================================
// GLOBAL FACTORY INSTANCE
// =============================================================================

// RateLimitProcessor is a global factory instance that can be used throughout the application
var RateLimitProcessor *RateLimiterFactory

// InitializeRateLimitProcessor initializes the global factory with a Redis client
func InitializeRateLimitProcessor(redisClient *redis.Client) {
	RateLimitProcessor = NewRateLimiterFactory(redisClient)
}

// InitializeRateLimitProcessorWithoutRedis initializes the global factory without Redis
func InitializeRateLimitProcessorWithoutRedis() {
	RateLimitProcessor = NewRateLimiterFactoryWithoutRedis()
}
