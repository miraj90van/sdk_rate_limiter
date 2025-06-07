package component

import (
	"context"
	"github.com/go-redis/redis/v8"
	"time"
)

// RedisClient interface that must be implemented by the feature repository
type RedisClient interface {
	// Eval executes a Lua script
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error)

	// Set sets a key-value pair with expiration
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// Get gets a value by key
	Get(ctx context.Context, key string) (string, error)

	// Incr increments a key
	Incr(ctx context.Context, key string) (int64, error)

	// Expire sets expiration for a key
	Expire(ctx context.Context, key string, expiration time.Duration) error

	// Del deletes keys
	Del(ctx context.Context, keys ...string) error

	// ZAdd adds members to sorted set
	ZAdd(ctx context.Context, key string, members ...interface{}) error

	// ZRemRangeByScore removes members by score range
	ZRemRangeByScore(ctx context.Context, key string, min, max string) error

	// ZCard gets cardinality of sorted set
	ZCard(ctx context.Context, key string) (int64, error)

	// Pipeline creates a pipeline
	Pipeline() RedisPipeliner

	// Ping checks connection
	Ping(ctx context.Context) error

	GetRedisClient() *redis.Client
}

// RedisPipeliner interface for Redis pipeline operations
type RedisPipeliner interface {
	ZRemRangeByScore(ctx context.Context, key string, min, max string) error
	ZAdd(ctx context.Context, key string, members ...interface{}) error
	ZCard(ctx context.Context, key string) (int64, error)
	Exec(ctx context.Context) ([]interface{}, error)
}

// RedisConfig contains Redis connection configuration
type RedisConfig struct {
	Enabled          bool          `json:"enabled"`            // Enable Redis support
	KeyPrefix        string        `json:"key_prefix"`         // Key prefix for rate limiting
	MaxRetries       int           `json:"max_retries"`        // Max retry attempts
	RetryDelay       time.Duration `json:"retry_delay"`        // Delay between retries
	HealthCheckDelay time.Duration `json:"health_check_delay"` // Health check interval
	FallbackToMemory bool          `json:"fallback_to_memory"` // Fallback to memory if Redis fails
}

// DefaultRedisConfig returns default Redis configuration
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Enabled:          false,
		KeyPrefix:        "rate_limiter",
		MaxRetries:       3,
		RetryDelay:       100 * time.Millisecond,
		HealthCheckDelay: 30 * time.Second,
		FallbackToMemory: true,
	}
}

// Validate validates Redis configuration
func (rc *RedisConfig) Validate() error {
	if rc.KeyPrefix == "" {
		rc.KeyPrefix = "rate_limiter"
	}
	if rc.MaxRetries <= 0 {
		rc.MaxRetries = 3
	}
	if rc.RetryDelay <= 0 {
		rc.RetryDelay = 100 * time.Millisecond
	}
	if rc.HealthCheckDelay <= 0 {
		rc.HealthCheckDelay = 30 * time.Second
	}
	return nil
}
