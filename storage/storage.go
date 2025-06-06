package storage

import (
	"context"
	"fmt"
	"time"
)

// StorageType represents the type of storage backend
type StorageType string

const (
	MemoryStorageType   StorageType = "memory"
	RedisStorageType    StorageType = "redis"
	FallbackStorageType StorageType = "fallback"
)

// StorageInfo provides information about the storage backend
type StorageInfo struct {
	Type        StorageType            `json:"type"`
	Status      string                 `json:"status"`
	Connected   bool                   `json:"connected"`
	LastError   string                 `json:"last_error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Performance *PerformanceMetrics    `json:"performance,omitempty"`
}

// PerformanceMetrics tracks storage performance
type PerformanceMetrics struct {
	TotalOperations int64         `json:"total_operations"`
	SuccessfulOps   int64         `json:"successful_ops"`
	FailedOps       int64         `json:"failed_ops"`
	AvgLatency      time.Duration `json:"avg_latency"`
	LastOperation   time.Time     `json:"last_operation"`
}

// ClientEntry represents a rate limiter entry that can be serialized
type ClientEntry struct {
	LastAccess   time.Time         `json:"last_access"`
	Created      time.Time         `json:"created"`
	RequestCount int64             `json:"request_count"`
	BlockedCount int64             `json:"blocked_count"`
	Tokens       int               `json:"tokens"`
	LastRefill   time.Time         `json:"last_refill"`
	Requests     []int64           `json:"requests"` // Timestamps for sliding window
	UserAgent    string            `json:"user_agent,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// StorageConfig represents configuration for storage backends
type StorageConfig struct {
	Type     StorageType     `json:"type"`
	Memory   *MemoryConfig   `json:"memory,omitempty"`
	Redis    *RedisConfig    `json:"redis,omitempty"`
	Fallback *FallbackConfig `json:"fallback,omitempty"`
}

// Common errors
var (
	ErrKeyNotFound     = fmt.Errorf("key not found")
	ErrStorageNotReady = fmt.Errorf("storage not ready")
	ErrInvalidKey      = fmt.Errorf("invalid key")
	ErrOperationFailed = fmt.Errorf("operation failed")
)

// RateLimiterStorage defines the interface for rate limiter storage backends
type RateLimiterStorage interface {
	// Token bucket operations
	GetTokens(ctx context.Context, key string) (tokens int, lastRefill time.Time, err error)
	SetTokens(ctx context.Context, key string, tokens int, lastRefill time.Time, ttl time.Duration) error

	// Sliding window operations
	AddRequest(ctx context.Context, key string, timestamp time.Time, window time.Duration) error
	GetRequestCount(ctx context.Context, key string, window time.Duration) (count int, err error)
	CleanupWindow(ctx context.Context, key string, window time.Duration) error

	// Generic operations
	Exists(ctx context.Context, key string) (bool, error)
	Delete(ctx context.Context, key string) error
	TTL(ctx context.Context, key string) (time.Duration, error)
	SetTTL(ctx context.Context, key string, ttl time.Duration) error

	// Batch operations for cleanup
	ListKeys(ctx context.Context, pattern string) ([]string, error)
	DeletePattern(ctx context.Context, pattern string) (int, error)

	// Advanced operations
	Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
	Decrement(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)

	// Health and connection management
	Ping(ctx context.Context) error
	Close() error

	// Storage info
	Type() StorageType
	Info() StorageInfo
}
