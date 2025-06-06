package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configuration for Redis storage
type RedisConfig struct {
	// Connection settings
	Addr         string        `json:"addr"`
	Password     string        `json:"password"`
	DB           int           `json:"db"`
	PoolSize     int           `json:"pool_size"`
	MinIdleConns int           `json:"min_idle_conns"`
	MaxRetries   int           `json:"max_retries"`
	DialTimeout  time.Duration `json:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`

	// Rate limiter specific
	KeyPrefix string `json:"key_prefix"`

	// Advanced settings
	ExistingClient redis.UniversalClient `json:"-"`
	EnableMetrics  bool                  `json:"enable_metrics"`
}

// RedisStorage implements RateLimiterStorage using Redis
type RedisStorage struct {
	client      redis.UniversalClient
	prefix      string
	ownedClient bool
	config      *RedisConfig
	metrics     *PerformanceMetrics
	metricsMu   sync.RWMutex
	closed      bool
}

// NewRedisStorage creates a new Redis storage instance
func NewRedisStorage(config *RedisConfig) (*RedisStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("Redis config is required")
	}

	var client redis.UniversalClient
	var ownedClient bool

	// Priority 1: Use existing client
	if config.ExistingClient != nil {
		client = config.ExistingClient
		ownedClient = false

		// Priority 2: Create new client from config
	} else if config.Addr != "" {
		client = redis.NewClient(&redis.Options{
			Addr:         config.Addr,
			Password:     config.Password,
			DB:           config.DB,
			PoolSize:     config.PoolSize,
			MinIdleConns: config.MinIdleConns,
			MaxRetries:   config.MaxRetries,
			DialTimeout:  config.DialTimeout,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
		})
		ownedClient = true

	} else {
		return nil, fmt.Errorf("no Redis client configuration provided")
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		if ownedClient {
			client.Close()
		}
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	prefix := config.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit:"
	}

	return &RedisStorage{
		client:      client,
		prefix:      prefix,
		ownedClient: ownedClient,
		config:      config,
		metrics: &PerformanceMetrics{
			LastOperation: time.Now(),
		},
	}, nil
}

// NewRedisStorageFromClient creates Redis storage from existing client
func NewRedisStorageFromClient(client redis.UniversalClient, keyPrefix string) *RedisStorage {
	if keyPrefix == "" {
		keyPrefix = "ratelimit:"
	}

	return &RedisStorage{
		client:      client,
		prefix:      keyPrefix,
		ownedClient: false,
		config: &RedisConfig{
			KeyPrefix:     keyPrefix,
			EnableMetrics: true,
		},
		metrics: &PerformanceMetrics{
			LastOperation: time.Now(),
		},
	}
}

func (r *RedisStorage) key(key string) string {
	return r.prefix + key
}

func (r *RedisStorage) recordOperation(success bool, duration time.Duration) {
	if !r.config.EnableMetrics {
		return
	}

	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()

	atomic.AddInt64(&r.metrics.TotalOperations, 1)
	if success {
		atomic.AddInt64(&r.metrics.SuccessfulOps, 1)
	} else {
		atomic.AddInt64(&r.metrics.FailedOps, 1)
	}

	// Update average latency
	if r.metrics.TotalOperations == 1 {
		r.metrics.AvgLatency = duration
	} else {
		r.metrics.AvgLatency = (r.metrics.AvgLatency + duration) / 2
	}
	r.metrics.LastOperation = time.Now()
}

func (r *RedisStorage) GetTokens(ctx context.Context, key string) (int, time.Time, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return 0, time.Time{}, ErrStorageNotReady
	}

	redisKey := r.key(key)

	result, err := r.client.HMGet(ctx, redisKey, "tokens", "last_refill").Result()
	if err != nil {
		if err == redis.Nil {
			return 0, time.Time{}, nil
		}
		r.recordOperation(false, time.Since(start))
		return 0, time.Time{}, err
	}

	tokens := 0
	var lastRefill time.Time

	if result[0] != nil {
		if tokensStr, ok := result[0].(string); ok {
			tokens, _ = strconv.Atoi(tokensStr)
		}
	}

	if result[1] != nil {
		if refillStr, ok := result[1].(string); ok {
			lastRefill, _ = time.Parse(time.RFC3339Nano, refillStr)
		}
	}

	return tokens, lastRefill, nil
}

func (r *RedisStorage) SetTokens(ctx context.Context, key string, tokens int, lastRefill time.Time, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	redisKey := r.key(key)

	pipe := r.client.Pipeline()
	pipe.HMSet(ctx, redisKey, map[string]interface{}{
		"tokens":      tokens,
		"last_refill": lastRefill.Format(time.RFC3339Nano),
		"last_access": time.Now().Format(time.RFC3339Nano),
	})

	if ttl > 0 {
		pipe.Expire(ctx, redisKey, ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) AddRequest(ctx context.Context, key string, timestamp time.Time, window time.Duration) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	redisKey := r.key(key)
	score := float64(timestamp.UnixNano())
	member := timestamp.UnixNano()

	pipe := r.client.Pipeline()

	// Add request to sorted set
	pipe.ZAdd(ctx, redisKey, redis.Z{
		Score:  score,
		Member: member,
	})

	// Remove old requests outside window
	windowStart := timestamp.Add(-window)
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("(%d", windowStart.UnixNano()))

	// Set TTL
	pipe.Expire(ctx, redisKey, window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) GetRequestCount(ctx context.Context, key string, window time.Duration) (int, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return 0, ErrStorageNotReady
	}

	redisKey := r.key(key)
	now := time.Now()
	windowStart := now.Add(-window)

	count, err := r.client.ZCount(ctx, redisKey,
		fmt.Sprintf("%d", windowStart.UnixNano()),
		fmt.Sprintf("%d", now.UnixNano())).Result()

	if err != nil {
		r.recordOperation(false, time.Since(start))
		return 0, err
	}

	return int(count), nil
}

func (r *RedisStorage) CleanupWindow(ctx context.Context, key string, window time.Duration) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	redisKey := r.key(key)
	windowStart := time.Now().Add(-window)

	_, err := r.client.ZRemRangeByScore(ctx, redisKey, "0",
		fmt.Sprintf("(%d", windowStart.UnixNano())).Result()

	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return false, ErrStorageNotReady
	}

	redisKey := r.key(key)
	result, err := r.client.Exists(ctx, redisKey).Result()
	if err != nil {
		r.recordOperation(false, time.Since(start))
		return false, err
	}
	return result > 0, nil
}

func (r *RedisStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	redisKey := r.key(key)
	err := r.client.Del(ctx, redisKey).Err()
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) TTL(ctx context.Context, key string) (time.Duration, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return 0, ErrStorageNotReady
	}

	redisKey := r.key(key)
	result, err := r.client.TTL(ctx, redisKey).Result()
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return result, err
}

func (r *RedisStorage) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	redisKey := r.key(key)
	err := r.client.Expire(ctx, redisKey, ttl).Err()
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return nil, ErrStorageNotReady
	}

	searchPattern := r.key(pattern)
	if !strings.Contains(searchPattern, "*") {
		searchPattern += "*"
	}

	keys, err := r.client.Keys(ctx, searchPattern).Result()
	if err != nil {
		r.recordOperation(false, time.Since(start))
		return nil, err
	}

	// Remove prefix from keys
	result := make([]string, len(keys))
	for i, key := range keys {
		result[i] = strings.TrimPrefix(key, r.prefix)
	}

	return result, nil
}

func (r *RedisStorage) DeletePattern(ctx context.Context, pattern string) (int, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return 0, ErrStorageNotReady
	}

	keys, err := r.ListKeys(ctx, pattern)
	if err != nil {
		return 0, err
	}

	if len(keys) == 0 {
		return 0, nil
	}

	// Add prefix back for deletion
	redisKeys := make([]string, len(keys))
	for i, key := range keys {
		redisKeys[i] = r.key(key)
	}

	result, err := r.client.Del(ctx, redisKeys...).Result()
	if err != nil {
		r.recordOperation(false, time.Since(start))
		return 0, err
	}
	return int(result), nil
}

func (r *RedisStorage) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return 0, ErrStorageNotReady
	}

	redisKey := r.key(key)

	pipe := r.client.Pipeline()
	incr := pipe.IncrBy(ctx, redisKey, delta)
	if ttl > 0 {
		pipe.Expire(ctx, redisKey, ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		r.recordOperation(false, time.Since(start))
		return 0, err
	}

	return incr.Val(), nil
}

func (r *RedisStorage) Decrement(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	return r.Increment(ctx, key, -delta, ttl)
}

func (r *RedisStorage) Ping(ctx context.Context) error {
	start := time.Now()
	defer func() {
		r.recordOperation(!r.closed, time.Since(start))
	}()

	if r.closed {
		return ErrStorageNotReady
	}

	err := r.client.Ping(ctx).Err()
	if err != nil {
		r.recordOperation(false, time.Since(start))
	}
	return err
}

func (r *RedisStorage) Close() error {
	r.closed = true
	if r.ownedClient && r.client != nil {
		return r.client.Close()
	}
	return nil
}

func (r *RedisStorage) Type() StorageType {
	return RedisStorageType
}

func (r *RedisStorage) Info() StorageInfo {
	r.metricsMu.RLock()
	metrics := *r.metrics
	r.metricsMu.RUnlock()

	status := "healthy"
	connected := !r.closed
	lastError := ""

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		status = "unhealthy"
		connected = false
		lastError = err.Error()
	}

	return StorageInfo{
		Type:      RedisStorageType,
		Status:    status,
		Connected: connected,
		LastError: lastError,
		Metadata: map[string]interface{}{
			"key_prefix":   r.prefix,
			"owned_client": r.ownedClient,
		},
		Performance: &metrics,
	}
}
