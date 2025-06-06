package storage

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// FallbackConfig configuration for fallback storage
type FallbackConfig struct {
	Primary             RateLimiterStorage `json:"-"`
	Fallback            RateLimiterStorage `json:"-"`
	HealthCheckInterval time.Duration      `json:"health_check_interval"`
	FailureThreshold    int                `json:"failure_threshold"`
	RecoveryThreshold   int                `json:"recovery_threshold"`
	EnableLogging       bool               `json:"enable_logging"`
}

// FallbackStorage implements automatic fallback between storage backends
type FallbackStorage struct {
	primary  RateLimiterStorage
	fallback RateLimiterStorage
	config   *FallbackConfig

	// Health tracking
	primaryHealthy  bool
	failureCount    int
	recoveryCount   int
	lastHealthCheck time.Time
	mu              sync.RWMutex

	// Background health checker
	healthTicker    *time.Ticker
	stopHealthCheck chan struct{}

	metrics   *PerformanceMetrics
	metricsMu sync.RWMutex
}

// NewFallbackStorage creates a new fallback storage
func NewFallbackStorage(config *FallbackConfig) (*FallbackStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("fallback config is required")
	}

	if config.Primary == nil || config.Fallback == nil {
		return nil, fmt.Errorf("both primary and fallback storage are required")
	}

	// Set defaults
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 3
	}
	if config.RecoveryThreshold <= 0 {
		config.RecoveryThreshold = 3
	}

	fs := &FallbackStorage{
		primary:         config.Primary,
		fallback:        config.Fallback,
		config:          config,
		primaryHealthy:  true,
		stopHealthCheck: make(chan struct{}),
		metrics: &PerformanceMetrics{
			LastOperation: time.Now(),
		},
	}

	// Start health checking
	fs.startHealthCheck()

	return fs, nil
}

func (fs *FallbackStorage) startHealthCheck() {
	fs.healthTicker = time.NewTicker(fs.config.HealthCheckInterval)

	go func() {
		for {
			select {
			case <-fs.healthTicker.C:
				fs.checkHealth()
			case <-fs.stopHealthCheck:
				fs.healthTicker.Stop()
				return
			}
		}
	}()
}

func (fs *FallbackStorage) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := fs.primary.Ping(ctx)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.lastHealthCheck = time.Now()

	if err != nil {
		fs.failureCount++
		fs.recoveryCount = 0

		if fs.primaryHealthy && fs.failureCount >= fs.config.FailureThreshold {
			fs.primaryHealthy = false
			if fs.config.EnableLogging {
				log.Printf("Fallback Storage: Primary storage marked as unhealthy after %d failures", fs.failureCount)
			}
		}
	} else {
		fs.failureCount = 0
		fs.recoveryCount++

		if !fs.primaryHealthy && fs.recoveryCount >= fs.config.RecoveryThreshold {
			fs.primaryHealthy = true
			if fs.config.EnableLogging {
				log.Printf("Fallback Storage: Primary storage recovered after %d successful checks", fs.recoveryCount)
			}
		}
	}
}

func (fs *FallbackStorage) getStorage() RateLimiterStorage {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.primaryHealthy {
		return fs.primary
	}
	return fs.fallback
}

func (fs *FallbackStorage) recordOperation(success bool, duration time.Duration) {
	fs.metricsMu.Lock()
	defer fs.metricsMu.Unlock()

	fs.metrics.TotalOperations++
	if success {
		fs.metrics.SuccessfulOps++
	} else {
		fs.metrics.FailedOps++
	}

	if fs.metrics.TotalOperations == 1 {
		fs.metrics.AvgLatency = duration
	} else {
		fs.metrics.AvgLatency = (fs.metrics.AvgLatency + duration) / 2
	}
	fs.metrics.LastOperation = time.Now()
}

// Implement RateLimiterStorage interface by delegating to active storage

func (fs *FallbackStorage) GetTokens(ctx context.Context, key string) (int, time.Time, error) {
	start := time.Now()
	storage := fs.getStorage()
	tokens, lastRefill, err := storage.GetTokens(ctx, key)
	fs.recordOperation(err == nil, time.Since(start))
	return tokens, lastRefill, err
}

func (fs *FallbackStorage) SetTokens(ctx context.Context, key string, tokens int, lastRefill time.Time, ttl time.Duration) error {
	start := time.Now()
	storage := fs.getStorage()
	err := storage.SetTokens(ctx, key, tokens, lastRefill, ttl)
	fs.recordOperation(err == nil, time.Since(start))
	return err
}

func (fs *FallbackStorage) AddRequest(ctx context.Context, key string, timestamp time.Time, window time.Duration) error {
	start := time.Now()
	storage := fs.getStorage()
	err := storage.AddRequest(ctx, key, timestamp, window)
	fs.recordOperation(err == nil, time.Since(start))
	return err
}

func (fs *FallbackStorage) GetRequestCount(ctx context.Context, key string, window time.Duration) (int, error) {
	start := time.Now()
	storage := fs.getStorage()
	count, err := storage.GetRequestCount(ctx, key, window)
	fs.recordOperation(err == nil, time.Since(start))
	return count, err
}

func (fs *FallbackStorage) CleanupWindow(ctx context.Context, key string, window time.Duration) error {
	start := time.Now()
	storage := fs.getStorage()
	err := storage.CleanupWindow(ctx, key, window)
	fs.recordOperation(err == nil, time.Since(start))
	return err
}

func (fs *FallbackStorage) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	storage := fs.getStorage()
	exists, err := storage.Exists(ctx, key)
	fs.recordOperation(err == nil, time.Since(start))
	return exists, err
}

func (fs *FallbackStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	storage := fs.getStorage()
	err := storage.Delete(ctx, key)
	fs.recordOperation(err == nil, time.Since(start))
	return err
}

func (fs *FallbackStorage) TTL(ctx context.Context, key string) (time.Duration, error) {
	start := time.Now()
	storage := fs.getStorage()
	ttl, err := storage.TTL(ctx, key)
	fs.recordOperation(err == nil, time.Since(start))
	return ttl, err
}

func (fs *FallbackStorage) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	start := time.Time{}
	storage := fs.getStorage()
	err := storage.SetTTL(ctx, key, ttl)
	fs.recordOperation(err == nil, time.Since(start))
	return err
}

func (fs *FallbackStorage) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	start := time.Now()
	storage := fs.getStorage()
	keys, err := storage.ListKeys(ctx, pattern)
	fs.recordOperation(err == nil, time.Since(start))
	return keys, err
}

func (fs *FallbackStorage) DeletePattern(ctx context.Context, pattern string) (int, error) {
	start := time.Now()
	storage := fs.getStorage()
	count, err := storage.DeletePattern(ctx, pattern)
	fs.recordOperation(err == nil, time.Since(start))
	return count, err
}

func (fs *FallbackStorage) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	storage := fs.getStorage()
	result, err := storage.Increment(ctx, key, delta, ttl)
	fs.recordOperation(err == nil, time.Since(start))
	return result, err
}

func (fs *FallbackStorage) Decrement(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	storage := fs.getStorage()
	result, err := storage.Decrement(ctx, key, delta, ttl)
	fs.recordOperation(err == nil, time.Since(start))
	return result, err
}

func (fs *FallbackStorage) Ping(ctx context.Context) error {
	return fs.getStorage().Ping(ctx)
}

func (fs *FallbackStorage) Close() error {
	close(fs.stopHealthCheck)

	var errors []error
	if err := fs.primary.Close(); err != nil {
		errors = append(errors, fmt.Errorf("primary storage close error: %w", err))
	}
	if err := fs.fallback.Close(); err != nil {
		errors = append(errors, fmt.Errorf("fallback storage close error: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %v", errors)
	}
	return nil
}

func (fs *FallbackStorage) Type() StorageType {
	return FallbackStorageType
}

func (fs *FallbackStorage) Info() StorageInfo {
	fs.mu.RLock()
	primaryHealthy := fs.primaryHealthy
	failureCount := fs.failureCount
	recoveryCount := fs.recoveryCount
	lastHealthCheck := fs.lastHealthCheck
	fs.mu.RUnlock()

	fs.metricsMu.RLock()
	metrics := *fs.metrics
	fs.metricsMu.RUnlock()

	activeStorage := "primary"
	if !primaryHealthy {
		activeStorage = "fallback"
	}

	return StorageInfo{
		Type:      FallbackStorageType,
		Status:    "healthy",
		Connected: true,
		Metadata: map[string]interface{}{
			"active_storage":    activeStorage,
			"primary_healthy":   primaryHealthy,
			"failure_count":     failureCount,
			"recovery_count":    recoveryCount,
			"last_health_check": lastHealthCheck,
			"primary_type":      fs.primary.Type(),
			"fallback_type":     fs.fallback.Type(),
		},
		Performance: &metrics,
	}
}
