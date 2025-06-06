package storage

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

// NewStorage creates a storage instance based on configuration
func NewStorage(config *StorageConfig) (RateLimiterStorage, error) {
	if config == nil {
		config = &StorageConfig{Type: MemoryStorageType}
	}

	switch config.Type {
	case MemoryStorageType:
		return NewMemoryStorage(config.Memory), nil

	case RedisStorageType:
		if config.Redis == nil {
			return nil, fmt.Errorf("redis config is required for Redis storage")
		}
		return NewRedisStorage(config.Redis)

	case FallbackStorageType:
		if config.Fallback == nil {
			return nil, fmt.Errorf("fallback config is required for fallback storage")
		}
		return NewFallbackStorage(config.Fallback)

	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.Type)
	}
}

// NewRedisStorageFromURL creates Redis storage from connection URL
func NewRedisStorageFromURL(redisURL string, keyPrefix string) (*RedisStorage, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	config := &RedisConfig{
		Addr:      opt.Addr,
		Password:  opt.Password,
		DB:        opt.DB,
		KeyPrefix: keyPrefix,
	}

	return NewRedisStorage(config)
}

// NewFallbackStorageFromConfigs creates fallback storage from separate configs
func NewFallbackStorageFromConfigs(primaryConfig, fallbackConfig *StorageConfig, fallbackOptions *FallbackConfig) (RateLimiterStorage, error) {
	primary, err := NewStorage(primaryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary storage: %w", err)
	}

	fallback, err := NewStorage(fallbackConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback storage: %w", err)
	}

	if fallbackOptions == nil {
		fallbackOptions = &FallbackConfig{}
	}
	fallbackOptions.Primary = primary
	fallbackOptions.Fallback = fallback

	return NewFallbackStorage(fallbackOptions)
}

// CreateRedisCluster creates a Redis cluster client
func CreateRedisCluster(addrs []string, password string) redis.UniversalClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    addrs,
		Password: password,
	})
}

// CreateRedisFailover creates a Redis sentinel client
func CreateRedisFailover(masterName string, sentinelAddrs []string, password string) redis.UniversalClient {
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    masterName,
		SentinelAddrs: sentinelAddrs,
		Password:      password,
	})
}
