package component

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"time"
)

type RedisClientImpl struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client implementation
func NewRedisClient(addr, password string, db int) (*RedisClientImpl, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClientImpl{client: rdb}, nil
}

// Implement RedisClient interface methods

func (r *RedisClientImpl) Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	return r.client.Eval(ctx, script, keys, args...).Result()
}

func (r *RedisClientImpl) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisClientImpl) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *RedisClientImpl) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

func (r *RedisClientImpl) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return r.client.Expire(ctx, key, expiration).Err()
}

func (r *RedisClientImpl) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

func (r *RedisClientImpl) ZAdd(ctx context.Context, key string, members ...interface{}) error {
	// Convert members to Redis Z structs
	var zMembers []*redis.Z
	for i := 0; i < len(members); i += 2 {
		if i+1 < len(members) {
			score, ok1 := members[i].(float64)
			member, ok2 := members[i+1].(string)
			if ok1 && ok2 {
				zMembers = append(zMembers, &redis.Z{Score: score, Member: member})
			}
		}
	}
	return r.client.ZAdd(ctx, key, zMembers...).Err()
}

func (r *RedisClientImpl) ZRemRangeByScore(ctx context.Context, key string, min, max string) error {
	return r.client.ZRemRangeByScore(ctx, key, min, max).Err()
}

func (r *RedisClientImpl) ZCard(ctx context.Context, key string) (int64, error) {
	return r.client.ZCard(ctx, key).Result()
}

func (r *RedisClientImpl) Pipeline() RedisPipeliner {
	return &RedisPipelinerImpl{pipeline: r.client.Pipeline()}
}

func (r *RedisClientImpl) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *RedisClientImpl) GetRedisClient() *redis.Client {
	return r.client
}

// RedisPipelinerImpl implements the RedisPipeliner interface
type RedisPipelinerImpl struct {
	pipeline redis.Pipeliner
}

func (p *RedisPipelinerImpl) ZRemRangeByScore(ctx context.Context, key string, min, max string) error {
	p.pipeline.ZRemRangeByScore(ctx, key, min, max)
	return nil
}

func (p *RedisPipelinerImpl) ZAdd(ctx context.Context, key string, members ...interface{}) error {
	var zMembers []*redis.Z
	for i := 0; i < len(members); i += 2 {
		if i+1 < len(members) {
			score, ok1 := members[i].(float64)
			member, ok2 := members[i+1].(string)
			if ok1 && ok2 {
				zMembers = append(zMembers, &redis.Z{Score: score, Member: member})
			}
		}
	}
	p.pipeline.ZAdd(ctx, key, zMembers...)
	return nil
}

func (p *RedisPipelinerImpl) ZCard(ctx context.Context, key string) (int64, error) {
	cmd := p.pipeline.ZCard(ctx, key)
	return cmd.Val(), nil
}

func (p *RedisPipelinerImpl) Exec(ctx context.Context) ([]interface{}, error) {
	cmds, err := p.pipeline.Exec(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]interface{}, len(cmds))
	for i, cmd := range cmds {
		results[i] = cmd
	}
	return results, nil
}
