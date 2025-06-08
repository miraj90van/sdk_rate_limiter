package integration

import (
	"context"
	"fmt"
	"github.com/miraj90van/sdk_rate_limiter/middleware"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"
)

type RateLimiterTestSuite struct {
	suite.Suite
	redisClient *redis.Client
	ctx         context.Context
}

func (suite *RateLimiterTestSuite) SetupSuite() {
	// Setup Redis for integration tests
	suite.redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use different DB for tests
	})

	suite.ctx = context.Background()

	// Test Redis connection
	err := suite.redisClient.Ping(suite.ctx).Err()
	if err != nil {
		suite.T().Skip("Redis not available, skipping integration tests")
	}
}

func (suite *RateLimiterTestSuite) SetupTest() {
	// Clean Redis before each test
	suite.redisClient.FlushDB(suite.ctx)
}

func (suite *RateLimiterTestSuite) TearDownSuite() {
	if suite.redisClient != nil {
		suite.redisClient.Close()
	}
}

func TestRateLimiterSuite(t *testing.T) {
	suite.Run(t, new(RateLimiterTestSuite))
}

func TestBasicRateLimiter_Configuration(t *testing.T) {
	tests := []struct {
		name        string
		config      *middleware.BasicRateLimiterConfig
		expectError bool
	}{
		{
			name: "Valid configuration",
			config: &middleware.BasicRateLimiterConfig{
				Rate:          rate.Limit(100),
				Burst:         10,
				EnableHeaders: true,
			},
			expectError: false,
		},
		{
			name:        "Default configuration",
			config:      nil,
			expectError: false,
		},
		{
			name: "Zero rate",
			config: &middleware.BasicRateLimiterConfig{
				Rate:  0,
				Burst: 10,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := middleware.NewBasicRateLimiter(tt.config)
			assert.NotNil(t, limiter)

			if tt.expectError {
				// Test with invalid config should still create limiter with defaults
				assert.Equal(t, middleware.BasicType, limiter.Type())
			}
		})
	}
}

func TestTokenBucketRateLimiter_BasicFunctionality(t *testing.T) {
	config := &middleware.TokenBucketConfig{
		Rate:           rate.Limit(10), // 10 req/sec
		Burst:          5,              // 5 burst
		EnableFallback: true,
		KeyExtractor:   middleware.IPKeyExtractor,
		EnableHeaders:  true,
		EnableLogging:  false,
	}

	limiter := middleware.NewTokenBucketRateLimiter(config)
	defer limiter.Stop()

	// Test middleware creation
	middleware := limiter.Middleware()
	assert.NotNil(t, middleware)

	// Test stats
	stats := limiter.GetStats()
	assert.Equal(t, int64(0), stats.GetTotalRequests())
}

func TestTokenBucketRateLimiter_Concurrency(t *testing.T) {
	config := &middleware.TokenBucketConfig{
		Rate:           rate.Limit(1000), // 1000 req/sec
		Burst:          100,              // 100 burst
		EnableFallback: true,
		KeyExtractor:   middleware.IPKeyExtractor,
	}

	limiter := middleware.NewTokenBucketRateLimiter(config)
	defer limiter.Stop()

	const numGoroutines = 100
	const requestsPerGoroutine = 10
	var successCount int64

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("GET", "/test", nil)
				c.Request.RemoteAddr = fmt.Sprintf("192.168.1.%d:8080", goroutineID%255+1)

				limiter.Middleware()(c)

				if w.Code != http.StatusTooManyRequests {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	stats := limiter.GetStats()
	totalRequests := int64(numGoroutines * requestsPerGoroutine)

	assert.Equal(t, totalRequests, stats.GetTotalRequests())
	assert.Equal(t, successCount, stats.GetAllowedRequests())
	assert.Equal(t, totalRequests-successCount, stats.GetBlockedRequests())

	// Verify no data races occurred
	assert.True(t, successCount > 0, "Some requests should have succeeded")
	assert.True(t, successCount <= totalRequests, "Success count should not exceed total")
}

func BenchmarkBasicRateLimiter_Allow(b *testing.B) {
	limiter := middleware.NewBasicRateLimiter(&middleware.BasicRateLimiterConfig{
		Rate:  rate.Limit(1000000), // Very high limit
		Burst: 1000000,
	})
	defer limiter.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			limiter.Middleware()(c)
		}
	})
}

func BenchmarkTokenBucketRateLimiter_Memory(b *testing.B) {
	config := &middleware.TokenBucketConfig{
		Rate:           rate.Limit(1000000), // Very high limit
		Burst:          1000000,
		EnableFallback: true,
		KeyExtractor:   middleware.IPKeyExtractor,
	}

	limiter := middleware.NewTokenBucketRateLimiter(config)
	defer limiter.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		clientID := 0
		for pb.Next() {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)
			c.Request.RemoteAddr = fmt.Sprintf("192.168.1.%d:8080", clientID%255+1)

			limiter.Middleware()(c)
			clientID++
		}
	})
}

func (suite *RateLimiterTestSuite) TestMultipleLimiters_Integration() {
	// Global limiter: 1000 req/sec
	globalLimiter := middleware.NewBasicRateLimiter(&middleware.BasicRateLimiterConfig{
		Rate:  rate.Limit(1000),
		Burst: 100,
	})
	defer globalLimiter.Stop()

	// Per-IP limiter: 10 req/sec
	ipLimiter := middleware.NewTokenBucketRateLimiter(&middleware.TokenBucketConfig{
		Rate:           rate.Limit(10),
		Burst:          5,
		RedisClient:    suite.redisClient,
		KeyExtractor:   middleware.IPKeyExtractor,
		EnableFallback: true,
	})
	defer ipLimiter.Stop()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(globalLimiter.Middleware())
	r.Use(ipLimiter.Middleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	// Test requests from same IP
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:8080"
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		if i < 5 {
			assert.Equal(suite.T(), http.StatusOK, w.Code, "Request %d should succeed", i)
		} else {
			assert.Equal(suite.T(), http.StatusTooManyRequests, w.Code, "Request %d should be blocked", i)
		}
	}
}

func TestRateLimiter_LoadTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	config := &middleware.SlidingWindowConfig{
		Rate:           1000, // 1000 req/minute
		WindowSize:     time.Minute,
		EnableFallback: true,
		KeyExtractor:   middleware.IPKeyExtractor,
	}

	limiter := middleware.NewSlidingWindowRateLimiter(config)
	defer limiter.Stop()

	const totalRequests = 50000
	const numClients = 100
	const requestsPerClient = totalRequests / numClients

	var wg sync.WaitGroup
	results := make([]int, numClients)

	startTime := time.Now()

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			successCount := 0
			for i := 0; i < requestsPerClient; i++ {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("GET", "/test", nil)
				c.Request.RemoteAddr = fmt.Sprintf("192.168.1.%d:8080", id%255+1)

				limiter.Middleware()(c)

				if w.Code != http.StatusTooManyRequests {
					successCount++
				}

				// Small delay to simulate real traffic
				time.Sleep(time.Microsecond * 100)
			}
			results[id] = successCount
		}(clientID)
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Calculate results
	totalSuccess := 0
	for _, success := range results {
		totalSuccess += success
	}

	stats := limiter.GetStats()

	t.Logf("Load Test Results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful Requests: %d", totalSuccess)
	t.Logf("  Blocked Requests: %d", totalRequests-totalSuccess)
	t.Logf("  Success Rate: %.2f%%", float64(totalSuccess)/float64(totalRequests)*100)
	t.Logf("  Throughput: %.0f req/sec", float64(totalRequests)/duration.Seconds())

	assert.Equal(t, int64(totalRequests), stats.GetTotalRequests())
	assert.Equal(t, int64(totalSuccess), stats.GetAllowedRequests())
	assert.True(t, totalSuccess > 0, "Some requests should succeed")
}

func (suite *RateLimiterTestSuite) TestRedisFailover() {
	config := &middleware.TokenBucketConfig{
		Rate:           rate.Limit(10),
		Burst:          5,
		RedisClient:    suite.redisClient,
		EnableFallback: true,
		KeyExtractor:   middleware.IPKeyExtractor,
	}

	limiter := middleware.NewTokenBucketRateLimiter(config)
	defer limiter.Stop()

	// Test with Redis working
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1:8080"

	limiter.Middleware()(c)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Simulate Redis failure by closing connection
	suite.redisClient.Close()

	// Next request should fallback to memory
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1:8080"

	limiter.Middleware()(c)
	// Should still work due to fallback
	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

func TestRateLimiter_MemoryCleanup(t *testing.T) {
	config := &middleware.TokenBucketConfig{
		Rate:            rate.Limit(100),
		Burst:           10,
		EnableFallback:  true,
		KeyExtractor:    middleware.IPKeyExtractor,
		CleanupInterval: time.Millisecond * 100, // Fast cleanup for testing
		ClientTTL:       time.Millisecond * 200, // Short TTL for testing
	}

	limiter := middleware.NewTokenBucketRateLimiter(config)
	defer limiter.Stop()

	// Generate requests from many different IPs
	for i := 0; i < 1000; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = fmt.Sprintf("192.168.%d.%d:8080", i/255, i%255)

		limiter.Middleware()(c)
	}

	// Check initial client count
	initialCount := limiter.GetClientCount()
	assert.True(t, initialCount > 0, "Should have active clients")

	// Wait for cleanup
	time.Sleep(time.Millisecond * 500)

	// Check client count after cleanup
	finalCount := limiter.GetClientCount()
	assert.True(t, finalCount < initialCount, "Client count should decrease after cleanup")
}

func createTestGinContext(method, path, remoteAddr string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	c.Request.RemoteAddr = remoteAddr
	return c, w
}

func assertRateLimitHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should have rate limit header")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "Should have remaining header")
}

func TestAllRateLimiters_BasicFunctionality(t *testing.T) {
	testCases := []struct {
		name    string
		limiter middleware.RateLimiter
	}{
		{
			name:    "BasicRateLimiter",
			limiter: middleware.NewBasicRateLimiter(middleware.DefaultBasicConfig()),
		},
		{
			name:    "TokenBucketRateLimiter",
			limiter: middleware.NewTokenBucketRateLimiter(middleware.DefaultTokenBucketConfig()),
		},
		{
			name:    "SlidingWindowRateLimiter",
			limiter: middleware.NewSlidingWindowRateLimiter(middleware.DefaultSlidingWindowConfig()),
		},
		{
			name:    "FixedWindowRateLimiter",
			limiter: middleware.NewFixedWindowRateLimiter(middleware.DefaultFixedWindowConfig()),
		},
		{
			name:    "LeakyBucketRateLimiter",
			limiter: middleware.NewLeakyBucketRateLimiter(middleware.DefaultLeakyBucketConfig()),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.limiter.Stop()

			// Test middleware creation
			middleware := tc.limiter.Middleware()
			assert.NotNil(t, middleware)

			// Test stats
			stats := tc.limiter.GetStats()
			assert.NotNil(t, stats)
			assert.Equal(t, int64(0), stats.GetTotalRequests())

			// Test request processing
			c, w := createTestGinContext("GET", "/test", "192.168.1.1:8080")
			middleware(c)

			// Should not return error for first request
			assert.NotEqual(t, http.StatusInternalServerError, w.Code)
		})
	}
}
