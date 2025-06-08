# 🚀 Rate Limiter SDK for Go

A comprehensive, production-ready rate limiting middleware for Go applications using the Gin framework. This SDK provides multiple rate limiting algorithms with Redis support, fallback mechanisms, and extensive configuration options.

[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/your-username/sdk_rate_limiter?style=flat-square)](https://goreportcard.com/report/github.com/your-username/sdk_rate_limiter)

## ✨ Features

- **Multiple Algorithms**: 5 different rate limiting algorithms to choose from
- **Redis Support**: Distributed rate limiting with Redis backend
- **Fallback Mechanism**: Automatic fallback to in-memory storage when Redis fails
- **Flexible Key Extraction**: IP, User ID, API Key, or custom key extractors
- **Comprehensive Statistics**: Detailed metrics and monitoring capabilities
- **Production Ready**: Battle-tested with proper error handling and cleanup
- **Easy Integration**: Simple middleware integration with Gin framework
- **Configurable**: Extensive configuration options for fine-tuning

## 🎯 Supported Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| **Basic** | Global rate limiting | Simple server protection |
| **Token Bucket** | Burst support with smooth refill | API rate limiting with burst allowance |
| **Fixed Window** | Fixed time windows | Simple quota management |
| **Sliding Window** | Precise sliding time windows | Smooth traffic distribution |
| **Leaky Bucket** | Constant outflow rate | Traffic smoothing and shaping |

## 📦 Installation

```bash
go get github.com/your-username/sdk_rate_limiter
```

## 🚀 Quick Start

### Basic Usage (In-Memory)

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/your-username/sdk_rate_limiter/middleware"
)

func main() {
    // Initialize factory without Redis
    middleware.InitializeRateLimitProcessorWithoutRedis()
    
    // Create a basic rate limiter (100 req/sec, 10 burst)
    limiter := middleware.RateLimitProcessor.CreateBasicRateLimiter(100, 10)
    
    // Setup Gin router
    r := gin.Default()
    r.Use(limiter.Middleware())
    
    r.GET("/api/test", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello World!"})
    })
    
    r.Run(":8080")
}
```

### Advanced Usage with Redis

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/go-redis/redis/v8"
    "github.com/your-username/sdk_rate_limiter/middleware"
    "github.com/your-username/sdk_rate_limiter/component"
)

func main() {
    // Setup Redis client
    redisClient, err := component.NewRedisClient("localhost:6379", "", 0)
    if err != nil {
        panic(err)
    }
    
    // Initialize factory with Redis
    middleware.InitializeRateLimitProcessor(redisClient.GetRedisClient())
    
    // Create token bucket limiter with builder pattern
    limiter := middleware.RateLimitProcessor.NewBuilder().
        Rate(100).                    // 100 requests per second
        Burst(200).                   // 200 burst capacity
        WithIPKey().                  // Rate limit by IP
        EnableLogging().              // Enable request logging
        Window(time.Minute).          // 1-minute window
        ErrorMessage("Rate limit exceeded for your IP").
        CreateTokenBucketRateLimiter(100, 200)
    
    // Register limiter
    middleware.RateLimitRegistry.Register("api_limiter", limiter)
    
    r := gin.Default()
    r.Use(limiter.Middleware())
    
    // Stats endpoint
    r.GET("/stats", func(c *gin.Context) {
        stats := limiter.GetStats()
        c.JSON(200, stats)
    })
    
    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"data": "your data here"})
    })
    
    r.Run(":8080")
}
```

## 🔧 Configuration Examples

### 1. Token Bucket with Custom Key Extractor

```go
// Custom key extractor for API keys
apiKeyExtractor := func(c *gin.Context) string {
    apiKey := c.GetHeader("X-API-Key")
    if apiKey == "" {
        return c.ClientIP() // Fallback to IP
    }
    return "api:" + apiKey
}

config := &middleware.TokenBucketConfig{
    Rate:           rate.Limit(1000), // 1000 tokens/sec
    Burst:          2000,             // 2000 token capacity
    KeyExtractor:   apiKeyExtractor,
    EnableHeaders:  true,
    EnableLogging:  true,
    RedisClient:    redisClient,
    EnableFallback: true,
    ErrorMessage:   "API rate limit exceeded",
}

limiter := middleware.NewTokenBucketRateLimiter(config)
```

### 2. Sliding Window with User-based Limiting

```go
config := &middleware.SlidingWindowConfig{
    Rate:           100,                          // 100 requests
    WindowSize:     time.Hour,                    // per hour
    KeyExtractor:   middleware.UserIDKeyExtractor, // Rate limit by user ID
    RedisClient:    redisClient,
    EnableFallback: true,
    EnableHeaders:  true,
    MaxClients:     50000,
    ErrorMessage:   "User rate limit exceeded",
}

limiter := middleware.NewSlidingWindowRateLimiter(config)
```

### 3. Multiple Rate Limiters

```go
// Global rate limiter
globalLimiter := middleware.RateLimitProcessor.CreateBasicRateLimiter(10000, 1000)

// Per-IP rate limiter
ipLimiter := middleware.RateLimitProcessor.CreateTokenBucketRateLimiter(100, 200)

// Per-user rate limiter
userLimiter := middleware.RateLimitProcessor.NewBuilder().
    Rate(50).
    Burst(100).
    WithUserKey().
    CreateSlidingWindowsRateLimiter(50, 100)

r := gin.Default()

// Apply multiple limiters
r.Use(globalLimiter.Middleware())
r.Use(ipLimiter.Middleware()) 
r.Use(userLimiter.Middleware())
```

## 📊 Monitoring and Statistics

### Get Statistics

```go
// Get limiter statistics
stats := limiter.GetStats()
fmt.Printf("Total Requests: %d\n", stats.GetTotalRequests())
fmt.Printf("Success Rate: %.2f%%\n", stats.GetSuccessRate()*100)
fmt.Printf("Uptime: %v\n", stats.GetUptime())

// Get client-specific statistics
clientStats := limiter.GetClientStats("192.168.1.1")
fmt.Printf("Client Requests: %d\n", clientStats.TotalRequests)
```

### Registry Statistics

```go
// Get all registered limiters stats
allStats := middleware.RateLimitRegistry.GetAllStats()

// Get summary statistics
summary := middleware.RateLimitRegistry.GetSummaryStats()
```

### Built-in Stats Endpoint

```go
r.GET("/admin/rate-limit-stats", func(c *gin.Context) {
    summary := middleware.RateLimitRegistry.GetSummaryStats()
    c.JSON(200, summary)
})

r.GET("/admin/rate-limit-stats/:limiter", func(c *gin.Context) {
    limiterName := c.Param("limiter")
    if limiter, exists := middleware.RateLimitRegistry.Get(limiterName); exists {
        stats := limiter.GetStats()
        c.JSON(200, stats)
    } else {
        c.JSON(404, gin.H{"error": "limiter not found"})
    }
})
```

## 🔑 Key Extractors

### Built-in Extractors

```go
// IP-based rate limiting
middleware.IPKeyExtractor

// User ID from X-User-ID header
middleware.UserIDKeyExtractor  

// API Key from X-API-Key header
middleware.APIKeyExtractor
```

### Composite Key Extractor

```go
// Combine multiple extractors
compositeExtractor := middleware.CreateCompositeKeyExtractor(
    middleware.UserIDKeyExtractor,
    middleware.APIKeyExtractor,
    middleware.IPKeyExtractor, // Fallback
)
```

### Custom Key Extractor

```go
customExtractor := func(c *gin.Context) string {
    // Extract tenant ID from subdomain
    host := c.Request.Host
    parts := strings.Split(host, ".")
    if len(parts) > 0 {
        return "tenant:" + parts[0]
    }
    return c.ClientIP()
}
```

## 🛠️ Advanced Configuration

### Redis Configuration

```go
redisConfig := &component.RedisConfig{
    Enabled:          true,
    KeyPrefix:        "myapp_rate_limit",
    MaxRetries:       3,
    RetryDelay:       100 * time.Millisecond,
    HealthCheckDelay: 30 * time.Second,
    FallbackToMemory: true,
}

// Apply configuration when creating Redis client
redisClient, err := component.NewRedisClient("localhost:6379", "password", 0)
```

### Custom Error Responses

```go
config := &middleware.TokenBucketConfig{
    Rate:  rate.Limit(100),
    Burst: 200,
    ErrorResponse: gin.H{
        "error": "RATE_LIMIT_EXCEEDED",
        "message": "Too many requests",
        "retry_after": "60s",
        "documentation": "https://docs.example.com/rate-limits",
    },
}
```

### Custom Event Handlers

```go
config := &middleware.SlidingWindowConfig{
    Rate:       100,
    WindowSize: time.Minute,
    OnLimitExceeded: func(c *gin.Context, info *middleware.SlidingWindowRequestInfo) {
        // Custom logging
        log.Printf("Rate limit exceeded for client: %s", info.ClientKey)
        
        // Custom response
        c.JSON(429, gin.H{
            "error": "Too many requests",
            "reset_time": info.WindowEnd.Format(time.RFC3339),
        })
        c.Abort()
    },
    OnRequestProcessed: func(c *gin.Context, info *middleware.SlidingWindowRequestInfo, allowed bool) {
        // Custom metrics collection
        metrics.CounterAdd("requests_total", 1, map[string]string{
            "allowed": fmt.Sprintf("%t", allowed),
            "client":  info.ClientKey,
        })
    },
}
```

## 🧪 Testing

### Unit Tests

```bash
go test ./...
```

### Integration Tests

```bash
# Start Redis for integration tests
docker run -d -p 6379:6379 redis:alpine

# Run integration tests
go test -tags=integration ./...
```

### Load Testing Example

```go
func TestRateLimiterLoad(t *testing.T) {
    limiter := middleware.RateLimitProcessor.CreateTokenBucketRateLimiter(1000, 2000)
    
    // Simulate 10000 concurrent requests
    var wg sync.WaitGroup
    successCount := int64(0)
    
    for i := 0; i < 10000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            
            w := httptest.NewRecorder()
            c, _ := gin.CreateTestContext(w)
            c.Request = httptest.NewRequest("GET", "/test", nil)
            
            limiter.Middleware()(c)
            
            if w.Code != 429 {
                atomic.AddInt64(&successCount, 1)
            }
        }()
    }
    
    wg.Wait()
    
    stats := limiter.GetStats()
    assert.Equal(t, int64(10000), stats.GetTotalRequests())
    assert.Equal(t, successCount, stats.GetAllowedRequests())
}
```

## 📈 Performance

### Benchmarks

| Algorithm | Throughput | Memory Usage | Redis Ops/sec |
|-----------|------------|--------------|---------------|
| Basic | ~2M req/s | Low | N/A |
| Token Bucket | ~1.5M req/s | Medium | ~500K |
| Fixed Window | ~1.2M req/s | Medium | ~300K |
| Sliding Window | ~800K req/s | High | ~200K |
| Leaky Bucket | ~1M req/s | Medium | ~400K |

### Performance Tips

1. **Use Basic Limiter** for global rate limiting
2. **Token Bucket** for APIs with burst requirements
3. **Enable Redis** for distributed setups
4. **Configure cleanup intervals** appropriately
5. **Use composite keys** sparingly

## 🔄 Migration Guide

### From v1.x to v2.x

```go
// Old way (v1.x)
limiter := ratelimit.NewLimiter(100, 200)

// New way (v2.x)
limiter := middleware.RateLimitProcessor.CreateTokenBucketRateLimiter(100, 200)
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-username/sdk_rate_limiter.git
cd sdk_rate_limiter

# Install dependencies
go mod download

# Run tests
make test

# Run linting
make lint

# Start Redis for development
make redis-start
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [gin-gonic/gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [go-redis/redis](https://github.com/go-redis/redis) - Redis client
- [golang.org/x/time/rate](https://golang.org/x/time/rate) - Rate limiting utilities

## 📞 Support

- 📖 [Documentation](https://github.com/miraj90van/sdk_rate_limiter/wiki)
- 🐛 [Issue Tracker](https://github.com/miraj90van/sdk_rate_limiter/issues)
- 💬 [Discussions](https://github.com/miraj90van/sdk_rate_limiter/discussions)

---

**Made with ❤️ by [Mi'raj](https://github.com/miraj90van)**
