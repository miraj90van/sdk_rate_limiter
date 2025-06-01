# Rate Limiter SDK for Gin Framework

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/rate-limiter-sdk)

A comprehensive, production-ready rate limiting SDK for Gin web framework with multiple algorithms and flexible configuration options.

## 🚀 Features

- **6 Rate Limiting Strategies**: Basic, IP-based, User-based, Advanced, Sliding Window, Token Bucket
- **Thread-Safe**: Concurrent request handling with proper synchronization
- **Memory Efficient**: Automatic cleanup and configurable limits
- **Production Ready**: Comprehensive monitoring, statistics, and error handling
- **Flexible Configuration**: Extensive customization options for each rate limiter
- **Registry System**: Centralized management of multiple rate limiters
- **Standard Headers**: RFC-compliant rate limiting headers
- **Graceful Degradation**: Token bucket with waiting capabilities

## 📦 Installation

```bash
go get github.com/yourusername/rate-limiter-sdk
```

## 🎯 Quick Start

```go
package main

import (
    "github.com/gin-gonic/gin"
    "your-repo/middleware"
)

func main() {
    r := gin.Default()
    
    // Basic global rate limiting (1000 req/sec for all clients)
    r.Use(middleware.BasicRateLimitMiddleware(1000, 100))
    
    // Per-IP rate limiting (100 req/sec per IP)
    r.Use(middleware.IPRateLimitMiddleware(100, 20))
    
    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "success"})
    })
    
    r.Run(":8080")
}
```

## 📋 Rate Limiter Types

### 1. Basic Rate Limiter (Global)
**Purpose**: Server protection - all clients share the same rate limit

```go
// All clients share 1000 req/sec total
r.Use(middleware.BasicRateLimitMiddleware(1000, 100))
```

**Use Cases**:
- Server overload protection
- Emergency rate limiting
- DDoS protection

### 2. IP Rate Limiter
**Purpose**: Fair limiting per IP address

```go
// Each IP gets 100 req/sec individually
r.Use(middleware.IPRateLimitMiddleware(100, 20))
```

**Features**:
- Trusted proxy support
- IP whitelist/blacklist
- Geographic blocking (optional)

### 3. User Rate Limiter
**Purpose**: Fair limiting per authenticated user

```go
// Each user gets 50 req/sec individually
r.Use(middleware.UserRateLimitMiddleware(50, 10))
```

**Features**:
- Multiple authentication methods
- Fallback to IP for anonymous users
- Tier-based limiting support

### 4. Advanced Rate Limiter
**Purpose**: Flexible rate limiting with custom key extraction

```go
// Tier-based limiting
r.Use(middleware.TierBasedRateLimitMiddleware(100, 20))
```

**Features**:
- Custom key extraction functions
- Multi-tenant support
- Composite keys

### 5. Sliding Window Rate Limiter
**Purpose**: Precise time-window based limiting

```go
// Exactly 100 requests per minute
r.Use(middleware.SlidingWindowRateLimitMiddleware(100, time.Minute))
```

**Features**:
- Exact time tracking
- Precise quotas
- Regulatory compliance

### 6. Token Bucket Rate Limiter
**Purpose**: Graceful rate limiting with waiting capability

```go
// Wait up to 2 seconds for tokens
r.Use(middleware.WaitingTokenBucketRateLimitMiddleware(10, 5, 2*time.Second))
```

**Features**:
- Queue-like behavior
- Graceful degradation
- Burst traffic handling

## 🏗️ Architecture Patterns

### Layered Protection
```go
func setupLayeredProtection(r *gin.Engine) {
    // Layer 1: Global server protection
    r.Use(middleware.BasicRateLimitMiddleware(10000, 1000))
    
    // Layer 2: Per-IP fairness
    r.Use(middleware.IPRateLimitMiddleware(100, 20))
    
    // Layer 3: Per-user business rules
    api := r.Group("/api")
    api.Use(middleware.UserRateLimitMiddleware(50, 10))
}
```

### Service-Specific Limiting
```go
func setupServiceSpecific(r *gin.Engine) {
    // Heavy operations - wait for capacity
    heavy := r.Group("/heavy")
    heavy.Use(middleware.WaitingTokenBucketRateLimitMiddleware(1, 1, 5*time.Second))
    
    // Real-time operations - precise timing
    realtime := r.Group("/realtime")
    realtime.Use(middleware.SlidingWindowRateLimitMiddleware(1000, time.Minute))
    
    // User operations - per-user fairness
    user := r.Group("/user")
    user.Use(middleware.UserRateLimitMiddleware(100, 20))
}
```

## ⚙️ Advanced Configuration

### Custom IP Rate Limiter
```go
config := &middleware.IPRateLimiterConfig{
    Rate:            rate.Limit(100),
    Burst:           20,
    MaxIPs:          10000,
    CleanupInterval: 5 * time.Minute,
    IPTTL:           1 * time.Hour,
    EnableHeaders:   true,
    EnableLogging:   true,
    TrustedProxies:  []string{"10.0.0.0/8", "172.16.0.0/12"},
    WhitelistIPs:    []string{"127.0.0.1"},
    BlacklistIPs:    []string{"192.168.1.100"},
    OnLimitExceeded: func(c *gin.Context, info *middleware.IPRequestInfo) {
        log.Printf("Rate limit exceeded for IP: %s", info.IP)
        c.JSON(429, gin.H{
            "error": "Too many requests",
            "ip":    info.IP,
        })
        c.Abort()
    },
}

limiter := middleware.NewIPRateLimiter(config)
r.Use(limiter.Middleware())
```

### Advanced Tier-Based Limiting
```go
config := &middleware.AdvancedRateLimiterConfig{
    Rate:  rate.Limit(100),
    Burst: 20,
    CustomKeyFunc: func(c *gin.Context) string {
        userID := c.GetHeader("X-User-ID")
        tier := c.GetHeader("X-User-Tier")
        return fmt.Sprintf("user:%s:tier:%s", userID, tier)
    },
    OnLimitExceeded: func(c *gin.Context, info *middleware.AdvancedRequestInfo) {
        c.JSON(429, gin.H{
            "error": "Upgrade your plan for higher limits",
            "upgrade_url": "https://example.com/upgrade",
        })
        c.Abort()
    },
}
```

## 📊 Monitoring & Statistics

### Registry System
```go
// Register multiple rate limiters
middleware.GlobalRegistry.Register("global", globalLimiter)
middleware.GlobalRegistry.Register("per-ip", ipLimiter)

// Get statistics for all
allStats := middleware.GlobalRegistry.GetAllStats()

// Get summary
summary := middleware.GlobalRegistry.GetSummaryStats()

// Stop all gracefully
defer middleware.GlobalRegistry.Stop()
```

### Statistics API
```go
r.GET("/admin/stats", func(c *gin.Context) {
    c.JSON(200, middleware.GlobalRegistry.GetSummaryStats())
})

r.GET("/admin/stats/:name", func(c *gin.Context) {
    name := c.Param("name")
    limiter, exists := middleware.GlobalRegistry.Get(name)
    if !exists {
        c.JSON(404, gin.H{"error": "Not found"})
        return
    }
    c.JSON(200, limiter.GetStats())
})
```

### Individual Rate Limiter Stats
```go
stats := limiter.GetStats()
fmt.Printf("Success Rate: %.2f%%\n", stats.GetSuccessRate()*100)
fmt.Printf("Total Requests: %d\n", stats.GetTotalRequests())
fmt.Printf("Uptime: %s\n", stats.GetUptime())

// For client-aware limiters
if clientLimiter, ok := limiter.(middleware.ClientAwareRateLimiter); ok {
    clients := clientLimiter.ListActiveClients()
    fmt.Printf("Active Clients: %d\n", len(clients))
}
```

## 🧪 Testing

```bash
# Run tests
make test

# Run tests with race detection
make test-race

# Run tests with coverage
make test-cover

# Generate HTML coverage report
make test-cover-html

# Run benchmarks
make benchmark
```

## 📈 Performance

### Benchmark Results
```
BenchmarkBasicRateLimiter-8     	 1000000	      1200 ns/op	     128 B/op	       2 allocs/op
BenchmarkIPRateLimiter-8        	  800000	      1500 ns/op	     256 B/op	       3 allocs/op
BenchmarkUserRateLimiter-8      	  700000	      1700 ns/op	     312 B/op	       4 allocs/op
BenchmarkAdvancedRateLimiter-8  	  600000	      2000 ns/op	     384 B/op	       5 allocs/op
BenchmarkSlidingWindow-8        	  400000	      3500 ns/op	     512 B/op	       8 allocs/op
BenchmarkTokenBucket-8          	  900000	      1300 ns/op	     192 B/op	       3 allocs/op
```

### Memory Usage
| Rate Limiter | Memory per Client | Max Clients | Total Memory |
|--------------|------------------|-------------|--------------|
| Basic        | N/A (global)     | N/A         | ~200 bytes   |
| IP-based     | ~300 bytes       | 10,000      | ~3 MB        |
| User-based   | ~350 bytes       | 50,000      | ~17 MB       |
| Advanced     | ~400 bytes       | 100,000     | ~40 MB       |

## 🛡️ Production Deployment

### Docker Support
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o rate-limiter-app ./examples/production

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/rate-limiter-app .
CMD ["./rate-limiter-app"]
```

### Environment Configuration
```bash
# Rate limiting configuration
GLOBAL_RATE_LIMIT=10000
IP_RATE_LIMIT=100
USER_RATE_LIMIT=50

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090

# Security
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
ADMIN_API_KEY=your-secure-admin-key
```

### Health Checks
```go
r.GET("/health", func(c *gin.Context) {
    stats := middleware.GlobalRegistry.GetAllStats()
    healthy := true
    
    for _, stat := range stats {
        if stat.GetSuccessRate() < 0.8 {
            healthy = false
            break
        }
    }
    
    status := 200
    if !healthy {
        status = 503
    }
    
    c.JSON(status, gin.H{"healthy": healthy})
})
```

## 📚 Examples

Comprehensive examples are available in the `examples/` directory:

- **[Basic Examples](examples/basic/)**: Simple usage of all rate limiter types
- **[Production Setup](examples/production/)**: Production-ready configuration with monitoring
- **[Comparison](examples/comparison/)**: Performance comparison between different algorithms

```bash
# Run basic examples
make examples-basic

# Run production example
make examples-production

# Run all examples
make examples
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone repository
git clone https://github.com/miraj90van/rate-limiter-sdk.git
cd rate-limiter-sdk

# Install development tools
make dev-setup

# Run tests
make test

# Run linting
make lint

# Run all checks
make check
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) for the token bucket algorithm
- [Gin Web Framework](https://github.com/gin-gonic/gin) for the excellent HTTP framework
- All contributors who have helped improve this SDK

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/yourusername/rate-limiter-sdk/issues)
- 💬 [Discussions](https://github.com/yourusername/rate-limiter-sdk/discussions)
- 📧 Email: support@example.com

---

**Made with ❤️ by the Rate Limiter SDK Team**