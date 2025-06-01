// middleware/doc.go
// Package documentation for the rate limiting middleware

/*
Package middleware provides comprehensive rate limiting algorithms for Gin web framework.

This package includes multiple rate limiting strategies designed for different use cases:

# Rate Limiter Types

## Basic Rate Limiter
Global rate limiting where all clients share the same rate limit.
Use case: Server protection, DDoS prevention, emergency limiting.

	r.Use(middleware.BasicRateLimitMiddleware(1000, 100)) // 1000 req/sec globally

## IP Rate Limiter
Per-IP rate limiting where each IP address gets its own rate limit.
Use case: Fair limiting per IP, prevent single IP from hogging resources.

	r.Use(middleware.IPRateLimitMiddleware(100, 20)) // 100 req/sec per IP

## User Rate Limiter
Per-user rate limiting where each authenticated user gets their own rate limit.
Use case: SaaS applications, user-facing APIs, subscription tiers.

	r.Use(middleware.UserRateLimitMiddleware(50, 10)) // 50 req/sec per user

## Advanced Rate Limiter
Flexible rate limiting with custom key extraction for complex scenarios.
Use case: Multi-tenant apps, composite keys, custom business logic.

	r.Use(middleware.TierBasedRateLimitMiddleware(100, 20)) // Tier-based limiting

## Sliding Window Rate Limiter
Precise time-window based limiting using sliding window algorithm.
Use case: When precision matters more than performance, exact quotas.

	r.Use(middleware.SlidingWindowRateLimitMiddleware(100, time.Minute)) // Exactly 100/min

## Token Bucket Rate Limiter
Graceful rate limiting with wait capability instead of immediate rejection.
Use case: When you want to queue requests instead of dropping them.

	r.Use(middleware.WaitingTokenBucketRateLimitMiddleware(10, 5, 2*time.Second)) // Wait up to 2s

# Architecture

All rate limiters implement common interfaces defined in middleware.go:

	type RateLimiter interface {
		Middleware() gin.HandlerFunc
		GetStats() Stats
		ResetStats()
		Stop()
		Type() RateLimiterType
		Algorithm() Algorithm
	}

# Registry System

The package provides a global registry for managing multiple rate limiters:

	// Register multiple rate limiters
	middleware.GlobalRegistry.Register("global", basicLimiter)
	middleware.GlobalRegistry.Register("per-ip", ipLimiter)

	// Get statistics for all
	allStats := middleware.GlobalRegistry.GetAllStats()

	// Stop all gracefully
	defer middleware.GlobalRegistry.Stop()

# Layered Protection

You can combine multiple rate limiters for layered protection:

	func setupLayeredProtection(r *gin.Engine) {
		// Layer 1: Global server protection
		r.Use(middleware.BasicRateLimitMiddleware(10000, 1000))

		// Layer 2: Per-IP fairness
		r.Use(middleware.IPRateLimitMiddleware(100, 20))

		// Layer 3: Per-user business rules
		api := r.Group("/api")
		api.Use(middleware.UserRateLimitMiddleware(50, 10))
	}

# Configuration

All rate limiters support extensive configuration options:

	config := &middleware.IPRateLimiterConfig{
		Rate:            rate.Limit(100),
		Burst:           20,
		MaxIPs:          10000,
		CleanupInterval: 5 * time.Minute,
		EnableHeaders:   true,
		EnableLogging:   true,
		TrustedProxies:  []string{"10.0.0.0/8"},
		WhitelistIPs:    []string{"127.0.0.1"},
		OnLimitExceeded: customHandler,
	}

	limiter := middleware.NewIPRateLimiter(config)
	r.Use(limiter.Middleware())

# Monitoring

Built-in statistics and monitoring capabilities:

	stats := limiter.GetStats()
	fmt.Printf("Success Rate: %.2f%%\n", stats.GetSuccessRate()*100)
	fmt.Printf("Total Requests: %d\n", stats.GetTotalRequests())

	// For client-aware limiters
	if clientLimiter, ok := limiter.(middleware.ClientAwareRateLimiter); ok {
		clients := clientLimiter.ListActiveClients()
		fmt.Printf("Active Clients: %d\n", len(clients))
	}

# Production Setup

Example production configuration with monitoring:

	func setupProduction(r *gin.Engine) {
		// Create and register rate limiters
		globalLimiter := middleware.NewBasicRateLimiter(&middleware.BasicRateLimiterConfig{
			Rate: rate.Limit(10000), Burst: 1000, EnableHeaders: true,
		})
		middleware.GlobalRegistry.Register("global", globalLimiter)

		ipLimiter := middleware.NewIPRateLimiter(&middleware.IPRateLimiterConfig{
			Rate: rate.Limit(100), Burst: 20, EnableHeaders: true,
			MaxIPs: 50000, TrustedProxies: []string{"10.0.0.0/8"},
		})
		middleware.GlobalRegistry.Register("per-ip", ipLimiter)

		// Apply middleware
		r.Use(globalLimiter.Middleware())
		r.Use(ipLimiter.Middleware())

		// Monitoring endpoint
		r.GET("/admin/rate-limit-stats", func(c *gin.Context) {
			c.JSON(200, middleware.GlobalRegistry.GetSummaryStats())
		})

		// Graceful shutdown
		defer middleware.GlobalRegistry.Stop()
	}

# Error Handling

The package provides comprehensive error handling:

	// Check for specific errors
	if err := config.Validate(); err != nil {
		if errors.Is(err, middleware.ErrInvalidRate) {
			log.Fatal("Invalid rate configuration")
		}
	}

	// Custom error responses
	config.OnLimitExceeded = func(c *gin.Context, info *middleware.IPRequestInfo) {
		c.JSON(429, gin.H{
			"error": "Rate limit exceeded",
			"ip":    info.IP,
			"retry_after": 60,
		})
		c.Abort()
	}

# Thread Safety

All rate limiters are designed to be thread-safe and can handle concurrent requests safely.
Memory management includes automatic cleanup of inactive clients to prevent memory leaks.

For more examples and advanced usage, see the examples/ directory.
*/
package middleware
