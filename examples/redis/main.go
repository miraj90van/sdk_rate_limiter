package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/miraj90van/sdk_rate_limiter/component"
	"github.com/miraj90van/sdk_rate_limiter/middleware"
	"log"
	"net/http"
	"time"
)

func main() {
	// Initialize Gin router
	r := gin.Default()

	// Example 1: Using rate limiter WITHOUT Redis (in-memory only)
	log.Println("Setting up rate limiter without Redis...")
	setupWithoutRedis(r)

	// Example 2: Using rate limiter WITH Redis (distributed)
	log.Println("Setting up rate limiter with Redis...")
	setupWithRedis(r)

	setupMonitoring(r)

	// Start server
	log.Println("Starting server on :8888")
	if err := r.Run(":8888"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// setupWithoutRedis demonstrates rate limiting without Redis
func setupWithoutRedis(r *gin.Engine) {
	// Initialize factory without Redis
	middleware.InitializeGlobalFactoryWithoutRedis()

	// Create a route group for in-memory rate limiting
	memoryGroup := r.Group("/memory")

	// Apply global rate limiting (100 req/sec globally)
	memoryGroup.Use(middleware.GlobalFactory.GlobalMiddleware(10, 2))

	// Apply per-IP rate limiting (10 req/sec per IP)
	memoryGroup.Use(middleware.GlobalFactory.IPMiddleware(10, 2))

	memoryGroup.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from in-memory rate limiter!",
			"time":    time.Now(),
		})
	})

	// Example using builder pattern
	limiterBuilder := middleware.GlobalFactory.NewBuilder().
		Rate(50).           // 50 req/sec
		Burst(5).           // 5 burst
		WithIPKey().        // Per-IP limiting
		EnableLogging().    // Enable logging
		Window(time.Minute) // 1-minute window

	memoryGroup.GET("/builder", limiterBuilder.BuildMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from builder pattern!",
			"backend": "memory",
		})
	})
}

func setupWithRedis(r *gin.Engine) {

	// Initialize Redis client:
	redisClient, err := component.NewRedisClient("localhost:6379", "", 0)
	if err != nil {
		log.Printf("Redis connection failed: %v", err)
		log.Println("Falling back to in-memory rate limiting...")

		// Fallback to in-memory if Redis is not available:
		middleware.InitializeGlobalFactoryWithoutRedis()
	} else {
		log.Println("Redis connection successful!")

		// Configure Redis settings
		redisConfig := &component.RedisConfig{
			Enabled:          true,
			KeyPrefix:        "myapp_rate_limiter",
			MaxRetries:       3,
			RetryDelay:       100 * time.Millisecond,
			HealthCheckDelay: 30 * time.Second,
			FallbackToMemory: true,
		}

		// Initialize factory with Redis
		middleware.InitializeGlobalFactory(redisClient, redisConfig)
	}

	// Create a route group for Redis-backed rate limiting
	redisGroup := r.Group("/redis")

	// Apply global rate limiting (distributed across all instances)
	//globalLimiter := middleware.GlobalFactory.GlobalMiddleware(10, 2)
	globalLimiter := middleware.GlobalFactory.CreateGlobalRateLimiter(10, 2)
	middleware.GlobalRegistry.Register("redis_global", globalLimiter)
	//redisGroup.Use(globalLimiter.Middleware())

	tokenBucketLimiter := middleware.GlobalFactory.CreateTokenBucketRateLimiter(5, 2)
	middleware.GlobalRegistry.Register("token_bucket", tokenBucketLimiter)
	//redisGroup.Use(tokenBucketLimiter.Middleware())

	slidingWindowLimiter := middleware.GlobalFactory.CreateSlidingWindowsRateLimiter(10, 2)
	middleware.GlobalRegistry.Register("sliding_window", slidingWindowLimiter)
	//redisGroup.Use(slidingWindowLimiter.Middleware())

	fixedWindowLimiter := middleware.GlobalFactory.CreateFixedWindowRateLimiter(10, 2)
	middleware.GlobalRegistry.Register("fixed_window", fixedWindowLimiter)
	redisGroup.Use(fixedWindowLimiter.Middleware())

	leakyBucketLimiter := middleware.GlobalFactory.CreateLeakyBucketRateLimiter(10, 2)
	middleware.GlobalRegistry.Register("leaky_bucket", leakyBucketLimiter)
	//redisGroup.Use(leakyBucketLimiter.Middleware())

	redisGroup.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from Redis-backed rate limiter!",
			"time":    time.Now(),
		})
	})

	// Per-user rate limiting
	redisGroup.GET("/user", middleware.GlobalFactory.UserMiddleware(15, 3), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello authenticated user!",
			"user_id": c.GetHeader("X-User-ID"),
		})
	})

	// Per-API-key rate limiting
	redisGroup.GET("/api", middleware.GlobalFactory.APIKeyMiddleware(100, 10), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello API client!",
			"api_key": c.GetHeader("X-API-Key"),
		})
	})

	// Custom rate limiting with composite key
	customExtractor := middleware.CreateCompositeKeyExtractor(
		middleware.UserIDKeyExtractor,
		middleware.APIKeyExtractor,
	)

	customLimiter := middleware.GlobalFactory.CreateCustomRateLimiter(
		30,              // 30 req/sec
		5,               // 5 burst
		customExtractor, // Custom key extraction
		"user_api",      // Scope
	)

	redisGroup.GET("/custom", customLimiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from custom rate limiter!",
			"scope":   "user_api",
		})
	})

	// Layered rate limiting example
	//layeredConfig := &middleware.LayeredRateLimitConfig{}
	//layeredConfig.Global.Enabled = true
	//layeredConfig.Global.RequestsPerSecond = 1000
	//layeredConfig.Global.Burst = 100
	//
	//layeredConfig.PerIP.Enabled = true
	//layeredConfig.PerIP.RequestsPerSecond = 50
	//layeredConfig.PerIP.Burst = 10
	//
	//layeredConfig.PerUser.Enabled = true
	//layeredConfig.PerUser.RequestsPerSecond = 25
	//layeredConfig.PerUser.Burst = 5

	//layeredMiddlewares := middleware.GlobalFactory.CreateLayeredMiddleware(layeredConfig)

	// Apply all layers
	//layeredGroup := redisGroup.Group("/layered")
	//for _, mw := range layeredMiddlewares {
	//	layeredGroup.Use(mw)
	//}
	//
	//layeredGroup.GET("/test", func(c *gin.Context) {
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": "Hello from layered rate limiting!",
	//		"layers":  []string{"global", "per-ip", "per-user"},
	//	})
	//})
}

// =============================================================================
// MONITORING AND STATS ENDPOINTS
// =============================================================================

func setupMonitoring(r *gin.Engine) {
	// Stats endpoint
	r.GET("/stats", func(c *gin.Context) {
		stats := middleware.GlobalRegistry.GetAllStats()
		c.JSON(http.StatusOK, gin.H{
			"rate_limiters": stats,
			"summary":       middleware.GlobalRegistry.GetSummaryStats(),
		})
	})

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
		})
	})

	// Rate limiter registry endpoint
	r.GET("/rate-limiters", func(c *gin.Context) {
		limiters := middleware.GlobalRegistry.List()
		c.JSON(http.StatusOK, gin.H{
			"active_limiters": limiters,
			"count":           len(limiters),
		})
	})
}

// =============================================================================
// CONVENIENCE FUNCTIONS FOR QUICK SETUP
// =============================================================================

// QuickSetupGlobal sets up global rate limiting with sensible defaults
func QuickSetupGlobal(r *gin.Engine, requestsPerSecond float64) {
	r.Use(middleware.BasicRateLimitMiddleware(requestsPerSecond, int(requestsPerSecond*0.1)))
}

// QuickSetupWithRedis sets up distributed rate limiting with Redis
func QuickSetupWithRedis(r *gin.Engine, requestsPerSecond float64, redisAddr string) error {
	redisClient, err := component.NewRedisClient(redisAddr, "", 0)
	if err != nil {
		return fmt.Errorf("failed to setup Redis: %w", err)
	}

	r.Use(middleware.DistributedGlobalRateLimitMiddleware(requestsPerSecond, int(requestsPerSecond*0.1), redisClient))
	return nil
}

// =============================================================================
// ADVANCED CONFIGURATION EXAMPLE
// =============================================================================

func setupAdvancedConfiguration() {
	// Create Redis client
	redisClient, err := component.NewRedisClient("localhost:6379", "", 0)
	if err != nil {
		log.Printf("Redis unavailable: %v", err)
		return
	}

	// Advanced Redis configuration
	redisConfig := &component.RedisConfig{
		Enabled:          true,
		KeyPrefix:        "advanced_limiter",
		MaxRetries:       5,
		RetryDelay:       200 * time.Millisecond,
		HealthCheckDelay: 10 * time.Second,
		FallbackToMemory: true,
	}

	factory := middleware.NewRateLimiterFactory(redisClient, redisConfig)

	// Use factory to create a global rate limiter
	limiter := factory.CreateGlobalRateLimiter(500, 50)

	// Register the limiter
	middleware.GlobalRegistry.Register("factory_global", limiter)

	log.Println("Solution 2: Factory method - Rate limiter configured successfully")
}
