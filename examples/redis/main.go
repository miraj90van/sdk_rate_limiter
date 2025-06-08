package main

import (
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

	setupRateLimiter(r)

	setupMonitoring(r)

	// Start server
	log.Println("Starting server on :8888")
	if err := r.Run(":8888"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func setupRateLimiter(r *gin.Engine) {

	// Initialize Redis client:
	redisClient, err := component.NewRedisClient("localhost:63792", "", 0)
	if err != nil {
		log.Printf("Redis connection failed: %v", err)
		log.Println("Falling back to in-memory rate limiting...")

		// Fallback to in-memory if Redis is not available:
		middleware.InitializeRateLimitProcessorWithoutRedis()
	} else {
		log.Println("Redis connection successful!")

		// Initialize factory with Redis:
		middleware.InitializeRateLimitProcessor(redisClient.GetRedisClient())
	}

	// Create a route group for Redis-backed rate limiting:
	redisGroup := r.Group("/api")

	basicLimiter := middleware.RateLimitProcessor.CreateTokenBucketRateLimiter(5, 2)
	middleware.RateLimitRegistry.Register("basic", basicLimiter)
	//redisGroup.Use(basicLimiter.Middleware())

	tokenBucketLimiter := middleware.RateLimitProcessor.CreateTokenBucketRateLimiter(5, 2)
	middleware.RateLimitRegistry.Register("token_bucket", tokenBucketLimiter)
	//redisGroup.Use(tokenBucketLimiter.Middleware())

	slidingWindowLimiter := middleware.RateLimitProcessor.CreateSlidingWindowsRateLimiter(10, 2)
	middleware.RateLimitRegistry.Register("sliding_window", slidingWindowLimiter)
	//redisGroup.Use(slidingWindowLimiter.Middleware())

	fixedWindowLimiter := middleware.RateLimitProcessor.CreateFixedWindowRateLimiter(10, 2)
	middleware.RateLimitRegistry.Register("fixed_window", fixedWindowLimiter)
	//redisGroup.Use(fixedWindowLimiter.Middleware())

	leakyBucketLimiter := middleware.RateLimitProcessor.CreateLeakyBucketRateLimiter(10, 2)
	middleware.RateLimitRegistry.Register("leaky_bucket", leakyBucketLimiter)
	redisGroup.Use(leakyBucketLimiter.Middleware())

	redisGroup.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from Redis-backed rate limiter!",
			"time":    time.Now(),
		})
	})
}

func setupMonitoring(r *gin.Engine) {
	// Stats endpoint:
	r.GET("/stats", func(c *gin.Context) {
		stats := middleware.RateLimitRegistry.GetAllStats()
		c.JSON(http.StatusOK, gin.H{
			"rate_limiters": stats,
			"summary":       middleware.RateLimitRegistry.GetSummaryStats(),
		})
	})

	// Health check endpoint:
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
		})
	})

	// Rate limiter registry endpoint:
	r.GET("/rate-limiters", func(c *gin.Context) {
		limiters := middleware.RateLimitRegistry.List()
		c.JSON(http.StatusOK, gin.H{
			"active_limiters": limiters,
			"count":           len(limiters),
		})
	})
}
