package example

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
	"sdk_rate_limiter/middleware"
	"time"
)

func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"time":    time.Now().Format(time.RFC3339),
	})
}

func userHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "User data",
		"user_id": c.Param("id"),
		"time":    time.Now().Format(time.RFC3339),
	})
}

func main() {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router
	r := gin.Default()

	// Initialize rate limiters
	ipLimiter := middleware.NewIPRateLimiter(rate.Every(time.Second), 5)        // 5 req/sec per IP
	slidingLimiter := middleware.NewSlidingWindowLimiter(10, time.Minute)       // 10 req/min sliding window
	userLimiter := middleware.NewUserRateLimiter(rate.Every(2*time.Second), 10) // 0.5 req/sec per user

	// Routes dengan berbagai rate limiting

	// 1. Global rate limit - 10 req/sec untuk semua request
	v1 := r.Group("/api/v1")
	v1.Use(middleware.RateLimitMiddleware(10, 20))
	{
		v1.GET("/ping", pingHandler)
	}

	// 2. Per-IP rate limit
	v2 := r.Group("/api/v2")
	v2.Use(ipLimiter.Middleware())
	{
		v2.GET("/ping", pingHandler)
		v2.GET("/users/:id", userHandler)
	}

	// 3. Sliding window rate limit
	v3 := r.Group("/api/v3")
	v3.Use(slidingLimiter.Middleware())
	{
		v3.GET("/ping", pingHandler)
	}

	// 4. Advanced rate limit dengan headers
	v4 := r.Group("/api/v4")
	v4.Use(middleware.AdvancedRateLimitMiddleware(rate.Every(time.Second), 5))
	{
		v4.GET("/ping", pingHandler)
	}

	// 5. User-based rate limit
	v5 := r.Group("/api/v5")
	v5.Use(userLimiter.Middleware())
	{
		v5.GET("/ping", pingHandler)
		v5.GET("/users/:id", userHandler)
	}

	// 6. Kombinasi multiple rate limiters
	protected := r.Group("/api/protected")
	protected.Use(middleware.RateLimitMiddleware(100, 200)) // Global limit
	protected.Use(ipLimiter.Middleware())                   // Per-IP limit
	{
		protected.GET("/sensitive", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "This is a protected endpoint",
				"time":    time.Now().Format(time.RFC3339),
			})
		})
	}

	// Health check endpoint tanpa rate limit
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})
}
