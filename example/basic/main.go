// examples/basic/main.go
// Basic usage examples for all rate limiter types

package main

import (
	"fmt"
	"log"
	"net/http"
	"sdk_rate_limiter/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Set Gin to release mode for cleaner output
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router
	r := gin.Default()

	// Setup all basic examples
	setupBasicExamples(r)

	// Add a health check endpoint (no rate limiting)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// Add monitoring endpoint
	r.GET("/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, middleware.GlobalRegistry.GetSummaryStats())
	})

	// Print usage information
	printUsageInfo()

	// Start server
	log.Println("🚀 Basic examples server starting on :8080")
	log.Println("📊 View stats at: http://localhost:8080/stats")
	log.Println("❤️  Health check at: http://localhost:8080/health")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func setupBasicExamples(r *gin.Engine) {
	// Example 1: Global rate limiting (all clients share the same limit)
	globalGroup := r.Group("/global")
	globalLimiter := middleware.NewBasicRateLimiter(&middleware.BasicRateLimiterConfig{
		Rate:          1000, // 1000 requests per second globally
		Burst:         100,  // 100 burst globally
		EnableHeaders: true,
		EnableLogging: false,
	})
	middleware.GlobalRegistry.Register("global", globalLimiter)
	globalGroup.Use(globalLimiter.Middleware())
	{
		globalGroup.GET("/ping", pingHandler)
		globalGroup.GET("/data", dataHandler)
	}

	// Example 2: Per-IP rate limiting (each IP gets its own limit)
	ipGroup := r.Group("/per-ip")
	ipLimiter := middleware.NewIPRateLimiter(&middleware.IPRateLimiterConfig{
		Rate:          100, // 100 requests per second per IP
		Burst:         20,  // 20 burst per IP
		EnableHeaders: true,
		EnableLogging: false,
		MaxIPs:        1000, // Track up to 1000 IPs
	})
	middleware.GlobalRegistry.Register("per-ip", ipLimiter)
	ipGroup.Use(ipLimiter.Middleware())
	{
		ipGroup.GET("/ping", pingHandler)
		ipGroup.GET("/data", dataHandler)
		ipGroup.POST("/submit", submitHandler)
	}

	// Example 3: Per-user rate limiting (each user gets their own limit)
	userGroup := r.Group("/per-user")
	userLimiter := middleware.NewUserRateLimiter(&middleware.UserRateLimiterConfig{
		Rate:          50, // 50 requests per second per user
		Burst:         10, // 10 burst per user
		EnableHeaders: true,
		EnableLogging: false,
		FallbackToIP:  true, // Fallback to IP if no user ID
	})
	middleware.GlobalRegistry.Register("per-user", userLimiter)
	userGroup.Use(userLimiter.Middleware())
	{
		userGroup.GET("/profile", profileHandler)
		userGroup.POST("/update", updateHandler)
	}

	// Example 4: Token bucket with waiting
	tokenGroup := r.Group("/token-bucket")
	tokenLimiter := middleware.NewTokenBucketLimiter(&middleware.TokenBucketConfig{
		Rate:          10,              // 10 tokens per second
		Burst:         5,               // 5 token capacity
		WaitTimeout:   2 * time.Second, // Wait up to 2 seconds for tokens
		EnableHeaders: true,
		EnableLogging: false,
	})
	middleware.GlobalRegistry.Register("token-bucket", tokenLimiter)
	tokenGroup.Use(tokenLimiter.Middleware())
	{
		tokenGroup.GET("/slow", slowHandler)
		tokenGroup.POST("/process", processHandler)
	}

	// Example 5: Sliding window (precise timing)
	slidingGroup := r.Group("/sliding-window")
	slidingLimiter := middleware.NewSlidingWindowLimiter(&middleware.SlidingWindowConfig{
		Limit:         60,          // 60 requests
		Window:        time.Minute, // per minute (exactly)
		EnableHeaders: true,
		EnableLogging: false,
	})
	middleware.GlobalRegistry.Register("sliding-window", slidingLimiter)
	slidingGroup.Use(slidingLimiter.Middleware())
	{
		slidingGroup.GET("/precise", preciseHandler)
		slidingGroup.GET("/quota", quotaHandler)
	}

	// Example 6: Advanced with custom key extraction
	advancedGroup := r.Group("/advanced")
	advancedLimiter := middleware.NewAdvancedRateLimiter(&middleware.AdvancedRateLimiterConfig{
		Rate:          25, // 25 requests per second per client
		Burst:         5,  // 5 burst per client
		EnableHeaders: true,
		EnableLogging: false,
		CustomKeyFunc: func(c *gin.Context) string {
			// Custom key based on user tier
			userID := c.GetHeader("X-User-ID")
			tier := c.GetHeader("X-User-Tier")
			if userID == "" {
				return "anonymous:" + c.ClientIP()
			}
			if tier == "" {
				tier = "free"
			}
			return fmt.Sprintf("user:%s:tier:%s", userID, tier)
		},
		KeyDescription: "user-tier",
	})
	middleware.GlobalRegistry.Register("advanced", advancedLimiter)
	advancedGroup.Use(advancedLimiter.Middleware())
	{
		advancedGroup.GET("/tier-based", tierHandler)
		advancedGroup.POST("/premium", premiumHandler)
	}
}

// Handler functions
func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "pong",
		"timestamp": time.Now().Format(time.RFC3339),
		"path":      c.Request.URL.Path,
	})
}

func dataHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":      "Sample data response",
		"timestamp": time.Now().Format(time.RFC3339),
		"client_ip": c.ClientIP(),
	})
}

func submitHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Data submitted successfully",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func profileHandler(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   userID,
		"profile":   "User profile data",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func updateHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Profile updated",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func slowHandler(c *gin.Context) {
	// Simulate slow operation
	time.Sleep(100 * time.Millisecond)

	c.JSON(http.StatusOK, gin.H{
		"message":   "Slow operation completed",
		"timestamp": time.Now().Format(time.RFC3339),
		"note":      "This endpoint waits for tokens instead of immediate rejection",
	})
}

func processHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Request processed",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func preciseHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Precise timing enforced",
		"timestamp": time.Now().Format(time.RFC3339),
		"note":      "Exactly 60 requests per minute allowed",
	})
}

func quotaHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Quota-based endpoint",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func tierHandler(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	tier := c.GetHeader("X-User-Tier")

	if userID == "" {
		userID = "anonymous"
	}
	if tier == "" {
		tier = "free"
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   userID,
		"tier":      tier,
		"message":   "Tier-based rate limiting active",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func premiumHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Premium feature accessed",
		"timestamp": time.Now().Format(time.RFC3339),
		"note":      "Rate limit varies by user tier",
	})
}

func printUsageInfo() {
	fmt.Println("\n" + "="*60)
	fmt.Println("🚀 RATE LIMITER SDK - BASIC EXAMPLES")
	fmt.Println("=", *60)
	fmt.Println()

	fmt.Println("📋 Available endpoints:")
	fmt.Println()

	fmt.Println("1️⃣  GLOBAL RATE LIMITING (1000 req/sec shared by all clients)")
	fmt.Println("   GET  /global/ping")
	fmt.Println("   GET  /global/data")
	fmt.Println()

	fmt.Println("2️⃣  PER-IP RATE LIMITING (100 req/sec per IP)")
	fmt.Println("   GET  /per-ip/ping")
	fmt.Println("   GET  /per-ip/data")
	fmt.Println("   POST /per-ip/submit")
	fmt.Println()

	fmt.Println("3️⃣  PER-USER RATE LIMITING (50 req/sec per user)")
	fmt.Println("   Headers: X-User-ID: <user_id>")
	fmt.Println("   GET  /per-user/profile")
	fmt.Println("   POST /per-user/update")
	fmt.Println()

	fmt.Println("4️⃣  TOKEN BUCKET WITH WAITING (10 req/sec, waits up to 2s)")
	fmt.Println("   GET  /token-bucket/slow")
	fmt.Println("   POST /token-bucket/process")
	fmt.Println()

	fmt.Println("5️⃣  SLIDING WINDOW (exactly 60 req/min)")
	fmt.Println("   GET  /sliding-window/precise")
	fmt.Println("   GET  /sliding-window/quota")
	fmt.Println()

	fmt.Println("6️⃣  ADVANCED TIER-BASED (25 req/sec per user-tier combination)")
	fmt.Println("   Headers: X-User-ID: <user_id>, X-User-Tier: <tier>")
	fmt.Println("   GET  /advanced/tier-based")
	fmt.Println("   POST /advanced/premium")
	fmt.Println()

	fmt.Println("📊 MONITORING:")
	fmt.Println("   GET  /stats  - View all rate limiter statistics")
	fmt.Println("   GET  /health - Health check (no rate limiting)")
	fmt.Println()

	fmt.Println("🧪 TESTING EXAMPLES:")
	fmt.Println()
	fmt.Println("# Test global limiting")
	fmt.Println("curl http://localhost:8080/global/ping")
	fmt.Println()
	fmt.Println("# Test per-user limiting")
	fmt.Println("curl -H \"X-User-ID: user123\" http://localhost:8080/per-user/profile")
	fmt.Println()
	fmt.Println("# Test tier-based limiting")
	fmt.Println("curl -H \"X-User-ID: user123\" -H \"X-User-Tier: premium\" http://localhost:8080/advanced/tier-based")
	fmt.Println()
	fmt.Println("# View statistics")
	fmt.Println("curl http://localhost:8080/stats")
	fmt.Println()
	fmt.Println("=" * 60)
}
