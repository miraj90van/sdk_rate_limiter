// examples/production/main.go
// Production-ready rate limiting setup with monitoring, alerting, and layered protection

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sdk_rate_limiter/middleware"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Production mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	r := gin.New()

	// Add recovery middleware
	r.Use(gin.Recovery())

	// Add custom logging
	r.Use(customLoggingMiddleware())

	// Setup production rate limiting
	setupProductionRateLimiting(r)

	// Setup API routes
	setupAPIRoutes(r)

	// Setup monitoring endpoints
	setupMonitoringEndpoints(r)

	// Setup graceful shutdown
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Println("🚀 Production server starting on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Print production info
	printProductionInfo()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop all rate limiters
	middleware.GlobalRegistry.Stop()

	// Shutdown server
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("✅ Server stopped")
}

func setupProductionRateLimiting(r *gin.Engine) {
	// Layer 1: Global server protection (emergency brake)
	globalLimiter := middleware.NewBasicRateLimiter(&middleware.BasicRateLimiterConfig{
		Rate:          10000, // 10k req/sec globally
		Burst:         1000,  // 1k burst globally
		EnableHeaders: true,
		EnableLogging: true,
		ErrorMessage:  "Server overload protection activated",
		OnLimitExceeded: func(c *gin.Context, info *middleware.BasicRequestInfo) {
			// Alert on global limit exceeded
			log.Printf("🚨 ALERT: Global rate limit exceeded from %s", info.IP)

			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Server temporarily overloaded",
				"message": "Please try again in a few seconds",
				"scope":   "global",
				"level":   "emergency",
			})
			c.Abort()
		},
	})
	middleware.GlobalRegistry.Register("global-protection", globalLimiter)
	r.Use(globalLimiter.Middleware())

	// Layer 2: DDoS protection per IP
	ddosLimiter := middleware.NewIPRateLimiter(&middleware.IPRateLimiterConfig{
		Rate:            1000,  // 1k req/sec per IP
		Burst:           100,   // 100 burst per IP
		MaxIPs:          50000, // Track up to 50k IPs
		CleanupInterval: 5 * time.Minute,
		IPTTL:           1 * time.Hour,
		EnableHeaders:   true,
		EnableLogging:   true,
		TrustedProxies:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		WhitelistIPs:    []string{"127.0.0.1"}, // Localhost
		ErrorMessage:    "IP rate limit exceeded",
		OnLimitExceeded: func(c *gin.Context, info *middleware.IPRequestInfo) {
			// Log suspicious activity
			if !info.IsWhitelisted {
				log.Printf("🔒 Rate limit exceeded for IP: %s, Path: %s", info.IP, info.Path)
			}

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "IP rate limit exceeded",
				"ip":      info.IP,
				"message": "Too many requests from your IP address",
				"scope":   "per-ip",
			})
			c.Abort()
		},
	})
	middleware.GlobalRegistry.Register("ddos-protection", ddosLimiter)
	r.Use(ddosLimiter.Middleware())
}

func setupAPIRoutes(r *gin.Engine) {
	// Public API with basic rate limiting
	publicAPI := r.Group("/api/public")
	publicLimiter := middleware.NewIPRateLimiter(&middleware.IPRateLimiterConfig{
		Rate:          100, // 100 req/sec per IP
		Burst:         20,  // 20 burst per IP
		EnableHeaders: true,
		EnableLogging: false,
	})
	middleware.GlobalRegistry.Register("public-api", publicLimiter)
	publicAPI.Use(publicLimiter.Middleware())
	{
		publicAPI.GET("/health", healthHandler)
		publicAPI.GET("/info", infoHandler)
		publicAPI.POST("/contact", contactHandler)
	}

	// Authenticated API with user-based rate limiting
	authAPI := r.Group("/api/auth")
	authAPI.Use(authMiddleware()) // Authentication required

	userLimiter := middleware.NewUserRateLimiter(&middleware.UserRateLimiterConfig{
		Rate:          200,    // 200 req/sec per user
		Burst:         50,     // 50 burst per user
		MaxUsers:      100000, // Track up to 100k users
		EnableHeaders: true,
		EnableLogging: true,
		RequireAuth:   true, // Reject unauthenticated requests
		FallbackToIP:  false,
		OnLimitExceeded: func(c *gin.Context, info *middleware.UserRequestInfo) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "User rate limit exceeded",
				"user":        info.UserID,
				"message":     "You have exceeded your API rate limit",
				"scope":       "per-user",
				"retry_after": 60,
				"upgrade_url": "https://example.com/upgrade",
			})
			c.Abort()
		},
	})
	middleware.GlobalRegistry.Register("auth-api", userLimiter)
	authAPI.Use(userLimiter.Middleware())
	{
		authAPI.GET("/profile", profileHandler)
		authAPI.PUT("/profile", updateProfileHandler)
		authAPI.GET("/dashboard", dashboardHandler)
		authAPI.POST("/data", createDataHandler)
	}

	// Premium API with tier-based rate limiting
	premiumAPI := r.Group("/api/premium")
	premiumAPI.Use(authMiddleware())

	tierLimiter := middleware.NewAdvancedRateLimiter(&middleware.AdvancedRateLimiterConfig{
		Rate:           500, // Base rate
		Burst:          100, // Base burst
		EnableHeaders:  true,
		EnableLogging:  true,
		CustomKeyFunc:  tierBasedKeyExtractor,
		KeyDescription: "user-tier",
		OnLimitExceeded: func(c *gin.Context, info *middleware.AdvancedRequestInfo) {
			tier := c.GetHeader("X-User-Tier")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Tier rate limit exceeded",
				"tier":        tier,
				"client":      info.ClientKey,
				"message":     "Upgrade your plan for higher rate limits",
				"scope":       "tier-based",
				"upgrade_url": "https://example.com/upgrade",
			})
			c.Abort()
		},
	})
	middleware.GlobalRegistry.Register("premium-api", tierLimiter)
	premiumAPI.Use(tierLimiter.Middleware())
	{
		premiumAPI.GET("/analytics", analyticsHandler)
		premiumAPI.POST("/bulk-import", bulkImportHandler)
		premiumAPI.GET("/export", exportHandler)
	}

	// Heavy operations with token bucket (graceful waiting)
	heavyAPI := r.Group("/api/heavy")
	heavyAPI.Use(authMiddleware())

	heavyLimiter := middleware.NewTokenBucketLimiter(&middleware.TokenBucketConfig{
		Rate:          5,                // 5 operations per second
		Burst:         2,                // 2 operation capacity
		WaitTimeout:   10 * time.Second, // Wait up to 10 seconds
		EnableHeaders: true,
		EnableLogging: true,
		OnWaitTimeout: func(c *gin.Context, info *middleware.TokenBucketRequestInfo) {
			log.Printf("⏰ Heavy operation timeout for client: %s", info.ClientKey)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":     "Operation queue full",
				"message":   "Server is processing too many heavy operations. Please try again later.",
				"waited":    int64(info.WaitTime.Milliseconds()),
				"timeout":   10000,
				"algorithm": "token-bucket",
			})
			c.Abort()
		},
	})
	middleware.GlobalRegistry.Register("heavy-operations", heavyLimiter)
	heavyAPI.Use(heavyLimiter.Middleware())
	{
		heavyAPI.POST("/process-large-file", processLargeFileHandler)
		heavyAPI.POST("/generate-report", generateReportHandler)
		heavyAPI.POST("/ml-inference", mlInferenceHandler)
	}
}

func setupMonitoringEndpoints(r *gin.Engine) {
	admin := r.Group("/admin")
	admin.Use(adminAuthMiddleware()) // Admin authentication required

	// Rate limiter statistics
	admin.GET("/rate-limiters", func(c *gin.Context) {
		c.JSON(http.StatusOK, middleware.GlobalRegistry.GetSummaryStats())
	})

	// Detailed stats for specific rate limiter
	admin.GET("/rate-limiters/:name", func(c *gin.Context) {
		name := c.Param("name")
		limiter, exists := middleware.GlobalRegistry.Get(name)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Rate limiter not found"})
			return
		}

		stats := limiter.GetStats()
		response := gin.H{
			"name":             name,
			"type":             limiter.Type().String(),
			"algorithm":        limiter.Algorithm().String(),
			"total_requests":   stats.GetTotalRequests(),
			"allowed_requests": stats.GetAllowedRequests(),
			"blocked_requests": stats.GetBlockedRequests(),
			"success_rate":     stats.GetSuccessRate(),
			"uptime":           stats.GetUptime().String(),
		}

		// Add client-specific stats if available
		if clientAware, ok := limiter.(middleware.ClientAwareRateLimiter); ok {
			response["active_clients"] = clientAware.GetClientCount()
			response["client_list"] = clientAware.ListActiveClients()
		}

		c.JSON(http.StatusOK, response)
	})

	// Reset statistics
	admin.POST("/rate-limiters/:name/reset", func(c *gin.Context) {
		name := c.Param("name")
		limiter, exists := middleware.GlobalRegistry.Get(name)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Rate limiter not found"})
			return
		}

		limiter.ResetStats()
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Statistics reset for %s", name)})
	})

	// Health check for rate limiters
	admin.GET("/health", func(c *gin.Context) {
		stats := middleware.GlobalRegistry.GetAllStats()
		healthy := true
		issues := []string{}

		for name, stat := range stats {
			successRate := stat.GetSuccessRate()
			if successRate < 0.8 { // Less than 80% success rate
				healthy = false
				issues = append(issues, fmt.Sprintf("%s has low success rate: %.2f%%", name, successRate*100))
			}
		}

		status := http.StatusOK
		if !healthy {
			status = http.StatusServiceUnavailable
		}

		c.JSON(status, gin.H{
			"healthy": healthy,
			"issues":  issues,
			"stats":   stats,
		})
	})

	// Metrics in Prometheus format (basic)
	admin.GET("/metrics", func(c *gin.Context) {
		var metrics []string
		stats := middleware.GlobalRegistry.GetAllStats()

		for name, stat := range stats {
			metrics = append(metrics,
				fmt.Sprintf("rate_limiter_total_requests{name=\"%s\"} %d", name, stat.GetTotalRequests()),
				fmt.Sprintf("rate_limiter_allowed_requests{name=\"%s\"} %d", name, stat.GetAllowedRequests()),
				fmt.Sprintf("rate_limiter_blocked_requests{name=\"%s\"} %d", name, stat.GetBlockedRequests()),
				fmt.Sprintf("rate_limiter_success_rate{name=\"%s\"} %.4f", name, stat.GetSuccessRate()),
			)
		}

		c.Header("Content-Type", "text/plain")
		for _, metric := range metrics {
			c.String(http.StatusOK, metric+"\n")
		}
	})
}

// Middleware functions
func customLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path
		ip := c.ClientIP()

		// Log format: [timestamp] status method path latency ip
		log.Printf("[%s] %d %s %s %v %s",
			start.Format("2006-01-02 15:04:05"),
			status,
			method,
			path,
			latency,
			ip,
		)

		// Alert on high latency
		if latency > 5*time.Second {
			log.Printf("🐌 SLOW REQUEST: %s %s took %v", method, path, latency)
		}

		// Alert on errors
		if status >= 500 {
			log.Printf("🚨 SERVER ERROR: %d for %s %s", status, method, path)
		}
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simple authentication check
		userID := c.GetHeader("X-User-ID")
		apiKey := c.GetHeader("X-API-Key")

		if userID == "" && apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"message": "Provide X-User-ID or X-API-Key header",
			})
			c.Abort()
			return
		}

		// Set user tier based on user ID or API key
		if userID != "" {
			// Simulate tier determination
			tier := "free"
			if userID == "premium_user" || userID == "enterprise_user" {
				tier = "premium"
			}
			c.Header("X-User-Tier", tier)
		}

		c.Next()
	}
}

func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminKey := c.GetHeader("X-Admin-Key")
		if adminKey != "admin123" { // In production, use proper admin authentication
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Admin authentication required",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func tierBasedKeyExtractor(c *gin.Context) string {
	userID := c.GetHeader("X-User-ID")
	tier := c.GetHeader("X-User-Tier")

	if userID == "" {
		return "anonymous:" + c.ClientIP()
	}
	if tier == "" {
		tier = "free"
	}

	return fmt.Sprintf("user:%s:tier:%s", userID, tier)
}

// Handler functions
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

func infoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "Rate Limiter SDK Demo",
		"version": "1.0.0",
		"uptime":  time.Since(time.Now().Add(-time.Hour)).String(), // Mock uptime
	})
}

func contactHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Contact form submitted",
		"status":  "received",
	})
}

func profileHandler(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"profile": "User profile data",
		"tier":    c.GetHeader("X-User-Tier"),
	})
}

func updateProfileHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
	})
}

func dashboardHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"dashboard": "User dashboard data",
		"widgets":   []string{"analytics", "reports", "settings"},
	})
}

func createDataHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"message": "Data created successfully",
		"id":      "data_123",
	})
}

func analyticsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"analytics": "Premium analytics data",
		"metrics":   []string{"views", "clicks", "conversions"},
	})
}

func bulkImportHandler(c *gin.Context) {
	// Simulate heavy operation
	time.Sleep(2 * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"message": "Bulk import completed",
		"records": 1000,
	})
}

func exportHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"export_url": "https://example.com/exports/file123.csv",
		"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

func processLargeFileHandler(c *gin.Context) {
	// Simulate very heavy operation
	time.Sleep(5 * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"message":      "Large file processed",
		"file_size":    "100MB",
		"process_time": "5.0s",
	})
}

func generateReportHandler(c *gin.Context) {
	// Simulate heavy operation
	time.Sleep(3 * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"message":   "Report generated",
		"report_id": "report_456",
		"pages":     50,
	})
}

func mlInferenceHandler(c *gin.Context) {
	// Simulate ML inference
	time.Sleep(1 * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"prediction": 0.85,
		"confidence": 0.92,
		"model":      "production_v2",
	})
}

func printProductionInfo() {
	fmt.Println("🏭 RATE LIMITER SDK - PRODUCTION EXAMPLE")
	fmt.Println()

	fmt.Println("🛡️  LAYERED PROTECTION:")
	fmt.Println("   Layer 1: Global protection (10k req/sec)")
	fmt.Println("   Layer 2: DDoS protection (1k req/sec per IP)")
	fmt.Println("   Layer 3: API-specific limits")
	fmt.Println()

	fmt.Println("🔗 API ENDPOINTS:")
	fmt.Println()
	fmt.Println("📖 PUBLIC API (100 req/sec per IP):")
	fmt.Println("   GET  /api/public/health")
	fmt.Println("   GET  /api/public/info")
	fmt.Println("   POST /api/public/contact")
	fmt.Println()

	fmt.Println("🔐 AUTHENTICATED API (200 req/sec per user):")
	fmt.Println("   Headers: X-User-ID: <user_id>")
	fmt.Println("   GET  /api/auth/profile")
	fmt.Println("   PUT  /api/auth/profile")
	fmt.Println("   GET  /api/auth/dashboard")
	fmt.Println("   POST /api/auth/data")
	fmt.Println()

	fmt.Println("💎 PREMIUM API (tier-based limits):")
	fmt.Println("   Headers: X-User-ID: <user_id>, X-User-Tier: <tier>")
	fmt.Println("   GET  /api/premium/analytics")
	fmt.Println("   POST /api/premium/bulk-import")
	fmt.Println("   GET  /api/premium/export")
	fmt.Println()

	fmt.Println("🏗️  HEAVY OPERATIONS (5 req/sec with 10s wait):")
	fmt.Println("   Headers: X-User-ID: <user_id>")
	fmt.Println("   POST /api/heavy/process-large-file")
	fmt.Println("   POST /api/heavy/generate-report")
	fmt.Println("   POST /api/heavy/ml-inference")
	fmt.Println()

	fmt.Println("📊 MONITORING (Admin endpoints):")
	fmt.Println("   Headers: X-Admin-Key: admin123")
	fmt.Println("   GET  /admin/rate-limiters")
	fmt.Println("   GET  /admin/rate-limiters/:name")
	fmt.Println("   POST /admin/rate-limiters/:name/reset")
	fmt.Println("   GET  /admin/health")
	fmt.Println("   GET  /admin/metrics")
	fmt.Println()

	fmt.Println("🧪 TESTING EXAMPLES:")
	fmt.Println()
	fmt.Println("# Test public API")
	fmt.Println("curl http://localhost:8080/api/public/health")
	fmt.Println()
	fmt.Println("# Test authenticated API")
	fmt.Println("curl -H \"X-User-ID: premium_user\" http://localhost:8080/api/auth/profile")
	fmt.Println()
	fmt.Println("# Test premium features")
	fmt.Println("curl -H \"X-User-ID: premium_user\" -H \"X-User-Tier: premium\" http://localhost:8080/api/premium/analytics")
	fmt.Println()
	fmt.Println("# Test heavy operations (waits for capacity)")
	fmt.Println("curl -H \"X-User-ID: user123\" -X POST http://localhost:8080/api/heavy/process-large-file")
	fmt.Println()
	fmt.Println("# Monitor rate limiters (admin)")
	fmt.Println("curl -H \"X-Admin-Key: admin123\" http://localhost:8080/admin/rate-limiters")
	fmt.Println()
	fmt.Println("# Load test example")
	fmt.Println("for i in {1..100}; do curl -s http://localhost:8080/api/public/health & done")
	fmt.Println()
}
