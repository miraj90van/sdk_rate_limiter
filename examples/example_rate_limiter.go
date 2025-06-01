package examples

import (
	"github.com/gin-gonic/gin"
	"github.com/miraj90van/sdk_rate_limiter/middleware"
	"net/http"
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

	//Global protection (all clients share 1000 req/sec)
	v1 := r.Group("/api/v1")
	v1.Use(middleware.BasicRateLimitMiddleware(1000, 100))
	{
		v1.GET("/ping", pingHandler)
	}

	//Per-IP fairness (each IP gets 100 req/sec)
	v2 := r.Group("/api/v2")
	v2.Use(middleware.IPRateLimitMiddleware(100, 20))
	{
		v2.GET("/ping", pingHandler)
		v2.GET("/users/:id", userHandler)
	}

	//Per-user fairness (each user gets 50 req/sec)
	v3 := r.Group("/api/v3")
	v3.Use(middleware.UserRateLimitMiddleware(50, 10))
	{
		v3.GET("/ping", pingHandler)
	}

	//Per-user business rules
	v4 := r.Group("/api/v4")
	v4.Use(middleware.UserRateLimitMiddleware(50, 10))
	{
		v4.GET("/ping", pingHandler)
	}

	//Token Bucket
	v5 := r.Group("/api/v5")
	v5.Use(middleware.TokenBucketRateLimitMiddleware(50, 1))
	{
		v5.GET("/ping", pingHandler)
		v5.GET("/users/:id", userHandler)
	}

	//Advance Rate Limiter:
	v6 := r.Group("/api/v6")
	v6.Use(middleware.TierBasedRateLimitMiddleware(50, 1))
	{
		v6.GET("/ping", pingHandler)
		v6.GET("/users/:id", userHandler)
	}

	// Health check endpoint tanpa rate limit
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	err := r.Run(":8080")
	if err != nil {
		return
	}
}
