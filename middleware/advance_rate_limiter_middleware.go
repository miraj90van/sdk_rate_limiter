package middleware

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
	"time"
)

func AdvancedRateLimitMiddleware(r rate.Limit, b int) gin.HandlerFunc {
	limiter := rate.NewLimiter(r, b)

	return gin.HandlerFunc(func(c *gin.Context) {
		// Set rate limit headers
		c.Header("X-RateLimit-Limit", "100") // per hour
		c.Header("X-RateLimit-Remaining", "99")
		c.Header("X-RateLimit-Reset", time.Now().Add(time.Hour).Format(time.RFC3339))

		if !limiter.Allow() {
			c.Header("Retry-After", "60") // seconds
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please try again later.",
				"retry_after": 60,
			})
			c.Abort()
			return
		}
		c.Next()
	})
}
