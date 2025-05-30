package middleware

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
)

func RateLimitMiddleware(r rate.Limit, b int) gin.HandlerFunc {
	limiter := rate.NewLimiter(r, b)

	return gin.HandlerFunc(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": "1s",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}
