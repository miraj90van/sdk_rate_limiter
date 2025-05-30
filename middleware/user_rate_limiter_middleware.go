package middleware

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
	"sync"
)

type UserRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewUserRateLimiter(r rate.Limit, b int) *UserRateLimiter {
	return &UserRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

func (u *UserRateLimiter) GetLimiter(userID string) *rate.Limiter {
	u.mu.Lock()
	defer u.mu.Unlock()

	limiter, exists := u.limiters[userID]
	if !exists {
		limiter = rate.NewLimiter(u.rate, u.burst)
		u.limiters[userID] = limiter
	}

	return limiter
}

func (u *UserRateLimiter) Middleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Ambil user ID dari header, JWT token, atau session
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			userID = c.ClientIP() // fallback ke IP jika tidak ada user ID
		}

		limiter := u.GetLimiter(userID)

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded for user: " + userID,
				"retry_after": "1s",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}
