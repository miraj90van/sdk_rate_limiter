package middleware

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"net/http"
	"sync"
	"time"
)

type IPRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(i.rate, i.burst)
		i.limiters[ip] = limiter
		// Cleanup old limiters (optional)
		go i.cleanupLimiter(ip)
	}

	return limiter
}

func (i *IPRateLimiter) cleanupLimiter(ip string) {
	time.Sleep(10 * time.Minute) // Cleanup after 10 minutes
	i.mu.Lock()
	delete(i.limiters, ip)
	i.mu.Unlock()
}

func (i *IPRateLimiter) Middleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := i.GetLimiter(ip)

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded for IP: " + ip,
				"retry_after": "1s",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}
