package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
	"time"
)

type SlidingWindowLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	limiter := &SlidingWindowLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	// Cleanup goroutine
	go limiter.cleanup()
	return limiter
}

func (s *SlidingWindowLimiter) cleanup() {
	ticker := time.NewTicker(s.window)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-s.window)

		for key, requests := range s.requests {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if reqTime.After(windowStart) {
					validRequests = append(validRequests, reqTime)
				}
			}
			if len(validRequests) == 0 {
				delete(s.requests, key)
			} else {
				s.requests[key] = validRequests
			}
		}
		s.mu.Unlock()
	}
}

func (s *SlidingWindowLimiter) Allow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-s.window)

	// Clean old requests
	if requests, exists := s.requests[key]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if reqTime.After(windowStart) {
				validRequests = append(validRequests, reqTime)
			}
		}
		s.requests[key] = validRequests
	}

	// Check limit
	if len(s.requests[key]) >= s.limit {
		return false
	}

	// Add new request
	s.requests[key] = append(s.requests[key], now)
	return true
}

func (s *SlidingWindowLimiter) Middleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		ip := c.ClientIP()
		if !s.Allow(ip) {
			remaining := s.window - time.Since(s.requests[ip][0])
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": remaining.String(),
				"limit":       s.limit,
				"window":      s.window.String(),
			})
			c.Abort()
			return
		}
		c.Next()
	})
}
