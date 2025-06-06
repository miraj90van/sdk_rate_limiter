package helper

import (
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

func setBasicRateLimitHeaders(c *gin.Context, requestsPerSecond float64, burst int, remaining int) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "global-redis")
}

func setIPRateLimitHeaders(c *gin.Context, requestsPerSecond float64, burst int, remaining int, ip string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "per-ip-redis")
	c.Header("X-RateLimit-IP", ip)
}

func setUserRateLimitHeaders(c *gin.Context, requestsPerSecond float64, burst int, remaining int, userID string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "per-user-redis")
	c.Header("X-RateLimit-User", userID)
}

func setAdvancedRateLimitHeaders(c *gin.Context, requestsPerSecond float64, burst int, remaining int, clientKey string) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "advanced-redis")
	c.Header("X-RateLimit-Client", clientKey)
}

func setSlidingWindowRateLimitHeaders(c *gin.Context, limit int, window time.Duration, remaining int) {
	c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Window", window.String())
	c.Header("X-RateLimit-Scope", "sliding-window-redis")
}

func setTokenBucketRateLimitHeaders(c *gin.Context, requestsPerSecond float64, burst int, remaining int, waitTime time.Duration) {
	limitPerMinute := int64(requestsPerSecond * 60)
	c.Header("X-RateLimit-Limit", strconv.FormatInt(limitPerMinute, 10))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Scope", "token-bucket-redis")

	if waitTime > 0 {
		c.Header("X-RateLimit-Wait-Time", strconv.FormatInt(waitTime.Milliseconds(), 10))
	}
}

// Helper function to extract user ID from headers
func extractUserIDFromHeaders(c *gin.Context, headers []string) string {
	for _, header := range headers {
		userID := c.GetHeader(header)
		if userID != "" {
			return userID
		}
	}
	return ""
}
