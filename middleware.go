package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CorrelationMiddleware adds correlation ID to requests
func CorrelationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			id, err := uuid.NewV7()
			if err != nil {
				correlationID = uuid.New().String() + "vtc" // Fallback to a random UUID if V7 is not available
			} else {
				correlationID = id.String()
			}
		}
		correlationID = strings.ReplaceAll(correlationID, "-", "")
		c.Set("correlation_id", correlationID)
		c.Header("X-Request-ID", correlationID)
		// cache-control
		c.Header("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate")
		c.Next()
	}
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		correlationID, _ := c.Get("correlation_id")
		log.Printf("[GIN] %s | %3d | %13v | %-15s | %-20s | correlation_id=%v",
			time.Now().Format("2006/01/02 - 15:04:05"),
			status,
			latency,
			getClientIPFromCDNHeaders(c),
			c.Request.URL.Path,
			correlationID,
		)
	}
}

// SensitivePathMiddleware blocks access to sensitive paths
func SensitivePathMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if sensitivePathRegex.MatchString(c.Request.URL.Path) {
			if c.Request.Method == http.MethodGet {
				c.Header("Content-Type", "text/html; charset=utf-8")
				c.Header("X-Content-Type-Options", "nosniff")
				c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
				c.Header("Pragma", "no-cache")
				c.Header("Expires", "0")
				c.Status(http.StatusForbidden)
				c.File("data/pages/403.html")
			} else {
				c.JSON(403, gin.H{"error": "forbidden"})
			}
			c.Abort()
			return
		}
	}
}
