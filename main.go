package main

import (
	"log"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

func main() {
	// Initialize cache and data structures
	appCache = cache.New(ipCacheExpiry, 10*time.Minute)
	_ = make(map[string]bool)
	riskyCIDRInfo = make([]CIDRInfo, 0)
	reasonMap = make(map[string]string)

	// Get configuration
	allowedDomains := getAllowedDomains()
	config := getDefaultConfig()

	// Setup CORS configuration
	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if !strings.HasPrefix(origin, "https://") {
				// Allow localhost for development if needed
				// return strings.HasPrefix(origin, "http://localhost")
				return false
			}
			for _, domain := range allowedDomains {
				if origin == "https://"+domain || strings.HasSuffix(origin, "."+domain) {
					return true
				}
			}
			return false
		},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	// Setup router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors.New(corsConfig))
	router.Use(CorrelationMiddleware())
	router.Use(LoggingMiddleware())
	router.Use(SensitivePathMiddleware())

	// Start background services
	go updateFastlyIPs(router)
	go updateIPListsPeriodically(config)
	startCDNListSync()
	initCDNIDCCache()

	// Setup routes
	setupRoutes(router)

	// Start server
	log.Printf("Starting server on port 8080...")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupRoutes configures all application routes
func setupRoutes(router *gin.Engine) {
	// Default route handlers
	router.NoRoute(notFoundHandler)
	router.GET("/", homeHandler)

	// API routes
	ipCheckGroup := router.Group("/api/v1/ip")
	{
		ipCheckGroup.GET("/:ip", checkIPHandler)
		ipCheckGroup.POST("/:ip", checkIPHandler)
	}
	router.GET("/api/v1/ip", checkRequestIPHandler)
	router.GET("/api/status", statusHandler)

	router.GET("/api/v1/info", ipInfoHandler)
	infoGroup := router.Group("/api/v1/info")
	{
		infoGroup.GET("/:ip", ipInfoHandler)
	}

	// Version route
	router.GET("/version", versionHandler)

	// Proxy filtering
	router.POST("/filter-proxies", filterProxiesHandler)

	// CDN routes
	router.GET("/cdn/:name", cdnHandler)
	router.GET("/cdn/all", cdnAllHandler)

	router.GET("/api/metrics", metricsHandler)

	router.GET("/api/cache/flush", flushCacheIndexHandler)
	router.POST("/api/cache/flush/:method/*range", flushCacheHandler)
}
