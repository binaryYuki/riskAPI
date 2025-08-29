package main

import (
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Set GOMAXPROCS to use all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Printf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))

	// Initialize cache and data structures
	appCache = NewRadixCache()
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
	router.Use(CrossOriginResourcePolicyMiddleware())
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

	// Start server with optimized settings for high concurrency
	log.Printf("Starting server on port 8080...")
	srv := &http.Server{
		Addr:           ":8080",
		Handler:        router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Configure transport for better concurrency
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 1000
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 100
	http.DefaultTransport.(*http.Transport).IdleConnTimeout = 90 * time.Second

	log.Printf("Server configured for high concurrency with optimized timeouts and connection limits")

	if err := srv.ListenAndServe(); err != nil {
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
