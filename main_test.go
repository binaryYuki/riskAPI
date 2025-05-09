package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleErrorReturnsCorrectJSONResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/error", func(c *gin.Context) {
		handleError(c, http.StatusBadRequest, "bad request")
	})

	req, _ := http.NewRequest(http.MethodGet, "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"bad request"}`, w.Body.String())
}

func TestIPCheckReturnsErrorForInvalidIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip/:ip", checkIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/invalid-ip", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"Invalid IP address format"}`, w.Body.String())
}

func TestIPCheckReturnsBannedForRiskyIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	riskyIPs["192.168.1.1"] = true
	reasonMap["192.168.1.1"] = "Test message"

	router := gin.Default()
	router.GET("/api/v1/ip/:ip", checkIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/192.168.1.1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"banned","message":"Test message"}`, w.Body.String())
}

func TestIPCheckReturnsOKForSafeIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip/:ip", checkIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/8.8.8.8", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
}

func TestFilterProxiesExcludesRiskyIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	riskyIPs["192.168.1.1"] = true

	router := gin.Default()
	router.POST("/filter-proxies", func(c *gin.Context) {
		var proxies []Proxy
		if err := c.ShouldBindJSON(&proxies); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Request body is invalid."})
			return
		}
		nonRiskyProxies := processProxies(proxies)
		c.JSON(http.StatusOK, gin.H{
			"filtered_count": len(proxies) - len(nonRiskyProxies),
			"proxies":        nonRiskyProxies,
		})
	})

	body := `[
			{"name": "Proxy1", "server": "192.168.1.1"},
			{"name": "Proxy2", "server": "8.8.8.8"}
			]`
	req, _ := http.NewRequest(http.MethodPost, "/filter-proxies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"filtered_count": 1, "proxies": [{"name": "Proxy2", "server": "8.8.8.8"}]}`, w.Body.String())
}
