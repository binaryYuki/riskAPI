package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleErrorReturnsInternalServerErrorForEmptyMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/error", func(c *gin.Context) {
		handleError(c, http.StatusNotFound, "")
	})

	req, _ := http.NewRequest(http.MethodGet, "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.JSONEq(t, `{"status":"error","message":""}`, w.Body.String())
}

func TestIPCheckReturnsErrorForPrivateIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip/:ip", checkIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip/192.168.0.1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"This is a private IP address, please check if you are calling this api correctly."}`, w.Body.String())
}
func TestFilterProxiesHandlesEmptyRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
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

	req, _ := http.NewRequest(http.MethodPost, "/filter-proxies", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"Request body is invalid."}`, w.Body.String())
}

func TestFilterProxiesHandlesAllRiskyIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	riskyIPs["192.168.1.1"] = true
	riskyIPs["10.0.0.1"] = true

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
		{"name": "Proxy2", "server": "10.0.0.1"},
		{"name": "Proxy3", "server": "103.21.244.1"}
	]`
	req, _ := http.NewRequest(http.MethodPost, "/filter-proxies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"filtered_count": 2, "proxies": {"name":"Proxy3", "server":"103.21.244.1"}}`, w.Body.String())
}
