package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	handleError(c, http.StatusBadRequest, "bad request")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"bad request"}`, w.Body.String())
}

func TestCheckRequestIPHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
		wantBody   string
		setup      func()
	}{
		{
			name:       "localhost",
			remoteAddr: "127.0.0.1:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"Request from localhost.","ip":"127.0.0.1"}`,
		},
		{
			name:       "invalid ip",
			remoteAddr: "invalid-ip:12345",
			wantCode:   http.StatusBadRequest,
			wantBody:   `{"message":"Invalid or unidentifiable IP address.", "status":"error"}`,
		},
		{
			name:       "private ip",
			remoteAddr: "192.168.1.1:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"Request from a private or bogon IP address.","ip":"192.168.1.1"}`,
		},
		{
			name:       "risky ip",
			remoteAddr: "8.8.8.8:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"banned","message":"Test reason","ip":"8.8.8.8"}`,
			setup: func() {
				riskySingleIPs = map[string]bool{"8.8.8.8": true}
				reasonMap = map[string]string{"8.8.8.8": "Test reason"}
			},
		},
		{
			name:       "safe ip",
			remoteAddr: "8.8.4.4:12345",
			wantCode:   http.StatusOK,
			wantBody:   `{"status":"ok","message":"IP is not listed as risky.","ip":"8.8.4.4"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			router := gin.Default()
			router.GET("/api/v1/ip", checkRequestIPHandler)
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
			req.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
			assert.JSONEq(t, tt.wantBody, w.Body.String())
		})
	}
}

func TestCorrelationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("generates correlation id", func(t *testing.T) {
		router := gin.New()
		router.Use(CorrelationMiddleware())
		router.GET("/test-correlation", func(c *gin.Context) {
			id, exists := c.Get("correlation_id")
			assert.True(t, exists)
			c.String(http.StatusOK, "%v", id)
		})
		req, _ := http.NewRequest(http.MethodGet, "/test-correlation", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		id := w.Body.String()
		assert.NotEmpty(t, id)
		assert.Equal(t, id, w.Header().Get("X-Request-ID"))
	})

	t.Run("uses provided correlation id", func(t *testing.T) {
		router := gin.New()
		router.Use(CorrelationMiddleware())
		router.GET("/test-correlation", func(c *gin.Context) {
			id, exists := c.Get("correlation_id")
			assert.True(t, exists)
			c.String(http.StatusOK, "%v", id)
		})
		req, _ := http.NewRequest(http.MethodGet, "/test-correlation", nil)
		req.Header.Set("X-Correlation-ID", "test-id-123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, "test-id-123", w.Body.String())
		assert.Equal(t, "test-id-123", w.Header().Get("X-Request-ID"))
	})
}
