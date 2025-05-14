package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleErrorReturnsCorrectStatusAndMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/error", func(c *gin.Context) {
		handleError(c, http.StatusInternalServerError, "internal error")
	})

	req, _ := http.NewRequest(http.MethodGet, "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"status":"error","message":"internal error"}`, w.Body.String())
}

func TestCheckRequestIPHandlerReturnsLocalhostMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","message":"Request from localhost.","ip":"127.0.0.1"}`, w.Body.String())
}

func TestCheckRequestIPHandlerReturnsErrorForInvalidIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "invalid-ip:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"message":"Invalid or unidentifiable IP address.", "status":"error"}`, w.Body.String())
}

func TestCheckRequestIPHandlerReturnsPrivateIPMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","message":"Request from a private or bogon IP address.","ip":"192.168.1.1"}`, w.Body.String())
}

func TestCheckRequestIPHandlerReturnsBannedForRiskyIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// 需要确保 riskySingleIPs 和 reasonMap 已初始化
	riskySingleIPs = make(map[string]bool)
	reasonMap = make(map[string]string)
	riskySingleIPs["8.8.8.8"] = true
	reasonMap["8.8.8.8"] = "Test reason"

	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "8.8.8.8:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"banned","message":"Test reason","ip":"8.8.8.8"}`, w.Body.String())
}

func TestCheckRequestIPHandlerReturnsOKForSafeIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "8.8.4.4:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"ok","message":"IP is not listed as risky.","ip":"8.8.4.4"}`, w.Body.String())
}
