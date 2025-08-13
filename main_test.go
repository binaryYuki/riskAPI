package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestRiskyIPChannels(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// edgeone
	riskyCIDRInfo = []CIDRInfo{}
	riskySingleIPs = map[string]bool{}
	reasonMap = map[string]string{}
	_, edgeoneNet, _ := net.ParseCIDR("1.71.146.0/23")
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: edgeoneNet, OriginalCIDR: "1.71.146.0/23"})
	reasonMap["1.71.146.0/23"] = "edgeone"

	router := gin.Default()
	router.GET("/api/v1/ip", checkRequestIPHandler)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.RemoteAddr = "1.71.146.1:12345"
	router.ServeHTTP(w, req)
	assert.Contains(t, w.Body.String(), "edgeone")

	// fastly
	riskyCIDRInfo = []CIDRInfo{}
	riskySingleIPs = map[string]bool{}
	reasonMap = map[string]string{}
	_, fastlyNet, _ := net.ParseCIDR("23.235.32.0/20")
	riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: fastlyNet, OriginalCIDR: "23.235.32.0/20"})
	reasonMap["23.235.32.0/20"] = "fastly"

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req2.RemoteAddr = "23.235.32.1:12345"
	router.ServeHTTP(w2, req2)
	assert.Contains(t, w2.Body.String(), "fastly")
}

func getFirstCIDRFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			return
		}
	}(f)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "//") {
			return line, nil
		}
	}
	return "", nil
}

func ipFromCIDR(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.String(), nil // fallback for IPv6
	}
	ip4[3]++ // 取第一个可用IP
	return ip4.String(), nil
}

func TestAllRiskyChannelsAuto(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var testFiles []string
	err := filepath.Walk("data", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") {
			testFiles = append(testFiles, path)
		}
		return nil
	})
	if err != nil {
		return
	}
	for _, file := range testFiles {
		cidr, err := getFirstCIDRFromFile(file)
		if err != nil || cidr == "" {
			continue
		}
		ip, err := ipFromCIDR(cidr)
		if err != nil {
			continue
		}
		// 渠道名用文件名
		parts := strings.Split(file, string(os.PathSeparator))
		channel := strings.TrimSuffix(parts[len(parts)-1], ".txt")
		t.Run(channel, func(t *testing.T) {
			riskyCIDRInfo = []CIDRInfo{}
			riskySingleIPs = map[string]bool{}
			reasonMap = map[string]string{}
			_, netObj, _ := net.ParseCIDR(cidr)
			riskyCIDRInfo = append(riskyCIDRInfo, CIDRInfo{Net: netObj, OriginalCIDR: cidr})
			reasonMap[cidr] = channel
			router := gin.Default()
			router.GET("/api/v1/ip", checkRequestIPHandler)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/ip", nil)
			req.RemoteAddr = ip + ":12345"
			router.ServeHTTP(w, req)
			assert.Contains(t, w.Body.String(), channel)
		})
	}
}
