package main

import (
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// 是否启用诱饵路由
func decoysEnabled() bool {
	v := os.Getenv("HONEYTRAP_DECOYS")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

func registerDecoys(r *gin.Engine) {
	if !decoysEnabled() {
		return
	}
	decoys := []string{
		"/admin", "/login", "/wp-login.php", "/wp-admin", "/phpmyadmin",
		"/unifiedpaymentsinterface", "/unified-payments-interface", "/npci-upi",
		"/impsnpci", "/bhim-npci", "/cheque-truncation-system",
	}
	for _, p := range decoys {
		path := p
		r.Any(path, func(c *gin.Context) {
			// 轻微延迟
			time.Sleep(time.Duration(60+rand.Intn(240)) * time.Millisecond)
			c.Header("Cache-Control", "no-store")
			c.Header("X-Frame-Options", "DENY")
			c.String(200, "OK")
		})
	}
}
