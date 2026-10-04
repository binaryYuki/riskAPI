package honeytrap

import (
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// decoyPaths 诱饵路由：常被扫描的管理/支付入口，统一返回 200 "OK"
var decoyPaths = []string{
	"/admin", "/login", "/wp-login.php", "/wp-admin", "/phpmyadmin",
	"/unifiedpaymentsinterface", "/unified-payments-interface", "/npci-upi",
	"/impsnpci", "/bhim-npci", "/cheque-truncation-system",
}

// RegisterDecoys 在 Config.Decoys 开启时注册诱饵路由
func (t *Trap) RegisterDecoys(r gin.IRoutes) {
	if !t.cfg.Decoys {
		return
	}
	for _, path := range decoyPaths {
		r.Any(path, func(c *gin.Context) {
			// 轻微延迟
			time.Sleep(time.Duration(60+rand.IntN(240)) * time.Millisecond)
			c.Header("Cache-Control", "no-store")
			c.Header("X-Frame-Options", "DENY")
			c.String(http.StatusOK, "OK")
		})
	}
}
