package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var version = "dev"

// checkIPHandler handles IP checking requests
func checkIPHandler(c *gin.Context) {
	ip := c.Param("ip")

	// Validate IP format (IPv4 / IPv6)
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid IP address format")
		return
	}

	// Check if IP is bogon or private
	if isBogonOrPrivateIP(ip) {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "IP is not risky (private/bogon)",
			IP:      ip,
		})
		return
	}

	// Check if IP is risky
	isRisky, reason := isRiskyIP(ip)
	if isRisky {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "risky",
			Message: "IP is in risky list: " + reason,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to CDN
	isCDN, cdnProvider := isCDNIP(ip)
	if isCDN {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "cdn",
			Message: "IP belongs to CDN: " + cdnProvider,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to IDC
	isIDC, idcProvider := isIDCIP(ip)
	if isIDC {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "idc",
			Message: "IP belongs to IDC: " + idcProvider,
			IP:      ip,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, ResponseWithIP{
		Status:  "ok",
		Message: "IP is not risky",
		IP:      ip,
	})
}

// checkRequestIPHandler checks the request's source IP
func checkRequestIPHandler(c *gin.Context) {
	ip := getClientIPFromCDNHeaders(c)

	// Validate IP format
	if net.ParseIP(ip) == nil {
		handleError(c, http.StatusBadRequest, "Invalid or unidentifiable IP address.")
		return
	}

	// Check if IP is bogon or private
	if isBogonOrPrivateIP(ip) {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "ok",
			Message: "Client IP is not risky (private/bogon)",
			IP:      ip,
		})
		return
	}

	// Check if IP is risky
	isRisky, reason := isRiskyIP(ip)
	if isRisky {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "banned",
			Message: reason,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to CDN
	isCDN, cdnProvider := isCDNIP(ip)
	if isCDN {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "cdn",
			Message: "Client IP belongs to CDN: " + cdnProvider,
			IP:      ip,
		})
		return
	}

	// Check if IP belongs to IDC
	isIDC, idcProvider := isIDCIP(ip)
	if isIDC {
		c.IndentedJSON(http.StatusOK, ResponseWithIP{
			Status:  "idc",
			Message: "Client IP belongs to IDC: " + idcProvider,
			IP:      ip,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, ResponseWithIP{
		Status:  "ok",
		Message: "IP is not listed as risky.",
		IP:      ip,
	})
}

// homeHandler handles root path requests
func homeHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusMisdirectedRequest,
		WelcomeJson{Msg: "Welcome to Catyuki's Risky IP Filter API. Use /api/v1/ip to check IPs."})
}

// filterProxiesHandler handles proxy filtering requests
func filterProxiesHandler(c *gin.Context) {
	var proxies []Proxy
	if err := c.ShouldBindJSON(&proxies); err != nil {
		c.JSON(http.StatusBadRequest, Response{"error", "Request body is invalid."})
		return
	}

	config := getDefaultConfig()
	nonRiskyProxies := processProxies(proxies, config.Concurrency)
	filteredData := gin.H{
		"filtered_count": len(proxies) - len(nonRiskyProxies),
		"proxies":        nonRiskyProxies,
	}
	c.JSON(http.StatusOK, Response{
		Status:  "ok",
		Message: filteredData,
	})
}

// statusHandler handles status requests
func statusHandler(c *gin.Context) {
	riskyDataMutex.RLock()
	count := len(riskySingleIPs) + len(riskyCIDRInfo)
	riskyDataMutex.RUnlock()

	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: StatusCountMsg{
			Timestamp: time.Now().Unix(),
			Count:     count,
		},
	})
}

// cdnHandler handles CDN list requests
func cdnHandler(c *gin.Context) {
	name := c.Param("name")
	allowed := map[string]bool{"edgeone": true, "cloudflare": true, "fastly": true}
	if !allowed[name] {
		handleError(c, http.StatusNotFound, "Not Found")
		return
	}

	filePath := "data/" + name + ".txt"
	file, err := os.Open(filePath)
	if err != nil {
		handleError(c, http.StatusInternalServerError, "File open error")
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		handleError(c, http.StatusInternalServerError, "File read error")
		return
	}
	c.String(http.StatusOK, strings.Join(lines, "\n"))
}

// cdnAllHandler handles combined CDN list requests
func cdnAllHandler(c *gin.Context) {
	var result []string
	providers := []struct{ name, label string }{
		{"edgeone", "====== edgeone ======"},
		{"cloudflare", "====== cloudflare ======"},
		{"fastly", "====== fastly ======"},
	}

	for _, p := range providers {
		result = append(result, p.label)
		filePath := "data/" + p.name + ".txt"
		data, err := os.ReadFile(filePath)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					result = append(result, l)
				}
			}
		} else {
			result = append(result, "# Error reading "+p.name+": "+err.Error())
		}
		result = append(result, "") // 空行分割
	}

	c.String(http.StatusOK, strings.Join(result, "\n"))
}

// versionHandler handles version requests
func versionHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Response{
		Status: "ok",
		Message: gin.H{
			"version": version,
		},
	})
}

// notFoundHandler handles 404 requests
func notFoundHandler(c *gin.Context) {
	handleError(c, http.StatusNotFound, "Not Found")
}
