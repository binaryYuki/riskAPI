package main

import (
	"encoding/xml"
	"net"
	"sync"

	"github.com/patrickmn/go-cache"
)

// FastlyIPList represents Fastly IP list structure
type FastlyIPList struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

// CIDRInfo stores a parsed CIDR network and its original string representation
type CIDRInfo struct {
	Net          *net.IPNet
	OriginalCIDR string
}

// IPAssociation is used to pass IP/CIDR entries and their reasons from fetchers
type IPAssociation struct {
	Entry  string // IP or CIDR string
	Reason string
}

// Config stores application configuration
type Config struct {
	Timeout     int `json:"timeout"`
	Retries     int `json:"retries"`
	RetryDelay  int `json:"retry_delay"`
	Concurrency int `json:"concurrency"`
}

// WelcomeJson root handler
type WelcomeJson struct {
	Msg string `json:"message"`
}

// Proxy represents a proxy configuration
type Proxy struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

// IPCacheData represents the cached IP data structure
type IPCacheData struct {
	Timestamp int64    `json:"timestamp"`
	Entries   []string `json:"entries"`
}

// RSSFeed is a struct for parsing Project Honeypot RSS data
type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

// Response represents standard API response
type Response struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
}

// ResponseWithIP represents API response with IP field
type ResponseWithIP struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message,omitempty"`
	IP      string      `json:"ip,omitempty"`
}

// StatusCountMsg represents status count message
type StatusCountMsg struct {
	Timestamp int64 `json:"timestamp"`
	Count     int   `json:"total_ip_count"`
}

// Global variables for data storage
var (
	// Data structures for storing risky IPs
	riskySingleIPs map[string]bool   // Stores single IPs for quick lookup
	riskyCIDRInfo  []CIDRInfo        // Stores parsed CIDR info
	reasonMap      map[string]string // Stores reasons for IPs/CIDRs
	riskyDataMutex sync.RWMutex      // Protects riskySingleIPs, riskyCIDRInfo, and reasonMap

	// Cache
	appCache *cache.Cache

	// CDN/IDC IP 列表内存缓存
	cdnIPCache    map[string][]CIDRInfo      // CDN IP 缓存 (edgeone, cloudflare, fastly)
	idcIPCache    map[string][]CIDRInfo      // IDC IP 缓存 (aws, azure, gcp, etc.)
	cdnSingleIPs  map[string]map[string]bool // CDN 单个 IP 缓存
	idcSingleIPs  map[string]map[string]bool // IDC 单个 IP 缓存
	cdnIdcMutex   sync.RWMutex               // 保护 CDN/IDC 缓存的读写锁
	cacheInitOnce sync.Once                  // 确保缓存只初始化一次

	// Fastly related
	fastlyCIDRsMutex sync.RWMutex
)
