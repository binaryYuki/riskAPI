package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultParseWorkerBase = "http://xhs-proxy.tzpro.workers.dev"
	defaultParseVVSecret   = "098070c045665742f76237ba7096131755c5c02942e963e94b9cecbc53152861"
	parsePathname          = "/api/parse"
)

var (
	parseWorkerBase = getEnvString("PARSE_WORKER_BASE", defaultParseWorkerBase)
	parseVVSecret   = getEnvString("PARSE_VV_SECRET", defaultParseVVSecret)
	parseHTTPClient = &http.Client{Timeout: 30 * time.Second}
	parseNonceChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

type parseBody struct {
	URL string `json:"url"`
}

func parseProxyHandler(c *gin.Context) {
	targetURL := strings.TrimSpace(c.Query("url"))
	if targetURL == "" {
		handleError(c, http.StatusBadRequest, "Missing required query parameter: url")
		return
	}

	if !isValidHTTPURL(targetURL) {
		handleError(c, http.StatusBadRequest, "Invalid url, only http/https is supported")
		return
	}

	body := parseBody{URL: targetURL}
	vv, err := generateVV(parseVVSecret, http.MethodPost, parsePathname, body)
	if err != nil {
		handleError(c, http.StatusInternalServerError, "Failed to generate request signature")
		return
	}

	base := strings.TrimRight(parseWorkerBase, "/")
	upstreamURL := fmt.Sprintf("%s%s?_vv=%s", base, parsePathname, url.QueryEscape(vv))

	payload, err := json.Marshal(body)
	if err != nil {
		handleError(c, http.StatusInternalServerError, "Failed to encode request body")
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, upstreamURL, bytes.NewReader(payload))
	if err != nil {
		handleError(c, http.StatusInternalServerError, "Failed to build upstream request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := parseHTTPClient.Do(req)
	if err != nil {
		handleError(c, http.StatusBadGateway, "Upstream parse service unavailable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		handleError(c, http.StatusBadGateway, "Failed to read upstream response")
		return
	}

	if json.Valid(raw) {
		var out interface{}
		if err := json.Unmarshal(raw, &out); err == nil {
			c.JSON(resp.StatusCode, out)
			return
		}
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.TrimSpace(contentType) == "" {
		contentType = "text/plain; charset=utf-8"
	}
	c.Data(resp.StatusCode, contentType, raw)
}

func generateVV(secret, method, pathname string, body parseBody) (string, error) {
	version := "v1"
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce, err := randomNonce(8)
	if err != nil {
		return "", err
	}

	bodyText, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	bodyHash := sha256Hex(string(bodyText))

	plain := strings.Join([]string{
		version,
		ts,
		nonce,
		strings.ToUpper(method),
		pathname,
		bodyHash,
		body.URL,
	}, "\n")

	sig := hmacSHA256Base64URL(secret, plain)
	return fmt.Sprintf("%s.%s.%s.%s", version, ts, nonce, sig), nil
}

func sha256Hex(text string) string {
	s := sha256.Sum256([]byte(text))
	return hex.EncodeToString(s[:])
}

func hmacSHA256Base64URL(secret, text string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(text))
	return strings.TrimRight(base64.URLEncoding.EncodeToString(m.Sum(nil)), "=")
}

func randomNonce(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	b := make([]byte, length)
	r := make([]byte, length)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	for i := 0; i < length; i++ {
		b[i] = parseNonceChars[int(r[i])%len(parseNonceChars)]
	}
	return string(b), nil
}

func isValidHTTPURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func getEnvString(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}
