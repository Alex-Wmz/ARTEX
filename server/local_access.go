package server

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// LocalAccess protects the management UI/API, not the target-recording proxy.
// The listen address and Docker's loopback port publication provide the actual
// network boundary. Host validation also rejects DNS rebinding; Origin checks
// protect unauthenticated setup/login from unrelated web pages.
func LocalAccess(next http.Handler) http.Handler {
	allowRemote := os.Getenv("ARTEX_ALLOW_REMOTE_ACCESS") == "1"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRemote && !loopbackAuthority(r.Host) {
			writeErr(w, http.StatusForbidden, "此构建默认仅允许通过 localhost 或环回地址访问")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !managementOrigin(r, origin) {
			writeErr(w, http.StatusForbidden, "拒绝来自其它网站的管理请求")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackAuthority(authority string) bool {
	u, err := url.Parse("http://" + authority)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func managementOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	// Next dev uses a second loopback port for SSE. No arbitrary LAN or
	// third-party origin is allowed, even when remote access is opted into.
	return u.Scheme == "http" && loopbackAuthority(r.Host) && loopbackAuthority(u.Host) &&
		(u.Port() == "3000" || u.Port() == "5173")
}
