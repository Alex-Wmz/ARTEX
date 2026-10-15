package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalSecurityManagementBoundary(t *testing.T) {
	t.Setenv("ARTEX_ALLOW_REMOTE_ACCESS", "")
	for _, tc := range []struct {
		name, target, origin string
		want int
	}{
		{"local UI", "http://127.0.0.1:8787/api/auth/init", "http://127.0.0.1:8787", 200},
		{"localhost", "http://localhost:8787/", "", 200},
		{"IPv6", "http://[::1]:8787/", "", 200},
		{"Next SSE", "http://127.0.0.1:8787/api/events", "http://127.0.0.1:3000", 200},
		{"cross site setup", "http://127.0.0.1:8787/api/auth/init", "https://evil.test", 403},
		{"null origin", "http://localhost:8787/api/auth/init", "null", 403},
		{"LAN host", "http://192.0.2.1:8787/", "", 403},
		{"DNS rebinding", "http://rebind.test:8787/api/auth/init", "http://rebind.test:8787", 403},
		{"fake loopback", "http://127.0.0.1.evil.test:8787/", "", 403},
		{"unrelated local port", "http://localhost:8787/api/auth/init", "http://localhost:9999", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := LocalAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest(http.MethodPost, tc.target, nil)
			if tc.origin != "" { r.Header.Set("Origin", tc.origin) }
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || called != (tc.want == 200) {
				t.Fatalf("status=%d handler-called=%v, want %d", w.Code, called, tc.want)
			}
		})
	}
}

func TestLocalSecurityRemoteOptInKeepsOriginProtection(t *testing.T) {
	t.Setenv("ARTEX_ALLOW_REMOTE_ACCESS", "1")
	h := LocalAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, tc := range []struct { origin string; want int }{
		{"http://artex.test:8787", 200}, {"https://evil.test", 403},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://artex.test:8787/api/auth/init", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want { t.Fatalf("origin %s: %d, want %d", tc.origin, w.Code, tc.want) }
	}
}
