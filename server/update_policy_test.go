package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/selfupdate"
)

func TestLocalSecurityDisabledUpdatesNeverFetch(t *testing.T) {
	t.Setenv("ARTEX_ENABLE_UPDATES", "")
	old := relCache
	t.Cleanup(func() { relCache = old })
	calls := 0
	relCache = newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		return &selfupdate.Release{TagName: "v99.0.0"}, nil
	})
	// No Manager is needed: all disabled routes must return before constructing
	// a network client or looking up credentials/global proxy configuration.
	s := &Server{}
	for _, path := range []string{"/api/update/check", "/api/update/check?force=1"} {
		w := httptest.NewRecorder()
		s.updateCheck(w, httptest.NewRequest(http.MethodGet, path, nil))
		var out struct { UpdatesEnabled bool `json:"updates_enabled"`; HasUpdate bool `json:"has_update"`; Reason string `json:"reason"` }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil { t.Fatal(err) }
		if w.Code != 200 || out.UpdatesEnabled || out.HasUpdate || out.Reason == "" {
			t.Fatalf("unexpected disabled response: %d %s", w.Code, w.Body.String())
		}
	}
	for _, handler := range []http.HandlerFunc{s.updateApply, s.updateRollback} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodPost, "/api/update/apply", nil))
		if w.Code != http.StatusForbidden { t.Fatalf("status=%d, want 403", w.Code) }
	}
	if calls != 0 { t.Fatalf("disabled updates made %d release queries", calls) }
}
