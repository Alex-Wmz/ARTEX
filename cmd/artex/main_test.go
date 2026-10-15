package main

import (
	"context"
	"os"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestShutdownContextPreservesNamedCause(t *testing.T) {
	signalCtx, signalCancel := context.WithCancel(context.Background())
	ctx, shutdown := shutdownContext(signalCtx)
	defer shutdown(nil)
	signalCancel()
	<-ctx.Done()
	if code, _, _, ok := agent.AbortReason(ctx); !ok || code != "shutdown" {
		t.Fatalf("code=%q ok=%v, want shutdown", code, ok)
	}
}

func TestLocalSecurityToolDownloadPolicy(t *testing.T) {
	t.Setenv("ARTEX_ALLOW_TOOL_DOWNLOADS", "")
	t.Setenv("NORMA_RIPGREP_NO_INSTALL", "")
	configureToolDownloads()
	if os.Getenv("NORMA_RIPGREP_NO_INSTALL") != "1" { t.Fatal("automatic ripgrep download was not disabled") }
	// Explicit permission does not erase an independent user prohibition.
	t.Setenv("ARTEX_ALLOW_TOOL_DOWNLOADS", "1")
	configureToolDownloads()
	if os.Getenv("NORMA_RIPGREP_NO_INSTALL") != "1" { t.Fatal("explicit no-install setting was erased") }
}
