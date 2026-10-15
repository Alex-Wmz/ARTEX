package selfupdate

import "os"

// Enabled is deliberately opt-in for this fork. Upstream release binaries do
// not contain the local hardening, so they must never replace this build by
// merely opening a page or reusing a previously staged update.
func Enabled() bool { return os.Getenv("ARTEX_ENABLE_UPDATES") == "1" }
