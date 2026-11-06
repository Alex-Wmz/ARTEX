package selfupdate

import "testing"

func TestLocalSecurityUpdatesRequireExplicitOptIn(t *testing.T) {
	for _, value := range []string{"", "0", "false", "true", "1"} {
		t.Setenv("ARTEX_ENABLE_UPDATES", value)
		if Enabled() != (value == "1") {
			t.Fatalf("unexpected update policy for %q", value)
		}
	}
}
