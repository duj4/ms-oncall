package harness

import "testing"

func TestExpectBackendErrorIsSingleUse(t *testing.T) {
	h := &Harness{t: t}
	wait := h.ExpectBackendError("sql: no rows in result set")

	if !h.shouldIgnoreBackendError("query failed: sql: no rows in result set") {
		t.Fatal("expected first matching backend error to be ignored")
	}
	wait()

	if h.shouldIgnoreBackendError("later failure: sql: no rows in result set") {
		t.Fatal("expected later matching backend error to retain normal error sensitivity")
	}
}
