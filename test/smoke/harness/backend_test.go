package harness

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWatchBackendLogsExpectedStringAndStructuredErrors(t *testing.T) {
	for _, test := range []struct {
		name  string
		error any
	}{
		{name: "string with quotes", error: `violates foreign key constraint "test_constraint"`},
		{name: "structured", error: map[string]string{"message": "expected structured failure"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &Harness{t: t, closing: true, logsDone: make(chan struct{})}
			substring := `violates foreign key constraint "test_constraint"`
			if test.name == "structured" {
				substring = "expected structured failure"
			}
			wait := h.ExpectBackendError(substring)
			entry, err := json.Marshal(map[string]any{"level": "error", "error": test.error})
			if err != nil {
				t.Fatal(err)
			}
			h.watchBackendLogs(strings.NewReader(string(entry)))
			wait()
			select {
			case <-h.logsDone:
			default:
				t.Fatal("log watcher did not signal completion")
			}
			if h.shouldIgnoreBackendError(substring) {
				t.Fatal("stream expectation was not single-use")
			}
		})
	}
}

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
