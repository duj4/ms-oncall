package harness

import (
	"encoding/json"
	"io"
	"strings"
	"time"
)

type expectedBackendError struct {
	substring string
	matched   chan struct{}
}

func (h *Harness) shouldIgnoreBackendError(msg string) bool {
	h.mx.Lock()
	defer h.mx.Unlock()

	for i, expected := range h.expectedBackendErrors {
		if !strings.Contains(msg, expected.substring) {
			continue
		}
		copy(h.expectedBackendErrors[i:], h.expectedBackendErrors[i+1:])
		h.expectedBackendErrors[len(h.expectedBackendErrors)-1] = nil
		h.expectedBackendErrors = h.expectedBackendErrors[:len(h.expectedBackendErrors)-1]
		close(expected.matched)
		return true
	}
	for _, substring := range h.ignoreErrors {
		if strings.Contains(msg, substring) {
			return true
		}
	}
	return false
}

// ExpectBackendError allows exactly one backend error containing substr and
// returns a function that waits for that expectation to be consumed.
func (h *Harness) ExpectBackendError(substr string) func() {
	h.t.Helper()
	expected := &expectedBackendError{substring: substr, matched: make(chan struct{})}
	h.mx.Lock()
	h.expectedBackendErrors = append(h.expectedBackendErrors, expected)
	h.mx.Unlock()

	return func() {
		h.t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-expected.matched:
			return
		case <-timer.C:
		}

		h.mx.Lock()
		pending := false
		for i, candidate := range h.expectedBackendErrors {
			if candidate != expected {
				continue
			}
			copy(h.expectedBackendErrors[i:], h.expectedBackendErrors[i+1:])
			h.expectedBackendErrors[len(h.expectedBackendErrors)-1] = nil
			h.expectedBackendErrors = h.expectedBackendErrors[:len(h.expectedBackendErrors)-1]
			pending = true
			break
		}
		h.mx.Unlock()
		if pending {
			h.t.Errorf("expected backend error containing %q", substr)
			return
		}

		// The log watcher consumed the expectation immediately before the timer
		// fired and will close matched after removing it.
		<-expected.matched
	}
}

func (h *Harness) watchBackendLogs(r io.Reader) {
	dec := json.NewDecoder(r)
	var entry struct {
		Error        string
		Message      string `json:"msg"`
		Source       string
		Level        string
		SQL          string
		ProviderType string
		URL          string
	}

	h.IgnoreErrorsWith("rotation advanced late")

	var err error
	for {
		var raw json.RawMessage
		err = dec.Decode(&raw)
		if err != nil {
			break
		}

		err = json.Unmarshal(raw, &entry)
		if err != nil {
			break
		}

		if h.shouldIgnoreBackendError(entry.Error) {
			entry.Level = "ignore[" + entry.Level + "]"
		}
		if entry.Level == "error" || entry.Level == "fatal" {
			if entry.SQL != "" {
				// ignore printed SQL errors
				continue
			}
			h.t.Errorf("Backend: %s(%s) %s: %s\n%s", strings.ToUpper(entry.Level), entry.Source, entry.Error, entry.Message, string(raw))
			continue
		} else {
			h.t.Logf("Backend: %s %s", strings.ToUpper(entry.Level), entry.Message)
		}
	}
	if h.isClosing() {
		return
	}
	data := make([]byte, 32768)
	n, _ := dec.Buffered().Read(data)
	nx, _ := r.Read(data[n:])
	if n+nx > 0 {
		h.t.Logf("Buffered: %s", string(data[:n+nx]))
	}

	h.t.Errorf("failed to read/parse JSON logs: %v", err)
}
