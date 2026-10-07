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
	defer close(h.logsDone)
	dec := json.NewDecoder(r)

	h.IgnoreErrorsWith("rotation advanced late")

	for {
		var raw json.RawMessage
		err := dec.Decode(&raw)
		if err != nil {
			// Decoder is unrecoverable; must keep draining the pipe so backend
			// writers don't block forever. Without this, a parse failure here
			// can deadlock app startup/shutdown.
			if !h.isClosing() {
				h.t.Errorf("failed to read JSON logs: %v", err)
			}
			_, _ = io.Copy(io.Discard, r)
			return
		}

		// Error is json.RawMessage because some log entries emit it as an object
		// (e.g. structured errors) rather than a string.
		var entry struct {
			Error        json.RawMessage
			Message      string `json:"msg"`
			Source       string
			Level        string
			SQL          string
			ProviderType string
			URL          string
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			h.t.Logf("Backend: failed to parse log entry: %v\n%s", err, string(raw))
			continue
		}

		errorMessage := string(entry.Error)
		var stringError string
		if json.Unmarshal(entry.Error, &stringError) == nil {
			errorMessage = stringError
		}
		if h.shouldIgnoreBackendError(errorMessage) {
			entry.Level = "ignore[" + entry.Level + "]"
		}
		if entry.Level == "error" || entry.Level == "fatal" {
			if entry.SQL != "" {
				// ignore printed SQL errors
				continue
			}
			h.t.Errorf("Backend: %s(%s) %s: %s\n%s", strings.ToUpper(entry.Level), entry.Source, string(entry.Error), entry.Message, string(raw))
			continue
		} else {
			h.t.Logf("Backend: %s %s", strings.ToUpper(entry.Level), entry.Message)
		}
	}
}
