package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mailpit struct {
	t        *testing.T
	smtpAddr string
	apiAddr  string
	cleanup  func() error
	database string
	cmd      *exec.Cmd
	done     <-chan struct{}
}

var mailpitStartLock sync.Mutex

const mailpitStopTimeout = 5 * time.Second

func newMailpit(t *testing.T) (mp *mailpit) {
	t.Helper()
	mailpitStartLock.Lock()
	defer mailpitStartLock.Unlock()

	addrs, err := findOpenPorts(2)
	require.NoError(t, err, "expected to find open ports for mailpit")
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "expected to find caller")

	var output bytes.Buffer
	cmdpath := filepath.Join(filepath.Dir(file), "../../../bin/tools/mailpit")

	// Keep SQLite (including WAL/SHM) and any child-created temporary files
	// together. Unlike t.TempDir, this cleanup can retain storage if the child
	// cannot be reaped, rather than deleting files still in use.
	dir, err := os.MkdirTemp("", "goalert-mailpit-")
	require.NoError(t, err, "expected to create mailpit storage")
	database := filepath.Join(dir, "mailpit.db")
	cmd := exec.Command(cmdpath, "-s", addrs[0], "-l", addrs[1], "--allow-internal-http-requests", "--database", database)
	cmd.Env = append(os.Environ(), "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir)
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.WaitDelay = mailpitStopTimeout
	done := make(chan struct{})
	var waitErr error // Read only after done closes, including output/ProcessState.
	t.Cleanup(func() {
		if cmd.Process != nil {
			select {
			case <-done:
			default:
				t.Errorf("mailpit has not been reaped; retaining storage: %s", dir)
				return
			}
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove mailpit storage: %v", err)
		}
	})
	require.NoError(t, cmd.Start(), "expected to start mailpit")

	cleanup := sync.OnceValue(func() error {
		select {
		case <-done:
			return waitErr
		default:
		}
		// Mailpit handles Interrupt by closing its database before exiting.
		if err := cmd.Process.Signal(os.Interrupt); err == nil {
			timer := time.NewTimer(mailpitStopTimeout)
			defer timer.Stop()
			select {
			case <-done:
				return waitErr
			case <-timer.C:
			}
		} else if !errors.Is(err, os.ErrProcessDone) {
			t.Logf("mailpit interrupt unavailable; forcing shutdown: %v", err)
		}
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill mailpit: %w", err)
		}
		timer := time.NewTimer(mailpitStopTimeout)
		defer timer.Stop()
		select {
		case <-done:
			t.Logf("mailpit forced shutdown reaped: %v", waitErr)
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				return nil // A forced kill is expected to have a nonzero exit.
			}
			return waitErr
		case <-timer.C:
			return fmt.Errorf("mailpit did not finish Wait within %s after kill", mailpitStopTimeout)
		}
	})
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("stop mailpit: %v", err)
		}
		if t.Failed() {
			select {
			case <-done:
				t.Log(output.String())
			default:
				// The output writer may still be running; do not race with it.
			}
		}
	})
	go func() {
		waitErr = cmd.Wait() // The sole reaper, also observes early startup exit.
		close(done)
	}()

	mp = &mailpit{
		t:        t,
		smtpAddr: addrs[0],
		apiAddr:  addrs[1],
		cleanup:  cleanup,
		database: database,
		cmd:      cmd,
		done:     done,
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			t.Fatalf("mailpit exited before readiness: %v\n%s", waitErr, output.String())
		case <-timer.C:
			t.Fatal("expected to find mailpit listening on ports")
		case <-ticker.C:
			if isListening(addrs[0]) && isListening(addrs[1]) {
				return mp
			}
		}
	}
}

func doJSON(t *testing.T, method, url string, reqBody, respBody any) {
	t.Helper()

	var data []byte
	if reqBody != nil {
		var err error
		data, err = json.Marshal(reqBody)
		require.NoError(t, err, "expected to marshal request")
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	require.NoError(t, err, "expected to create request")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "expected to send request")
	data, err = io.ReadAll(resp.Body)
	require.NoError(t, err, "expected to read response")
	require.Equalf(t, http.StatusOK, resp.StatusCode, "expected status OK; data=\n%s", string(data))
	if respBody == nil {
		return
	}
	require.NoErrorf(t, json.Unmarshal(data, respBody), "expected to unmarshal response from:\n%s", string(data))
}

func (m *mailpit) UnreadMessages() []emailMessage {
	m.t.Helper()

	var body struct {
		Messages []struct {
			To      []mail.Address
			Snippet string
		}
	}
	doJSON(m.t, "GET", "http://"+m.apiAddr+"/api/v1/search?query=is:unread", nil, &body)

	var result []emailMessage
	for _, msg := range body.Messages {
		var addrs []string
		for _, p := range msg.To {
			addrs = append(addrs, p.Address)
		}
		result = append(result, emailMessage{address: addrs, body: msg.Snippet})
	}

	return result
}

// ReadMessage will return true if an unread message was found and matched the keywords, marking it as read in the process.
func (m *mailpit) ReadMessage(to string, keywords ...string) bool {
	quotedKeywords := make([]string, len(keywords))
	for i, k := range keywords {
		quotedKeywords[i] = strconv.Quote(k)
	}
	query := fmt.Sprintf("is:unread to:%s %s", strconv.Quote(to), strings.Join(quotedKeywords, " "))

	var body struct {
		Messages []struct{ ID string }
	}
	doJSON(m.t, "GET", "http://"+m.apiAddr+"/api/v1/search?query="+url.QueryEscape(query), nil, &body)

	if len(body.Messages) == 0 {
		return false
	}

	var reqBody struct {
		IDs  []string
		Read bool
	}
	reqBody.IDs = append(reqBody.IDs, body.Messages[0].ID) // only read the first message
	reqBody.Read = true

	doJSON(m.t, http.MethodPut, "http://"+m.apiAddr+"/api/v1/messages", reqBody, nil)

	return true
}
