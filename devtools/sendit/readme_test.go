package sendit_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/devtools/sendit"
)

const readmeProcessTimeout = 10 * time.Second

type readmeProcess struct {
	cmd      *exec.Cmd
	reader   *os.File
	ready    chan string
	logDone  chan struct{}
	waitDone chan struct{}
	logErr   error
	waitErr  error
	stopOnce sync.Once
}

func waitReadmeWorker(t *testing.T, name string, done <-chan struct{}) bool {
	t.Helper()
	timer := time.NewTimer(readmeProcessTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		t.Errorf("%s did not complete within %s", name, readmeProcessTimeout)
		return false
	}
}

func (p *readmeProcess) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		kill := func() {
			if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("terminate %s: %v", filepath.Base(p.cmd.Path), err)
			}
		}
		kill()
		if !waitReadmeWorker(t, "process Wait", p.waitDone) {
			// Retry termination before releasing resources if the first attempt failed.
			kill()
			waitReadmeWorker(t, "process Wait after retry", p.waitDone)
		}
		// Closing the reader also releases a log worker if the child kept the pipe open.
		if err := p.reader.Close(); err != nil {
			t.Errorf("close log reader: %v", err)
		}
		if waitReadmeWorker(t, "log worker", p.logDone) && p.logErr != nil && !errors.Is(p.logErr, os.ErrClosed) {
			t.Errorf("read process logs: %v", p.logErr)
		}
	})
}

func startReadmeProcess(t *testing.T, executable, marker string, args ...string) *readmeProcess {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	cmd := exec.Command(executable, args...)
	cmd.Stdout, cmd.Stderr = w, w
	p := &readmeProcess{
		cmd: cmd, reader: r, ready: make(chan string, 1),
		logDone: make(chan struct{}), waitDone: make(chan struct{}),
	}
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		t.Fatalf("start %s: %v", filepath.Base(executable), err)
	}
	t.Cleanup(func() { p.stop(t) })
	go func() {
		defer close(p.logDone)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("%s: %s", filepath.Base(executable), line)
			if strings.Contains(line, marker) {
				select {
				case p.ready <- line:
				default:
				}
			}
		}
		p.logErr = scanner.Err()
	}()
	go func() {
		p.waitErr = cmd.Wait()
		close(p.waitDone)
	}()
	// Only the child retains a writer now; its exit produces EOF for the log reader.
	require.NoError(t, w.Close())
	return p
}

func (p *readmeProcess) waitReady(t *testing.T) string {
	t.Helper()
	timer := time.NewTimer(readmeProcessTimeout)
	defer timer.Stop()
	select {
	case <-p.waitDone:
		t.Fatalf("%s exited before readiness: %v", filepath.Base(p.cmd.Path), p.waitErr)
	case <-p.logDone:
		t.Fatalf("%s log ended before readiness: %v", filepath.Base(p.cmd.Path), p.logErr)
	case <-timer.C:
		t.Fatalf("%s did not signal readiness within %s", filepath.Base(p.cmd.Path), readmeProcessTimeout)
	case line := <-p.ready:
		select {
		case <-p.waitDone:
			t.Fatalf("%s exited at readiness: %v", filepath.Base(p.cmd.Path), p.waitErr)
		default:
		}
		return line
	}
	return ""
}

func buildReadmeCLI(t *testing.T, dir, name string) string {
	t.Helper()
	executable := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", executable, "./cmd/"+name)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "build %s: %s", name, output)
	return executable
}

// TestReadme runs the real README CLIs and validates forwarding through their tunnel.
func TestReadme(t *testing.T) {
	const secret = "testing-secret"
	dir := t.TempDir() // Registered first, so process cleanup runs before removal.
	tokenCLI := buildReadmeCLI(t, dir, "sendit-token")
	serverCLI := buildReadmeCLI(t, dir, "sendit-server")
	clientCLI := buildReadmeCLI(t, dir, "sendit")

	ctx, cancel := context.WithTimeout(context.Background(), readmeProcessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tokenCLI, "-secret", secret)
	var tokenErrors strings.Builder
	cmd.Stderr = &tokenErrors
	tokenData, err := cmd.Output()
	require.NoError(t, err, "generate token: %s", tokenErrors.String())
	token := strings.TrimSpace(string(tokenData))

	var c jwt.RegisteredClaims
	tok, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience(sendit.TokenAudienceAuth), jwt.WithIssuer(sendit.TokenIssuer))
	require.NoError(t, err, "must be valid jwt")
	assert.True(t, tok.Valid, "token must be valid")
	assert.Equal(t, "sendit", c.Issuer)

	server := startReadmeProcess(t, serverCLI, "Listening: ", "-secret", secret, "-addr", "127.0.0.1:0")
	line := server.waitReady(t)
	_, srvAddr, ok := strings.Cut(strings.TrimSpace(line), "Listening: ")
	require.True(t, ok, "must print Listening: <addr>")
	_, _, err = net.SplitHostPort(srvAddr)
	require.NoError(t, err, "must print a valid listening address")

	backendRequests := make(chan string, 1)
	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case backendRequests <- r.URL.Path:
		default:
		}
		_, _ = io.WriteString(w, "Hello, world!")
	}))
	t.Cleanup(testSrv.Close)

	srcURL := fmt.Sprintf("http://%s/server-prefix", srvAddr)
	client := startReadmeProcess(t, clientCLI, "Ready; Forwarding ", "-token", token, srcURL, testSrv.URL)
	client.waitReady(t)

	httpClient := &http.Client{Timeout: readmeProcessTimeout}
	resp, err := httpClient.Get(srcURL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, world!", string(data))
	select {
	case path := <-backendRequests:
		assert.Equal(t, "/server-prefix/test", path)
	default:
		t.Error("backend did not receive the tunneled request")
	}
}
