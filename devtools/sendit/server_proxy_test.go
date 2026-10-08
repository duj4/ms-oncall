package sendit

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each child starts with a fresh ProxyFromEnvironment cache. Loopback traffic
// keeps its normal proxy policy; the virtual host must bypass only that resolver.
func TestServerVirtualSessionProxy(t *testing.T) {
	if os.Getenv("SENDIT_PROXY_TEST_CHILD") == "1" {
		testVirtualSessionProxy(t)
		return
	}

	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)

	for _, mode := range []string{"no-proxy", "HTTP_PROXY", "NO_PROXY", "inherited-proxy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServerVirtualSessionProxy$", "-test.timeout=20s", "-test.v")
			// Remove cached-environment ambiguity and credentials from the child fixture.
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				switch strings.ToUpper(key) {
				case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD", "SENDIT_PROXY_TEST_CHILD", "SENDIT_EXPECT_PROXY":
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "SENDIT_PROXY_TEST_CHILD=1", "SENDIT_EXPECT_PROXY="+mode)
			if mode != "no-proxy" {
				cmd.Env = append(cmd.Env, "HTTP_PROXY="+proxy.URL, "HTTPS_PROXY="+proxy.URL)
			}
			if mode == "NO_PROXY" {
				cmd.Env = append(cmd.Env, "NO_PROXY=localhost,127.0.0.1,.invalid")
			}
			if mode == "inherited-proxy" {
				cmd.Env = append(cmd.Env, "http_proxy="+proxy.URL, "https_proxy="+proxy.URL)
			}
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "isolated %s regression: %s", mode, output)
			t.Logf("%s", output)
			assert.Zero(t, proxyRequests.Load(), "virtual requests must never reach the HTTP proxy")
		})
	}
}

func testVirtualSessionProxy(t *testing.T) {
	t.Helper()
	defaultTransport := http.DefaultTransport.(*http.Transport)
	hadDefaultProxy := defaultTransport.Proxy != nil
	defaultClientTransport := http.DefaultClient.Transport
	s := NewServer([]byte("proxy-regression-test-secret"), "/")
	transport := s.proxy.Transport.(*http.Transport)
	assert.Nil(t, transport.Proxy, "only the virtual-session transport must ignore HTTP_PROXY")
	assert.Equal(t, hadDefaultProxy, defaultTransport.Proxy != nil, "global proxy policy must remain unchanged")
	assert.Equal(t, defaultClientTransport, http.DefaultClient.Transport, "default client transport must remain unchanged")

	sess, err := s.newSession("server-prefix")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	clientConn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })
	serverConn, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	peerStream := NewStream()
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = serverConn.Close()
		_ = clientConn.Close()
		sess.End()
		_ = peerStream.Close()
	})
	// Both Stream peers perform the SYN/SYNACK exchange before yamux starts.
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	pipeDone := make(chan struct{})
	var pipeErr error
	go func() {
		pipeErr = sess.stream.SetPipe(serverConn, serverConn)
		close(pipeDone)
	}()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
		if !waitProxyWorker(pipeDone) {
			t.Error("stream handshake worker did not complete")
		}
	})
	require.NoError(t, peerStream.SetPipe(clientConn, clientConn))
	require.True(t, waitProxyWorker(pipeDone), "stream handshake must complete")
	require.NoError(t, pipeErr)
	require.NoError(t, serverConn.SetDeadline(time.Time{}))
	require.NoError(t, clientConn.SetDeadline(time.Time{}))
	peer, err := yamux.Client(peerStream, yamux.DefaultConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })

	// Exercise the real stream initialization and ping, with an owned bounded join.
	initialized := make(chan struct{})
	go func() {
		sess.start.Do(sess.init)
		close(initialized)
	}()
	t.Cleanup(func() {
		_ = peer.Close()
		if !waitProxyWorker(initialized) {
			t.Error("session initializer did not complete")
		}
	})
	require.True(t, waitProxyWorker(initialized), "session initialization must complete")
	select {
	case <-sess.readyCh:
	default:
		t.Fatal("virtual session must be ready")
	}

	resolvedProxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "http", Host: sess.ID}})
	require.NoError(t, err)
	if os.Getenv("SENDIT_EXPECT_PROXY") == "no-proxy" {
		assert.Nil(t, resolvedProxy)
	} else {
		require.NotNil(t, resolvedProxy, "the environment resolver must select a proxy for this virtual host")
		_, err := s.DialContext(context.Background(), "tcp", net.JoinHostPort(resolvedProxy.Hostname(), resolvedProxy.Port()))
		var addrErr *net.AddrError
		require.ErrorAs(t, err, &addrErr, "a proxy address is not a registered session and cannot be dialed")
	}
	_, err = s.DialContext(context.Background(), "tcp", "external.invalid:80")
	var addrErr *net.AddrError
	require.ErrorAs(t, err, &addrErr, "arbitrary network hosts must remain rejected")

	type backendRequest struct{ path, query, authorization string }
	requests := make(chan backendRequest, 1)
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case requests <- backendRequest{req.URL.Path, req.URL.RawQuery, req.Header.Get("Authorization")}:
		default:
		}
		_, _ = io.WriteString(w, "Hello, world!")
	})}
	served := make(chan error, 1)
	go func() { served <- backend.Serve(peer) }()
	t.Cleanup(func() {
		_ = backend.Close()
		select {
		case err := <-served:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !peer.IsClosed() {
				t.Errorf("backend serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("backend worker did not complete")
		}
	})

	dialed := make(chan string, 1)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case dialed <- addr:
		default:
		}
		return s.DialContext(ctx, network, addr)
	}
	public := httptest.NewServer(s)
	t.Cleanup(public.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(public.URL + "/server-prefix/test?message=test")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, world!", string(body))
	select {
	case addr := <-dialed:
		assert.Equal(t, net.JoinHostPort(sess.ID, "80"), addr, "dialer must receive the virtual session address")
	default:
		t.Error("virtual session dialer was not called")
	}
	select {
	case req := <-requests:
		assert.Equal(t, "/server-prefix/test", req.path)
		assert.Equal(t, "message=test", req.query)
		assert.Empty(t, req.authorization)
	default:
		t.Error("backend did not receive the tunneled request")
	}
}

func waitProxyWorker(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}
