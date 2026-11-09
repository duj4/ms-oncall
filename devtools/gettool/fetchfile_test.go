package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func fetchTestCache(t *testing.T) {
	t.Helper()
	old := cacheDir
	cacheDir = t.TempDir()
	t.Cleanup(func() { cacheDir = old })
}

func testFetcher(client *http.Client) fileFetcher {
	return fileFetcher{client, time.Second, 3 * time.Second, time.Millisecond}
}

func fetchContents(t *testing.T, f fileFetcher, ctx context.Context, u, want string) {
	t.Helper()
	fd, n, err := f.fetch(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	b, err := io.ReadAll(fd)
	if err != nil || string(b) != want || n != int64(len(want)) {
		t.Fatalf("contents=%q size=%d error=%v", b, n, err)
	}
}

func requireCacheEmpty(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cache entries=%v error=%v", entries, err)
	}
}

func TestFetchHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		wantErr  bool
	}{
		{"first200", []int{200}, false},
		{"504-504-200", []int{504, 504, 200}, false},
		{"502-503-200", []int{502, 503, 200}, false},
		{"exhausted504", []int{504, 504, 504}, true},
		{"404", []int{404}, true},
		{"400", []int{400}, true},
		{"401", []int{401}, true},
		{"403", []int{403}, true},
		{"429", []int{429}, true},
		{"500", []int{500}, true},
		{"204", []int{204}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetchTestCache(t)
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := int(attempts.Add(1)) - 1
				if i >= len(tc.statuses) {
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(tc.statuses[i])
				_, _ = io.WriteString(w, "synthetic tool")
			}))
			defer srv.Close()
			f := testFetcher(srv.Client())
			if tc.wantErr {
				fd, n, err := f.fetch(context.Background(), srv.URL)
				if err == nil || fd != nil || n != 0 {
					t.Fatalf("fd=%v size=%d error=%v", fd, n, err)
				}
				want := fmt.Sprintf("attempt %d/3: HTTP %d", len(tc.statuses), tc.statuses[len(tc.statuses)-1])
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("final error %q missing %q", err, want)
				}
				requireCacheEmpty(t)
			} else {
				fetchContents(t, f, context.Background(), srv.URL, "synthetic tool")
				// Cache hit must work even after the server is closed.
				srv.Close()
				fetchContents(t, f, context.Background(), srv.URL, "synthetic tool")
				entries, err := os.ReadDir(cacheDir)
				if err != nil || len(entries) != 1 || entries[0].Name() != hash256(srv.URL)+".data" {
					t.Fatalf("entries=%v error=%v", entries, err)
				}
			}
			if int(attempts.Load()) != len(tc.statuses) {
				t.Fatalf("attempts=%d", attempts.Load())
			}
		})
	}
}

func TestFetchTruncatedBodyAndRecovery(t *testing.T) {
	fetchTestCache(t)
	var attempts atomic.Int32
	var recover atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if !recover.Load() {
			w.Header().Set("Content-Length", "100")
		}
		_, _ = io.WriteString(w, "partial")
	}))
	defer srv.Close()
	f := testFetcher(srv.Client())
	fd, _, err := f.fetch(context.Background(), srv.URL)
	if fd != nil || !errors.Is(err, io.ErrUnexpectedEOF) || attempts.Load() != 3 {
		t.Fatalf("fd=%v err=%v attempts=%d", fd, err, attempts.Load())
	}
	requireCacheEmpty(t)
	recover.Store(true)
	fetchContents(t, f, context.Background(), srv.URL, "partial")
	if attempts.Load() != 4 {
		t.Fatalf("attempts=%d", attempts.Load())
	}
}

func TestFetchErrorThenSuccess(t *testing.T) {
	fetchTestCache(t)
	var available atomic.Bool
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if !available.Load() {
			w.WriteHeader(504)
			return
		}
		_, _ = io.WriteString(w, "complete")
	}))
	defer srv.Close()
	f := testFetcher(srv.Client())
	if _, _, err := f.fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("expected exhausted 504")
	}
	requireCacheEmpty(t)
	available.Store(true)
	fetchContents(t, f, context.Background(), srv.URL, "complete")
	available.Store(false)
	fetchContents(t, f, context.Background(), srv.URL, "complete")
	if attempts.Load() != 4 {
		t.Fatalf("valid cache was requested again: %d", attempts.Load())
	}
}

func TestFetchCancellation(t *testing.T) {
	for _, phase := range []string{"headers", "body", "backoff", "before-request"} {
		t.Run(phase, func(t *testing.T) {
			fetchTestCache(t)
			started := make(chan struct{}, 1)
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if phase == "backoff" {
					w.WriteHeader(504)
				} else if phase == "body" {
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "part")
					w.(http.Flusher).Flush()
				}
				started <- struct{}{}
				if phase != "backoff" {
					<-r.Context().Done()
				}
			}))
			defer srv.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := testFetcher(srv.Client())
			f.backoff = time.Second
			if phase == "before-request" {
				cancel()
			} else {
				go func() { <-started; cancel() }()
			}
			start := time.Now()
			fd, _, err := f.fetch(ctx, srv.URL)
			if fd != nil || !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
				t.Fatalf("fd=%v error=%v elapsed=%v", fd, err, time.Since(start))
			}
			want := int32(1)
			if phase == "before-request" {
				want = 0
			}
			if attempts.Load() != want {
				t.Fatalf("attempts=%d", attempts.Load())
			}
			requireCacheEmpty(t)
		})
	}
}

func TestFetchTimeoutBounds(t *testing.T) {
	for _, phase := range []string{"attempt", "total", "backoff", "body"} {
		t.Run(phase, func(t *testing.T) {
			fetchTestCache(t)
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if phase == "backoff" {
					w.WriteHeader(504)
					return
				}
				if phase == "body" {
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "part")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer srv.Close()
			f := testFetcher(srv.Client())
			f.attemptTimeout = 30 * time.Millisecond
			if phase == "total" {
				f.totalTimeout = 50 * time.Millisecond
			}
			if phase == "backoff" {
				f.totalTimeout, f.backoff = 50*time.Millisecond, time.Second
			}
			start := time.Now()
			fd, _, err := f.fetch(context.Background(), srv.URL)
			if fd != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
				t.Fatalf("fd=%v err=%v elapsed=%v", fd, err, time.Since(start))
			}
			if (phase == "attempt" || phase == "body") && attempts.Load() != 3 {
				t.Fatalf("attempts=%d", attempts.Load())
			}
			if phase == "backoff" && attempts.Load() != 1 {
				t.Fatalf("backoff ignored total deadline: attempts=%d", attempts.Load())
			}
			requireCacheEmpty(t)
		})
	}
}

type fetchRoundTrip func(*http.Request) (*http.Response, error)

func (f fetchRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestFetchBodiesClosedAndLogsSanitized(t *testing.T) {
	fetchTestCache(t)
	var bodies []*trackedBody
	client := &http.Client{Transport: fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
		body := &trackedBody{Reader: strings.NewReader("complete")}
		bodies = append(bodies, body)
		code := 504
		if len(bodies) == 3 {
			code = 200
		}
		return &http.Response{StatusCode: code, Body: body, ContentLength: 8, Header: make(http.Header)}, nil
	})}
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	fetchContents(t, testFetcher(client), context.Background(), "https://example.invalid/tool?token=synthetic-secret", "complete")
	for i, body := range bodies {
		if !body.closed {
			t.Fatalf("attempt %d body left open", i+1)
		}
	}
	client.Transport = fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: "https://example.invalid/?token=synthetic-secret", Err: io.ErrUnexpectedEOF}
	})
	_, _, err := testFetcher(client).fetch(context.Background(), "https://example.invalid/other")
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(logs.String(), "synthetic-secret") {
		t.Fatalf("unsafe failure/log: %v / %s", err, &logs)
	}
	if !strings.Contains(logs.String(), "attempt 3/3") || !strings.Contains(logs.String(), "HTTP 504") {
		t.Fatalf("missing diagnostic: %s", &logs)
	}
}

func TestFetchFailedBodyClosed(t *testing.T) {
	fetchTestCache(t)
	var bodies []*trackedBody
	client := &http.Client{Transport: fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
		body := &trackedBody{Reader: io.MultiReader(strings.NewReader("partial"), failingReader{})}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: 200, Body: body, ContentLength: 100}, nil
	})}
	if _, _, err := testFetcher(client).fetch(context.Background(), "https://example.invalid/tool"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	for _, b := range bodies {
		if !b.closed {
			t.Fatal("failed response body left open")
		}
	}
	requireCacheEmpty(t)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestFetchConcurrentCacheWinnerPreserved(t *testing.T) {
	for _, status := range []int{200, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fetchTestCache(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := "http://" + r.Host + r.URL.Path
				if err := os.WriteFile(filepath.Join(cacheDir, hash256(u)+".data"), []byte("existing complete"), 0o600); err != nil {
					t.Error(err)
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "new complete")
			}))
			defer srv.Close()
			f := testFetcher(srv.Client())
			u := srv.URL + "/"
			fd, _, err := f.fetch(context.Background(), u)
			if status == 200 {
				if err != nil {
					t.Fatal(err)
				}
				fd.Close()
			} else if err == nil {
				t.Fatal("expected 504 failure")
			}
			srv.Close()
			fetchContents(t, f, context.Background(), u, "existing complete")
			entries, err := os.ReadDir(cacheDir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("staging file leaked: %v %v", entries, err)
			}
		})
	}
}

func TestFetchArchiveIntegrity(t *testing.T) {
	var zipBytes bytes.Buffer
	zw := zip.NewWriter(&zipBytes)
	entry, err := zw.CreateHeader(&zip.FileHeader{Name: "bun-linux-x64/bun", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(entry, "synthetic binary")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var gzBytes bytes.Buffer
	gw := gzip.NewWriter(&gzBytes)
	_, _ = io.WriteString(gw, "synthetic tar bytes")
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	corruptZip := append([]byte(nil), zipBytes.Bytes()...)
	corruptZip[bytes.Index(corruptZip, []byte("synthetic binary"))] ^= 0xff
	corruptGzip := append([]byte(nil), gzBytes.Bytes()...)
	corruptGzip[len(corruptGzip)-8] ^= 0xff
	for _, tc := range []struct {
		name string
		body []byte
		bad  bool
	}{
		{"valid.zip", zipBytes.Bytes(), false},
		{"invalid.zip", []byte("not a zip"), true},
		{"crc.zip", corruptZip, true},
		{"valid.tar.gz", gzBytes.Bytes(), false},
		{"crc.tar.gz", corruptGzip, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetchTestCache(t)
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()
			u := srv.URL + "/" + tc.name
			if tc.bad {
				if _, _, err := testFetcher(srv.Client()).fetch(context.Background(), u); err == nil {
					t.Fatal("corrupt archive accepted")
				}
				requireCacheEmpty(t)
			} else {
				fetchContents(t, testFetcher(srv.Client()), context.Background(), u, string(tc.body))
			}
			if attempts.Load() != 1 {
				t.Fatalf("deterministic archive result retried: %d", attempts.Load())
			}
		})
	}
}

func TestFetchRedirectAndNoCache(t *testing.T) {
	fetchTestCache(t)
	cacheDir = ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/tool", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "complete")
	}))
	defer srv.Close()
	f := testFetcher(srv.Client())
	fd, n, err := f.fetch(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(fd)
	name := fd.Name()
	if err != nil || string(b) != "complete" || n != 8 {
		t.Fatalf("contents=%q size=%d error=%v", b, n, err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(name) // Required on platforms without open-file unlink.
}

func TestRetryTransportClassification(t *testing.T) {
	for _, err := range []error{context.Canceled, os.ErrPermission, &os.PathError{Op: "write", Path: "synthetic", Err: syscall.ECONNRESET}} {
		if retryTransport(err) {
			t.Fatalf("local/permanent error retried: %v", err)
		}
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, context.DeadlineExceeded} {
		if !retryTransport(err) {
			t.Fatalf("temporary transport error not retried: %v", err)
		}
	}
}

func TestFetchSimultaneousDownloads(t *testing.T) {
	fetchTestCache(t)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		started <- struct{}{}
		select {
		case <-release:
			_, _ = fmt.Fprintf(w, "complete-%d", n)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	f := testFetcher(srv.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			fd, n, err := f.fetch(ctx, srv.URL)
			if err == nil {
				b, readErr := io.ReadAll(fd)
				closeErr := fd.Close()
				if readErr != nil || closeErr != nil || n != 10 || (string(b) != "complete-1" && string(b) != "complete-2") {
					err = fmt.Errorf("incomplete result: %q %d %v %v", b, n, readErr, closeErr)
				}
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 1 || requests.Load() != 2 {
		t.Fatalf("entries=%v requests=%d error=%v", entries, requests.Load(), err)
	}
}

func TestFetchFileDefaultWrapper(t *testing.T) {
	fetchTestCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "complete")
	}))
	defer srv.Close()
	fd, n, err := fetchFile(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	b, err := io.ReadAll(fd)
	if err != nil || n != 8 || string(b) != "complete" {
		t.Fatalf("contents=%q size=%d error=%v", b, n, err)
	}
}

type zipCRCMember struct {
	name       string
	body       []byte
	crc        uint32
	descriptor bool
}

// CreateRaw preserves the supplied CRC even when it is zero or incorrect.
// CreateHeader would calculate it and normally add a data descriptor instead.
func zipCRCFixture(t *testing.T, members ...zipCRCMember) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, m := range members {
		var flags uint16
		if m.descriptor {
			flags = 8
		}
		f, err := w.CreateRaw(&zip.FileHeader{
			Name: m.name, Method: zip.Store, Flags: flags, CRC32: m.crc,
			CompressedSize64: uint64(len(m.body)), UncompressedSize64: uint64(len(m.body)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil || len(z.File) != len(members) {
		t.Fatalf("fixture members: %v error=%v", z, err)
	}
	for i, m := range members {
		f := z.File[i]
		if f.Name != m.name || f.CRC32 != m.crc || (f.Flags&8 != 0) != m.descriptor {
			t.Fatalf("fixture member %d: %+v", i, f.FileHeader)
		}
		t.Logf("member=%s descriptor=%t declared=%08x actual=%08x", m.name, m.descriptor, m.crc, crc32.ChecksumIEEE(m.body))
	}
	return b.Bytes()
}

func requireZIPCache(t *testing.T, u string, want []byte) {
	t.Helper()
	name := hash256(u) + ".data"
	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("cache entries=%v error=%v", entries, err)
	}
	b, err := os.ReadFile(filepath.Join(cacheDir, name))
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("cache bytes differ: size=%d error=%v", len(b), err)
	}
}

func TestFetchZIPMemberCRC(t *testing.T) {
	payload := []byte("synthetic binary with nonzero CRC") // Exact CI2-R1 F01 payload.
	actual := crc32.ChecksumIEEE(payload)
	zero := []byte{0x9d, 0x0a, 0xd9, 0x6d} // Nonempty content with IEEE CRC32 zero.
	if actual != 0x963db763 || crc32.ChecksumIEEE(zero) != 0 {
		t.Fatal("unexpected fixture CRC")
	}
	good := zipCRCMember{"first", payload, actual, false}
	bad := zipCRCMember{"later", payload, 0, false}
	for _, tc := range []struct {
		name    string
		members []zipCRCMember
		bad     bool
	}{
		{"zero-declared-nonzero-actual", []zipCRCMember{bad}, true},
		{"zero-declared-zero-actual", []zipCRCMember{{"zero", zero, 0, false}}, false},
		{"empty-zero-crc", []zipCRCMember{{"empty", nil, 0, false}}, false},
		{"nonzero-wrong-crc", []zipCRCMember{{"wrong", payload, actual ^ 1, false}}, true},
		{"descriptor-wrong-crc", []zipCRCMember{{"descriptor", payload, actual ^ 1, true}}, true},
		{"later-member-zero-crc", []zipCRCMember{good, bad}, true},
		{"all-members-correct", []zipCRCMember{good, {"zero", zero, 0, false}, {"descriptor", payload, actual, true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetchTestCache(t)
			body := zipCRCFixture(t, tc.members...)
			u := "https://example.invalid/" + tc.name + ".zip"
			requests := 0
			var bodies []*trackedBody
			f := testFetcher(&http.Client{Transport: fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
				requests++
				b := &trackedBody{Reader: bytes.NewReader(body)}
				bodies = append(bodies, b)
				return &http.Response{StatusCode: 200, Body: b, ContentLength: int64(len(body)), Header: make(http.Header)}, nil
			})})
			if tc.bad {
				fd, n, err := f.fetch(context.Background(), u)
				if fd != nil {
					fd.Close()
				}
				if fd != nil || n != 0 || !errors.Is(err, zip.ErrChecksum) || requests != 1 {
					t.Fatalf("fd=%v size=%d error=%v requests=%d", fd, n, err, requests)
				}
				requireCacheEmpty(t) // Neither .data nor staging may remain.
				// A subsequent correct response must work for the very same URL.
				body = zipCRCFixture(t, good)
			}
			fetchContents(t, f, context.Background(), u, string(body))
			wantRequests := 1
			if tc.bad {
				wantRequests = 2
			}
			if requests != wantRequests {
				t.Fatalf("download requests=%d want=%d", requests, wantRequests)
			}
			requireZIPCache(t, u, body)
			fetchContents(t, f, context.Background(), u, string(body))
			if requests != wantRequests {
				t.Fatalf("cache hit requested HTTP: %d", requests)
			}
			for _, b := range bodies {
				if !b.closed {
					t.Fatal("response body left open")
				}
			}
		})
	}
}

func TestFetchZIPCRCDoesNotReplaceCache(t *testing.T) {
	payload := []byte("synthetic binary with nonzero CRC")
	for _, winner := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent-winner=%t", winner), func(t *testing.T) {
			fetchTestCache(t)
			good := zipCRCFixture(t, zipCRCMember{"tool", payload, crc32.ChecksumIEEE(payload), false})
			bad := zipCRCFixture(t, zipCRCMember{"tool", payload, 0, false})
			u := "https://example.invalid/cache-preserved.zip"
			target := filepath.Join(cacheDir, hash256(u)+".data")
			publish := func() {
				t.Helper()
				if err := os.WriteFile(target, good, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			requests := 0
			f := testFetcher(&http.Client{Transport: fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
				requests++
				publish() // Another downloader has published since the cache miss.
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(bad)), ContentLength: int64(len(bad))}, nil
			})})
			if winner {
				fd, n, err := f.fetch(context.Background(), u)
				if fd != nil {
					fd.Close()
				}
				if fd != nil || n != 0 || !errors.Is(err, zip.ErrChecksum) || requests != 1 {
					t.Fatalf("corrupt download: fd=%v size=%d error=%v requests=%d", fd, n, err, requests)
				}
			} else {
				publish()
			}
			fetchContents(t, f, context.Background(), u, string(good))
			requireZIPCache(t, u, good)
			wantRequests := 0
			if winner {
				wantRequests = 1
			}
			if requests != wantRequests {
				t.Fatalf("requests=%d want=%d", requests, wantRequests)
			}
		})
	}
}

func TestFetchZIPCRCNoCache(t *testing.T) {
	fetchTestCache(t)
	cacheDir = ""
	before, err := filepath.Glob(filepath.Join(os.TempDir(), "gettool-*.download"))
	if err != nil {
		t.Fatal(err)
	}
	bad := zipCRCFixture(t, zipCRCMember{"tool", []byte("synthetic binary with nonzero CRC"), 0, false})
	requests := 0
	body := &trackedBody{Reader: bytes.NewReader(bad)}
	f := testFetcher(&http.Client{Transport: fetchRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: body, ContentLength: int64(len(bad))}, nil
	})})
	fd, n, err := f.fetch(context.Background(), "https://example.invalid/no-cache.zip")
	if fd != nil {
		fd.Close()
	}
	if fd != nil || n != 0 || !errors.Is(err, zip.ErrChecksum) || requests != 1 || !body.closed {
		t.Fatalf("fd=%v size=%d error=%v requests=%d closed=%t", fd, n, err, requests, body.closed)
	}
	after, err := filepath.Glob(filepath.Join(os.TempDir(), "gettool-*.download"))
	if err != nil || strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("temporary download leaked: before=%v after=%v error=%v", before, after, err)
	}
}
