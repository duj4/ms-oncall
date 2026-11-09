package main

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var errMiss = fmt.Errorf("file not found in cache")

const fetchAttempts = 3

type fileFetcher struct {
	client         *http.Client
	attemptTimeout time.Duration
	totalTimeout   time.Duration
	backoff        time.Duration
}

func hash256(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}

func getCacheFile(url string) (*os.File, int64, error) {
	if cacheDir == "" {
		return nil, 0, errMiss
	}

	fd, err := os.Open(filepath.Join(cacheDir, hash256(url)+".data"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, errMiss
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open cache: %w", err)
	}
	info, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, 0, fmt.Errorf("stat cache: %w", err)
	}
	if !info.Mode().IsRegular() {
		fd.Close()
		return nil, 0, fmt.Errorf("cache entry is not a regular file")
	}
	return fd, info.Size(), nil
}

func mkCacheFile(url string) (*os.File, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return os.CreateTemp(cacheDir, hash256(url)+"-*.tmp")
}

// fetchFile returns a complete download, positioned at offset zero. The caller
// owns the returned file. Default proxy, redirect and TLS verification behavior
// is preserved; request deadlines also cover redirects and response bodies.
func fetchFile(url string) (*os.File, int64, error) {
	f := fileFetcher{http.DefaultClient, 60 * time.Second, 185 * time.Second, time.Second}
	return f.fetch(context.Background(), url)
}

func (f fileFetcher) fetch(ctx context.Context, url string) (*os.File, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, f.totalTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	fd, n, err := getCacheFile(url)
	if err == nil {
		return fd, n, nil
	}
	if !errors.Is(err, errMiss) {
		return nil, 0, err
	}

	for attempt := 1; attempt <= fetchAttempts; attempt++ {
		attemptCtx, stop := context.WithTimeout(ctx, f.attemptTimeout)
		fd, n, retry, err := f.download(attemptCtx, url)
		stop()
		if err == nil {
			return fd, n, nil
		}
		log.Printf("download attempt %d/%d: %v (retryable=%t)", attempt, fetchAttempts, err, retry)
		if ctx.Err() != nil {
			return nil, 0, fmt.Errorf("download stopped after attempt %d/%d: %w", attempt, fetchAttempts, ctx.Err())
		}
		if !retry || attempt == fetchAttempts {
			return nil, 0, fmt.Errorf("download failed after attempt %d/%d: %w", attempt, fetchAttempts, err)
		}
		timer := time.NewTimer(time.Duration(attempt) * f.backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, 0, fmt.Errorf("download backoff: %w", ctx.Err())
		case <-timer.C:
		}
	}
	panic("unreachable")
}

// downloadError retains its cause for errors.Is/As, while keeping URLs, signed
// redirect queries, proxy credentials and response headers out of logs.
type downloadError struct {
	class string
	cause error
}

func (e *downloadError) Error() string { return e.class }
func (e *downloadError) Unwrap() error { return e.cause }

func retryTransport(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return false // A local write failure is not a temporary transport error.
	}
	var netErr net.Error
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()))
}

func (f fileFetcher) download(ctx context.Context, rawURL string) (result *os.File, size int64, retry bool, err error) {
	fail := func(class string, cause error, retry bool) (*os.File, int64, bool, error) {
		if errors.Is(cause, context.Canceled) {
			class = "request canceled"
		} else if errors.Is(cause, context.DeadlineExceeded) {
			class = "request timeout"
		} else if errors.Is(cause, io.ErrUnexpectedEOF) {
			class = "truncated body"
		}
		return nil, 0, retry, &downloadError{class, cause}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fail("invalid request", err, false)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fail("transport failure", err, retryTransport(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		code := resp.StatusCode
		return fail(fmt.Sprintf("HTTP %d", code), nil, code == 502 || code == 503 || code == 504)
	}

	var fd *os.File
	if cacheDir != "" {
		fd, err = mkCacheFile(rawURL)
		if err != nil {
			log.Println("cache staging unavailable; using temporary download")
		}
	}
	cached := fd != nil
	if !cached {
		fd, err = os.CreateTemp("", "gettool-*.download")
		if err != nil {
			return fail("create temporary download", err, false)
		}
	}
	tempPath := fd.Name()
	defer func() {
		if cached || err != nil {
			fd.Close()
			if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = &downloadError{"remove incomplete download", removeErr}
				retry = false
			}
		}
		if err != nil && result != nil {
			result.Close()
			result, size = nil, 0
		}
	}()

	n, err := io.Copy(fd, resp.Body)
	if err != nil {
		return fail("body transfer failure", err, retryTransport(err))
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fail("incomplete response body", io.ErrUnexpectedEOF, true)
	}
	if err := validateDownload(ctx, req.URL, fd, n); err != nil {
		return fail("archive validation failure", err, retryTransport(err) && !errors.Is(err, zip.ErrChecksum))
	}
	if err := ctx.Err(); err != nil {
		return fail("request deadline or cancellation", err, retryTransport(err))
	}
	if _, err := fd.Seek(0, io.SeekStart); err != nil {
		return fail("rewind download", err, false)
	}
	if !cached {
		// Unlink on platforms that support open-file removal. Otherwise the
		// complete temporary file remains caller-owned, as before.
		_ = os.Remove(tempPath)
		return fd, n, false, nil
	}
	if err := fd.Sync(); err != nil {
		return fail("sync cache staging file", err, false)
	}
	if err := fd.Close(); err != nil {
		return fail("close cache staging file", err, false)
	}
	if err := ctx.Err(); err != nil {
		return fail("request deadline or cancellation", err, retryTransport(err))
	}
	// A hard link publishes a fully written file atomically without replacing
	// an entry another downloader may have committed while we were fetching.
	target := filepath.Join(cacheDir, hash256(rawURL)+".data")
	if err := os.Link(tempPath, target); err != nil && !errors.Is(err, os.ErrExist) {
		return fail("publish cache entry", err, false)
	}
	result, size, err = getCacheFile(rawURL)
	if err != nil {
		return fail("open completed cache entry", err, false)
	}
	return result, size, false, nil
}

// Archive checks run before cache publication. Reading to EOF checks ZIP CRCs
// and gzip trailers; this is integrity checking, not authenticity verification.
func validateDownload(ctx context.Context, u *url.URL, fd *os.File, n int64) error {
	if strings.HasSuffix(u.Path, ".zip") {
		z, err := zip.NewReader(fd, n)
		if err != nil {
			return err
		}
		for _, entry := range z.File {
			r, err := entry.Open()
			if err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, contextReader{ctx, r})
			closeErr := r.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
	} else if strings.HasSuffix(u.Path, ".tar.gz") {
		if _, err := fd.Seek(0, io.SeekStart); err != nil {
			return err
		}
		r, err := gzip.NewReader(fd)
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, contextReader{ctx, r})
		closeErr := r.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	return ctx.Err()
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
