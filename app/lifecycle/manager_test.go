package lifecycle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// managerReceive bounds failures without using time as synchronization.
func managerReceive[T any](t *testing.T, ch <-chan T, operation string) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not complete", operation)
		var zero T
		return zero
	}
}

// managerTestBarrier gives the test and its cleanup the same idempotent release.
func managerTestBarrier() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	return ch, func() { once.Do(func() { close(ch) }) }
}

// managerCleanup must be registered before workers.Go. Result channels must
// hold every worker's result even if an assertion stops the test consuming them.
func managerCleanup(t *testing.T, workers *sync.WaitGroup, cancel context.CancelFunc, releases ...func()) {
	t.Helper()
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
		cancel()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("lifecycle test workers did not complete during cleanup")
		}
	})
}

func TestManagerShutdownDuringStartupCompletes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		startupErr error
	}{
		{name: "cancellation error", startupErr: context.Canceled},
		{name: "success after cancellation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			canceled := make(chan struct{})
			releaseStartup, allowStartup := managerTestBarrier()
			startupReturned := make(chan struct{})
			shutdownEntered := make(chan struct{})
			releaseShutdown, allowShutdown := managerTestBarrier()
			ctx, cancel := context.WithCancel(context.Background())
			var workers sync.WaitGroup
			managerCleanup(t, &workers, cancel, allowStartup, allowShutdown)
			var runCalls, shutdownCalls atomic.Int32
			var cleanupBeforeStartup atomic.Bool
			mgr := NewManager(
				func(context.Context) error { runCalls.Add(1); return nil },
				func(context.Context) error {
					shutdownCalls.Add(1)
					select {
					case <-startupReturned:
					default:
						cleanupBeforeStartup.Store(true)
					}
					close(shutdownEntered)
					<-releaseShutdown
					return nil
				},
			)
			require.NoError(t, mgr.SetStartupFunc(func(ctx context.Context) error {
				defer close(startupReturned)
				close(entered)
				<-ctx.Done()
				close(canceled)
				<-releaseStartup
				return tc.startupErr
			}))
			runResult := make(chan error, 1)
			workers.Go(func() { runResult <- mgr.Run(ctx) })
			managerReceive(t, entered, "startup entry")
			require.Equal(t, StatusStarting, mgr.Status())

			duplicateRuns := make(chan error, 3)
			for range 3 {
				workers.Go(func() { duplicateRuns <- mgr.Run(ctx) })
			}
			for range 3 {
				require.ErrorIs(t, managerReceive(t, duplicateRuns, "duplicate Run"), ErrAlreadyStarted)
			}

			const waiters = 8
			waitStarted := make(chan struct{}, waiters)
			waitResults := make(chan error, waiters)
			for range waiters {
				workers.Go(func() {
					waitStarted <- struct{}{}
					waitResults <- mgr.WaitForStartup(ctx)
				})
			}
			for range waiters {
				managerReceive(t, waitStarted, "startup waiter entry")
			}
			select {
			case <-waitResults:
				t.Fatal("WaitForStartup returned before startup completed")
			default:
			}

			shutdownResults := make(chan error, 4)
			workers.Go(func() { shutdownResults <- mgr.Shutdown(ctx) })
			managerReceive(t, canceled, "startup cancellation")
			require.Equal(t, StatusShutdown, mgr.Status())
			for range 3 {
				workers.Go(func() { shutdownResults <- mgr.Shutdown(ctx) })
			}
			allowStartup()
			managerReceive(t, startupReturned, "startup return")
			require.NoError(t, managerReceive(t, runResult, "interrupted Run"))
			managerReceive(t, shutdownEntered, "shutdown cleanup entry")
			for range waiters {
				require.ErrorIs(t, managerReceive(t, waitResults, "WaitForStartup"), tc.startupErr)
			}
			require.ErrorIs(t, mgr.WaitForStartup(context.Background()), tc.startupErr)
			allowShutdown()
			for range 4 {
				require.NoError(t, managerReceive(t, shutdownResults, "Shutdown"))
			}
			require.NoError(t, mgr.Shutdown(context.Background()))
			require.ErrorIs(t, mgr.Run(context.Background()), ErrShutdown)
			require.Zero(t, runCalls.Load())
			require.EqualValues(t, 1, shutdownCalls.Load())
			require.False(t, cleanupBeforeStartup.Load())
			require.Equal(t, StatusShutdown, mgr.Status())
		})
	}
}

func TestManagerStartupTerminalPaths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		startupErr error
	}{
		{name: "success"},
		{name: "startup error", startupErr: errors.New("startup failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			release, allowStartup := managerTestBarrier()
			ctx, cancel := context.WithCancel(context.Background())
			var workers sync.WaitGroup
			managerCleanup(t, &workers, cancel, allowStartup)
			var runCalls, shutdownCalls atomic.Int32
			mgr := NewManager(
				func(ctx context.Context) error { runCalls.Add(1); <-ctx.Done(); return ctx.Err() },
				func(context.Context) error { shutdownCalls.Add(1); return nil },
			)
			require.NoError(t, mgr.SetStartupFunc(func(context.Context) error {
				close(entered)
				<-release
				return tc.startupErr
			}))
			runResult := make(chan error, 1)
			workers.Go(func() { runResult <- mgr.Run(ctx) })
			managerReceive(t, entered, "startup entry")
			waitResults := make(chan error, 4)
			for range 4 {
				workers.Go(func() { waitResults <- mgr.WaitForStartup(ctx) })
			}
			allowStartup()
			for range 4 {
				require.ErrorIs(t, managerReceive(t, waitResults, "WaitForStartup"), tc.startupErr)
			}
			for range 3 {
				require.ErrorIs(t, mgr.WaitForStartup(context.Background()), tc.startupErr)
			}
			if tc.startupErr != nil {
				require.ErrorIs(t, managerReceive(t, runResult, "failed Run"), tc.startupErr)
				require.Equal(t, StatusStarting, mgr.Status())
				require.Zero(t, runCalls.Load())
			} else {
				require.Equal(t, StatusReady, mgr.Status())
			}
			require.ErrorIs(t, mgr.Run(context.Background()), ErrAlreadyStarted)
			shutdownResult := make(chan error, 1)
			workers.Go(func() { shutdownResult <- mgr.Shutdown(ctx) })
			require.NoError(t, managerReceive(t, shutdownResult, "Shutdown"))
			if tc.startupErr == nil {
				require.ErrorIs(t, managerReceive(t, runResult, "running Run"), context.Canceled)
				require.EqualValues(t, 1, runCalls.Load())
			}
			require.EqualValues(t, 1, shutdownCalls.Load())
			require.Equal(t, StatusShutdown, mgr.Status())
		})
	}
}

func TestManagerShutdownBeforeRunCompletesStartupWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	managerCleanup(t, &workers, cancel)
	var startupCalls, runCalls, shutdownCalls atomic.Int32
	mgr := NewManager(
		func(context.Context) error { runCalls.Add(1); return nil },
		func(context.Context) error { shutdownCalls.Add(1); return nil },
	)
	require.NoError(t, mgr.SetStartupFunc(func(context.Context) error {
		startupCalls.Add(1)
		return nil
	}))
	waitResults := make(chan error, 4)
	for range 4 {
		workers.Go(func() { waitResults <- mgr.WaitForStartup(ctx) })
	}
	shutdownResult := make(chan error, 1)
	workers.Go(func() { shutdownResult <- mgr.Shutdown(ctx) })
	require.NoError(t, managerReceive(t, shutdownResult, "pre-Run Shutdown"))
	for range 4 {
		require.NoError(t, managerReceive(t, waitResults, "pre-Run WaitForStartup"))
	}
	require.NoError(t, mgr.WaitForStartup(context.Background()))
	require.ErrorIs(t, mgr.Run(context.Background()), ErrShutdown)
	for range 3 {
		require.NoError(t, mgr.Shutdown(context.Background()))
	}
	require.Zero(t, startupCalls.Load())
	require.Zero(t, runCalls.Load())
	require.Zero(t, shutdownCalls.Load())
	require.Equal(t, StatusShutdown, mgr.Status())
}

func TestManager_PauseingShutdown(t *testing.T) {

	_, pr := buildPause()
	ran := make(chan struct{})
	run := func(ctx context.Context) error { <-ctx.Done(); close(ran); return ctx.Err() }
	shut := func(ctx context.Context) error { return nil }
	mgr := NewManager(run, shut)
	require.NoError(t, mgr.SetPauseResumer(pr))

	go func() { assert.ErrorIs(t, mgr.Run(context.Background()), context.Canceled) }()

	var err error
	errCh := make(chan error)
	pauseErr := make(chan error)

	tc := time.NewTimer(time.Second)
	defer tc.Stop()

	go func() { pauseErr <- mgr.Pause(context.Background()) }()
	tc.Reset(time.Second)
	select {
	case <-mgr.PauseWait():
	case <-tc.C:
		t.Fatal("pause didn't start")
	}
	// done(nil)

	go func() { errCh <- mgr.Shutdown(context.Background()) }()

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("shutdown never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("shutdown error: got %v; want nil", err)
	}

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("run never got canceled")
	case <-ran:
	}

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("pause never finished")
	case <-pauseErr:
	}

}

func TestManager_PauseShutdown(t *testing.T) {
	done, pr := buildPause()
	ran := make(chan struct{})
	run := func(ctx context.Context) error { <-ctx.Done(); close(ran); return ctx.Err() }
	shut := func(ctx context.Context) error { return nil }
	mgr := NewManager(run, shut)
	require.NoError(t, mgr.SetPauseResumer(pr))

	go func() { assert.ErrorIs(t, mgr.Run(context.Background()), context.Canceled) }()

	var err error
	errCh := make(chan error)
	go func() { errCh <- mgr.Pause(context.Background()) }()
	done(nil)

	tc := time.NewTimer(time.Second)
	defer tc.Stop()
	select {
	case <-tc.C:
		t.Fatal("pause never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("got %v; want nil", err)
	}

	go func() { errCh <- mgr.Shutdown(context.Background()) }()

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("shutdown never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("shutdown error: got %v; want nil", err)
	}

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("run never got canceled")
	case <-ran:
	}

}

func TestManager_PauseResume(t *testing.T) {
	done, pr := buildPause()
	run := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	shut := func(ctx context.Context) error { return nil }
	mgr := NewManager(run, shut)
	require.NoError(t, mgr.SetPauseResumer(pr))

	go func() { assert.ErrorIs(t, mgr.Run(context.Background()), context.Canceled) }()

	var err error
	errCh := make(chan error)
	go func() { errCh <- mgr.Pause(context.Background()) }()
	done(nil)

	tc := time.NewTimer(time.Second)
	defer tc.Stop()
	select {
	case <-tc.C:
		t.Fatal("pause never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("got %v; want nil", err)
	}

	go func() { errCh <- mgr.Resume(context.Background()) }()

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("resume never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("resume error: got %v; want nil", err)
	}

}

func TestManager_PauseingResume(t *testing.T) {

	_, pr := buildPause()
	ran := make(chan struct{})
	run := func(ctx context.Context) error { <-ctx.Done(); close(ran); return ctx.Err() }
	shut := func(ctx context.Context) error { return nil }
	mgr := NewManager(run, shut)
	require.NoError(t, mgr.SetPauseResumer(pr))

	go func() { assert.ErrorIs(t, mgr.Run(context.Background()), context.Canceled) }()

	var err error
	errCh := make(chan error)
	pauseErr := make(chan error)

	tc := time.NewTimer(time.Second)
	defer tc.Stop()

	go func() { pauseErr <- mgr.Pause(context.Background()) }()
	tc.Reset(time.Second)
	select {
	case <-mgr.PauseWait():
	case <-tc.C:
		t.Fatal("pause didn't start")
	}
	// done(nil)

	go func() { errCh <- mgr.Resume(context.Background()) }()

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("resume never finished")
	case err = <-errCh:
	}
	if err != nil {
		t.Fatalf("resume error: got %v; want nil", err)
	}

	tc.Reset(time.Second)
	select {
	case <-tc.C:
		t.Fatal("pause never finished")
	case <-pauseErr:
	}

}
