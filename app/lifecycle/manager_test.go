package lifecycle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

// managerPauseContext observes child cancellation or removal of its registration.
// Hiding the parent's private cancelCtx value makes WithCancel use AfterFunc.
type managerPauseContext struct {
	context.Context
	canceled chan struct{}
}

func (managerPauseContext) Value(any) any { return nil }

func (c managerPauseContext) AfterFunc(fn func()) func() bool {
	var once sync.Once
	stop := context.AfterFunc(c.Context, func() {
		fn()
		once.Do(func() { close(c.canceled) })
	})
	return func() bool {
		stopped := stop()
		once.Do(func() { close(c.canceled) })
		return stopped
	}
}

// managerPauseState reads private state only while owning the status token.
// Release it before assertions so a failing assertion cannot strand a worker.
func managerPauseState(t *testing.T, mgr *Manager) (Status, bool, <-chan struct{}) {
	t.Helper()
	s := managerReceive(t, mgr.status, "status token")
	isPausing, done := mgr.isPausing, mgr.pauseDone
	mgr.status <- s
	return s, isPausing, done
}

func managerAssertPauseFinished(t *testing.T, mgr *Manager, want Status, canceled <-chan struct{}) {
	t.Helper()
	s, isPausing, done := managerPauseState(t, mgr)
	require.Equal(t, want, s)
	require.False(t, isPausing)
	managerReceive(t, done, "pauseDone closure")
	managerReceive(t, canceled, "deferred pause cancellation")
}

func TestManagerPauseAfterFailedStartup(t *testing.T) {
	sentinel := errors.New("startup failed")
	for _, tc := range []struct {
		name       string
		startupErr error
	}{
		{name: "sentinel", startupErr: sentinel},
		{name: "context canceled", startupErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				var workers sync.WaitGroup
				managerCleanup(t, &workers, cancel)
				var runCalls, pauseCalls, resumeCalls, shutdownCalls atomic.Int32
				mgr := NewManager(
					func(context.Context) error { runCalls.Add(1); return nil },
					func(context.Context) error { shutdownCalls.Add(1); return nil },
				)
				require.NoError(t, mgr.SetStartupFunc(func(context.Context) error { return tc.startupErr }))
				require.NoError(t, mgr.SetPauseResumer(PauseResumerFunc(
					func(context.Context) error { pauseCalls.Add(1); return nil },
					func(context.Context) error { resumeCalls.Add(1); return nil },
				)))
				require.Same(t, tc.startupErr, mgr.Run(ctx))
				require.Same(t, tc.startupErr, mgr.WaitForStartup(ctx))

				// Each invocation owns a fresh pauseDone and child context.
				for range 3 {
					canceled := make(chan struct{})
					pauseCtx := managerPauseContext{Context: ctx, canceled: canceled}
					result := make(chan error, 1)
					workers.Go(func() { result <- mgr.Pause(pauseCtx) })
					err := managerReceive(t, result, "Pause after failed startup")
					require.ErrorIs(t, err, tc.startupErr)
					require.Same(t, tc.startupErr, err)
					managerAssertPauseFinished(t, mgr, StatusStarting, canceled)
				}

				resumeResult := make(chan error, 1)
				workers.Go(func() { resumeResult <- mgr.Resume(ctx) })
				require.NoError(t, managerReceive(t, resumeResult, "Resume after handled startup failure"))
				require.Equal(t, StatusStarting, mgr.Status())
				shutdownResult := make(chan error, 1)
				workers.Go(func() { shutdownResult <- mgr.Shutdown(ctx) })
				require.NoError(t, managerReceive(t, shutdownResult, "Shutdown after handled startup failure"))
				require.ErrorIs(t, mgr.Pause(ctx), ErrShutdown)
				require.Same(t, tc.startupErr, mgr.WaitForStartup(ctx))
				require.Equal(t, StatusShutdown, mgr.Status())
				require.Zero(t, runCalls.Load())
				require.Zero(t, pauseCalls.Load())
				require.Zero(t, resumeCalls.Load())
				require.EqualValues(t, 1, shutdownCalls.Load())
			})
		})
	}
}

func TestManagerPauseFailedStartupInterleavings(t *testing.T) {
	sentinel := errors.New("startup failed")
	for _, tc := range []struct {
		name         string
		beforeRun    bool
		success      bool
		cancelPause  bool
		shutdown     bool
		shutdownOnly bool
	}{
		{name: "during startup"},
		{name: "before Run", beforeRun: true},
		{name: "successful startup control", success: true},
		{name: "cancel before startup completes", cancelPause: true},
		{name: "Shutdown while Pause waits", shutdown: true},
		{name: "pre-Run Shutdown", beforeRun: true, shutdown: true, shutdownOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				pauseParent, cancelPause := context.WithCancel(ctx)
				canceled := make(chan struct{})
				pauseCtx := managerPauseContext{Context: pauseParent, canceled: canceled}
				startupEntered := make(chan struct{})
				startupGate, releaseStartup := managerTestBarrier()
				var workers sync.WaitGroup
				managerCleanup(t, &workers, func() { cancelPause(); cancel() }, releaseStartup)
				var runCalls, pauseCalls, resumeCalls, shutdownCalls atomic.Int32
				mgr := NewManager(
					func(ctx context.Context) error { runCalls.Add(1); <-ctx.Done(); return ctx.Err() },
					func(context.Context) error { shutdownCalls.Add(1); return nil },
				)
				require.NoError(t, mgr.SetStartupFunc(func(context.Context) error {
					close(startupEntered)
					<-startupGate
					if tc.success {
						return nil
					}
					return sentinel
				}))
				require.NoError(t, mgr.SetPauseResumer(PauseResumerFunc(
					func(context.Context) error { pauseCalls.Add(1); return nil },
					func(context.Context) error { resumeCalls.Add(1); return nil },
				)))
				runResult := make(chan error, 1)
				pauseResult := make(chan error, 1)
				if tc.beforeRun {
					workers.Go(func() { pauseResult <- mgr.Pause(pauseCtx) })
					synctest.Wait()
					s, isPausing, _ := managerPauseState(t, mgr)
					require.Equal(t, StatusUnknown, s)
					require.True(t, isPausing)
				}
				if !tc.shutdownOnly {
					workers.Go(func() { runResult <- mgr.Run(ctx) })
					managerReceive(t, startupEntered, "startup entry")
					if !tc.beforeRun {
						workers.Go(func() { pauseResult <- mgr.Pause(pauseCtx) })
					}
					synctest.Wait()
					s, isPausing, _ := managerPauseState(t, mgr)
					require.Equal(t, StatusStarting, s)
					require.True(t, isPausing)
				}
				// Wait proves Pause is blocked before any completion signal is released.
				select {
				case <-pauseResult:
					t.Fatal("Pause returned before startup completion")
				default:
				}

				shutdownResult := make(chan error, 1)
				if tc.shutdown {
					workers.Go(func() { shutdownResult <- mgr.Shutdown(ctx) })
					synctest.Wait()
					require.Equal(t, StatusShutdown, mgr.Status())
				}
				if tc.cancelPause {
					cancelPause()
					require.ErrorIs(t, managerReceive(t, pauseResult, "canceled Pause"), context.Canceled)
					managerAssertPauseFinished(t, mgr, StatusStarting, canceled)
				}
				releaseStartup()
				if !tc.cancelPause {
					err := managerReceive(t, pauseResult, "waiting Pause")
					wantStatus := StatusStarting
					switch {
					case tc.shutdown:
						require.ErrorIs(t, err, ErrShutdown)
						wantStatus = StatusShutdown
					case tc.success:
						require.NoError(t, err)
						wantStatus = StatusPaused
					default:
						require.ErrorIs(t, err, sentinel)
						require.Same(t, sentinel, err)
					}
					managerAssertPauseFinished(t, mgr, wantStatus, canceled)
				}

				var wantStartupErr error
				if !tc.success && !tc.shutdownOnly {
					wantStartupErr = sentinel
				}
				require.ErrorIs(t, mgr.WaitForStartup(ctx), wantStartupErr)
				if !tc.success && !tc.shutdownOnly {
					err := managerReceive(t, runResult, "failed or interrupted Run")
					if tc.shutdown {
						require.NoError(t, err) // existing Run shutdown precedence
					} else {
						require.Same(t, sentinel, err)
					}
				}
				if tc.cancelPause {
					require.ErrorIs(t, mgr.Pause(ctx), sentinel)
				}
				if tc.success {
					require.NoError(t, mgr.Resume(ctx))
					require.Equal(t, StatusReady, mgr.Status())
				}
				if !tc.shutdown {
					workers.Go(func() { shutdownResult <- mgr.Shutdown(ctx) })
				}
				require.NoError(t, managerReceive(t, shutdownResult, "Shutdown completion"))
				if tc.success {
					require.ErrorIs(t, managerReceive(t, runResult, "successful Run exit"), context.Canceled)
				}
				require.ErrorIs(t, mgr.Pause(ctx), ErrShutdown)
				require.ErrorIs(t, mgr.Run(ctx), ErrShutdown)
				require.NoError(t, mgr.Shutdown(ctx))
				if tc.success {
					require.EqualValues(t, 1, runCalls.Load())
					require.EqualValues(t, 1, pauseCalls.Load())
					require.EqualValues(t, 1, resumeCalls.Load())
				} else {
					require.Zero(t, runCalls.Load())
					require.Zero(t, pauseCalls.Load())
					require.Zero(t, resumeCalls.Load())
				}
				if tc.shutdownOnly {
					require.Zero(t, shutdownCalls.Load())
				} else {
					require.EqualValues(t, 1, shutdownCalls.Load())
				}
			})
		})
	}
}

func TestManagerConcurrentPauseAfterFailedStartup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		startupGate, releaseStartup := managerTestBarrier()
		callerGate, releaseCallers := managerTestBarrier()
		var workers sync.WaitGroup
		managerCleanup(t, &workers, cancel, releaseStartup, releaseCallers)
		var runCalls, pauseCalls atomic.Int32
		sentinel := errors.New("startup failed")
		mgr := NewManager(
			func(context.Context) error { runCalls.Add(1); return nil },
			func(context.Context) error { return nil },
		)
		require.NoError(t, mgr.SetStartupFunc(func(context.Context) error { <-startupGate; return sentinel }))
		require.NoError(t, mgr.SetPauseResumer(PauseResumerFunc(
			func(context.Context) error { pauseCalls.Add(1); return nil },
			func(context.Context) error { return nil },
		)))
		const callers = 8
		waitResults := make(chan error, callers)
		for range callers {
			workers.Go(func() { waitResults <- mgr.WaitForStartup(ctx) })
		}
		runResult := make(chan error, 1)
		workers.Go(func() { runResult <- mgr.Run(ctx) })
		synctest.Wait()
		require.Equal(t, StatusStarting, mgr.Status())
		releaseStartup()
		require.Same(t, sentinel, managerReceive(t, runResult, "failed Run"))
		for range callers {
			require.Same(t, sentinel, managerReceive(t, waitResults, "WaitForStartup caller"))
		}

		pauseResults := make(chan error, callers)
		cancellations := make([]<-chan struct{}, 0, callers)
		for range callers {
			canceled := make(chan struct{})
			cancellations = append(cancellations, canceled)
			pauseCtx := managerPauseContext{Context: ctx, canceled: canceled}
			workers.Go(func() { <-callerGate; pauseResults <- mgr.Pause(pauseCtx) })
		}
		synctest.Wait()
		releaseCallers()
		for range callers {
			err := managerReceive(t, pauseResults, "concurrent Pause caller")
			require.ErrorIs(t, err, sentinel)
			require.Same(t, sentinel, err)
		}
		for _, canceled := range cancellations {
			managerReceive(t, canceled, "concurrent deferred pause cancellation")
		}
		s, isPausing, done := managerPauseState(t, mgr)
		require.Equal(t, StatusStarting, s)
		require.False(t, isPausing)
		managerReceive(t, done, "final pauseDone closure")
		require.Zero(t, runCalls.Load())
		require.Zero(t, pauseCalls.Load())
	})
}

func TestManagerPauseFailedStartupUnsupported(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("startup failed")
	var runCalls atomic.Int32
	mgr := NewManager(
		func(context.Context) error { runCalls.Add(1); return nil },
		func(context.Context) error { return nil },
	)
	require.NoError(t, mgr.SetStartupFunc(func(context.Context) error { return sentinel }))
	require.Same(t, sentinel, mgr.Run(ctx))
	require.Same(t, sentinel, mgr.WaitForStartup(ctx))
	require.ErrorIs(t, mgr.Pause(ctx), ErrPauseUnsupported)
	s, isPausing, done := managerPauseState(t, mgr)
	require.Equal(t, StatusStarting, s)
	require.False(t, isPausing)
	require.Nil(t, done)
	require.NoError(t, mgr.Shutdown(ctx))
	require.ErrorIs(t, mgr.Pause(ctx), ErrPauseUnsupported)
	require.Zero(t, runCalls.Load())
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
