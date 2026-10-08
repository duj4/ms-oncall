package app

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/util/log"
)

func TestAppContextConfigStorePublication(t *testing.T) {
	logger := log.NewLogger()
	logger.SetOutput(io.Discard)
	app := &App{cfg: Config{LegacyLogger: logger}}
	store := new(config.Store)

	var existing config.Config
	existing.General.ApplicationName = "Before publication"
	parent := existing.Context(context.Background())
	require.Nil(t, app.configStoreSnapshot())
	require.Equal(t, config.FromContext(parent), config.FromContext(app.Context(parent)))

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		app.publishConfigStore(store)
	}()
	go func() {
		defer wg.Done()
		<-start
		for range 256 {
			app.Context(parent)
		}
	}()
	close(start)
	wg.Wait()

	require.Same(t, store, app.configStoreSnapshot())
	for range 10 {
		ctx := app.Context(parent)
		require.Equal(t, store.Config(), config.FromContext(ctx))
		require.Same(t, logger, log.FromContext(ctx))
		require.True(t, config.FromContext(ctx).General.DisableCalendarSubscriptions)
		require.True(t, config.FromContext(ctx).General.DisableLabelCreation)
	}
}

func TestAppContextPreStartupInjection(t *testing.T) {
	logger := log.NewLogger()
	logger.SetOutput(io.Discard)
	store := new(config.Store)
	app := &App{
		cfg: Config{
			LegacyLogger: logger,
			ExpFlags:     expflag.FlagSet{expflag.Example},
		},
		ConfigStore: store,
	}
	var existing config.Config
	existing.General.ApplicationName = "Parent configuration"
	parent, cancel := context.WithDeadline(existing.Context(context.Background()), time.Now().Add(time.Minute))
	defer cancel()

	// The exported field is injected before any concurrent App use. This tests
	// snapshot/Context compatibility; a full initStores test requires a database.
	contexts := make(chan context.Context, 1)
	go func() {
		contexts <- app.Context(parent)
	}()
	ctx := <-contexts
	require.Same(t, store, app.configStoreSnapshot())
	require.Same(t, store, app.ConfigStore)
	require.Equal(t, store.Config(), config.FromContext(ctx))
	require.Same(t, logger, log.FromContext(ctx))
	require.True(t, expflag.ContextHas(ctx, expflag.Example))
	require.False(t, expflag.ContextHas(ctx, expflag.UnivKeys))
	deadline, ok := parent.Deadline()
	require.True(t, ok)
	gotDeadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.Equal(t, deadline, gotDeadline)
	require.Equal(t, parent.Done(), ctx.Done())
	require.NoError(t, ctx.Err())

	cancel()
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	canceled := app.Context(parent)
	require.ErrorIs(t, canceled.Err(), context.Canceled)
	require.Equal(t, store.Config(), config.FromContext(canceled))
	require.Same(t, logger, log.FromContext(canceled))
	require.True(t, expflag.ContextHas(canceled, expflag.Example))
	require.Same(t, store, app.configStoreSnapshot())

	expired, stop := context.WithDeadline(existing.Context(context.Background()), time.Now().Add(-time.Second))
	defer stop()
	expiredCtx := app.Context(expired)
	require.ErrorIs(t, expiredCtx.Err(), context.DeadlineExceeded)
	require.Equal(t, store.Config(), config.FromContext(expiredCtx))
}
