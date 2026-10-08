package app

import (
	"context"

	"github.com/target/goalert/config"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/util/log"
)

// Context returns a new context with the App's configuration for
// experimental flags and logger.
//
// It should be used for calls from other packages to ensure that
// the correct configuration is used.
func (app *App) Context(ctx context.Context) context.Context {
	ctx = expflag.Context(ctx, app.cfg.ExpFlags)
	ctx = log.WithLogger(ctx, app.cfg.LegacyLogger)

	if store := app.configStoreSnapshot(); store != nil {
		ctx = store.Config().Context(ctx)
	}

	return ctx
}

func (app *App) configStoreSnapshot() *config.Store {
	app.configStoreMu.RLock()
	store := app.ConfigStore
	app.configStoreMu.RUnlock()
	return store
}

func (app *App) publishConfigStore(store *config.Store) {
	app.configStoreMu.Lock()
	app.ConfigStore = store
	app.configStoreMu.Unlock()
}
