package app

import (
	"context"
	"errors"
)

// validateSysAPI rejects configuration of the retired external System API before
// any listener, TLS material, or other application resource is initialized.
func (c Config) validateSysAPI() error {
	if c.SysAPIListenAddr != "" {
		return errors.New("SysAPI is disabled in MS OnCall")
	}
	return nil
}

func (app *App) initSysAPI(ctx context.Context) error {
	return app.cfg.validateSysAPI()
}
