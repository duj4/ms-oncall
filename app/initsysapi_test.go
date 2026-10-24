package app

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/target/goalert/app/lifecycle"
)

const sysAPIDisabledMessage = "SysAPI is disabled in MS OnCall"

func TestSysAPIHardDisabled(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("certificate-fields-%03b", mask), func(t *testing.T) {
			cfg := Config{}
			// These nonexistent paths prove no certificate/key loading occurs.
			for i, field := range []*string{&cfg.SysAPICertFile, &cfg.SysAPIKeyFile, &cfg.SysAPICAFile} {
				if mask&(1<<i) != 0 {
					*field = filepath.Join(t.TempDir(), "must-not-be-read")
				}
			}
			a := &App{cfg: cfg}
			if err := a.initSysAPI(context.Background()); err != nil {
				t.Fatal(err)
			}
			if a.sysAPIL != nil || a.sysAPISrv != nil || a.hSrv != nil {
				t.Fatal("empty address initialized SysAPI resources")
			}
			// The occupied address detects a net.Listen attempt before rejection.
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			for _, addr := range []string{occupied.Addr().String(), "invalid address", " "} {
				a.cfg.SysAPIListenAddr = addr
				if err := a.initSysAPI(context.Background()); err == nil || err.Error() != sysAPIDisabledMessage {
					t.Fatal("expected SysAPI disabled error before listen/TLS")
				}
				if a.sysAPIL != nil || a.sysAPISrv != nil || a.hSrv != nil {
					t.Fatal("disabled SysAPI initialized resources")
				}
			}
		})
	}
}

func TestSysAPIConstructorRejectsBeforeResources(t *testing.T) {
	// NewApp used to bind HTTP before the later SysAPI startup check. Exercise
	// the actual constructor with no DB pool; disabled configuration must be
	// rejected before accessing it or creating HTTP, TLS, status or SysAPI sockets.
	addresses := make([]string, 4)
	var reservations []net.Listener
	for i := range addresses {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		addresses[i] = l.Addr().String()
	}
	for _, l := range reservations {
		_ = l.Close()
	}
	cfg := Config{ListenAddr: addresses[0], TLSListenAddr: addresses[1], StatusAddr: addresses[2], SysAPIListenAddr: addresses[3]}
	for i := 0; i < 3; i++ {
		a, err := NewApp(cfg, nil)
		if a != nil || err == nil || err.Error() != sysAPIDisabledMessage {
			t.Fatal("constructor did not propagate SysAPI rejection")
		}
	}
	for _, addr := range addresses {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatal("startup failure left a reachable TCP listener")
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal("startup failure retained a socket")
		}
		_ = l.Close()
	}
}

func TestSysAPIStartupFailurePropagates(t *testing.T) {
	a := &App{cfg: Config{SysAPIListenAddr: "127.0.0.1:0"}}
	ran := false
	mgr := lifecycle.NewManager(func(context.Context) error { ran = true; return nil }, func(context.Context) error { return nil })
	if err := mgr.SetStartupFunc(func(ctx context.Context) error {
		a.initStartup(ctx, "Startup.SysAPI", a.initSysAPI)
		a.initStartup(ctx, "must not run", func(context.Context) error { t.Fatal("startup continued after failure"); return nil })
		return a.startupErr
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, err := range []error{mgr.Run(ctx), mgr.WaitForStartup(ctx)} {
		if err == nil || err.Error() != "Startup.SysAPI: "+sysAPIDisabledMessage {
			t.Fatal("startup/lifecycle failed to propagate SysAPI error")
		}
	}
	if ran || a.sysAPISrv != nil || a.sysAPIL != nil {
		t.Fatal("failed startup served traffic")
	}
	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
