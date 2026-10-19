package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/config"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/hsconfig"
	"github.com/meshpanel/meshpanel/internal/notify"
	"github.com/meshpanel/meshpanel/internal/registration"
	"github.com/meshpanel/meshpanel/internal/tailnet"
	"github.com/meshpanel/meshpanel/internal/tailnet/ts"
	"github.com/meshpanel/meshpanel/internal/telegram"
	"github.com/meshpanel/meshpanel/internal/web"
	"github.com/meshpanel/meshpanel/internal/webhook"
)

func configFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("MESHPANEL_CONFIG")
	for _, p := range []string{"config.yaml", "/etc/meshpanel/config.yaml"} {
		if def != "" {
			break
		}
		if _, err := os.Stat(p); err == nil {
			def = p
		}
	}
	return fs.String("c", def, "path to config.yaml")
}

func loadConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if c.Server.SessionSecret == "" {
		if c.Server.SessionSecret, err = persistedSecret(filepath.Join(filepath.Dir(c.DB.Path), "session_secret")); err != nil {
			return nil, fmt.Errorf("server.session_secret is not set and one could not be saved: %w\nset it yourself with: openssl rand -hex 32", err)
		}
	}
	return c, nil
}

// persistedSecret returns the secret saved at path, creating a random one on
// first use, so a bare `meshpanel` works without any configuration. It lives
// beside the database because it also seals the stored 2FA secrets.
func persistedSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= 32 {
			return s, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
		return "", err
	}
	slog.Info("generated a session secret", "path", path)
	return s, nil
}

// newHSClient talks to headscale over its socket, or, with headscale.api_key
// set (headscale 0.29.x), over its REST API at headscale.http_url.
func newHSClient(cfg *config.Config) *hs.Client {
	return hs.New(cfg.Headscale.Socket, cfg.Headscale.HTTPURL).UseAPIKey(cfg.Headscale.APIKey)
}

func setupLogging(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	setupLogging(cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d, err := db.Open(cfg.DB.Path)
	if err != nil {
		return fmt.Errorf("opening database %s: %w", cfg.DB.Path, err)
	}
	defer d.Close()

	client := newHSClient(cfg)
	var hsVersion struct {
		sync.Mutex
		v string
	}
	checkVersion := func() error {
		vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		v, err := client.Version(vctx)
		if err != nil {
			return err
		}
		hsVersion.Lock()
		hsVersion.v = v
		hsVersion.Unlock()
		if err := client.CheckSupportedFor(v); err != nil {
			return err
		}
		if !hs.IsTested(v) {
			slog.Warn("headscale is newer than the versions meshpanel was tested with", "version", v)
		}
		return nil
	}
	if err := checkVersion(); err != nil {
		if errors.Is(err, hs.ErrUnsupportedVersion) {
			return err
		}
		slog.Warn("could not read headscale's version; continuing", "err", err)
	}
	if err := client.Health(ctx); err != nil {
		slog.Warn("headscale is not reachable yet; the dashboard shows a banner until it is", "err", err)
	}

	bus := events.NewBus()
	poller := events.NewPoller(client, bus, cfg.Headscale.PollInterval)
	reg := registration.New(d, client, bus)
	engine := notify.NewEngine(d, poller.Snapshot)

	var editor *hsconfig.Editor
	var applier *hsconfig.Applier
	if cfg.Headscale.ConfigPath != "" {
		if _, err := os.Stat(cfg.Headscale.ConfigPath); err != nil {
			slog.Warn("headscale.config_path is not readable; DNS editing is off", "path", cfg.Headscale.ConfigPath, "err", err)
		} else {
			editor = &hsconfig.Editor{Path: cfg.Headscale.ConfigPath}
		}
	}
	if cfg.Headscale.RestartCommand != "" || cfg.Headscale.ReloadCommand != "" {
		applier = &hsconfig.Applier{
			Run: hsconfig.RunCommand, RestartCmd: cfg.Headscale.RestartCommand, ReloadCmd: cfg.Headscale.ReloadCommand,
			ConfigTest: hsconfig.HeadscaleConfigTest(cfg.Headscale.Binary), Health: client.Health, Timeout: 45 * time.Second,
		}
	}

	var bot *telegram.Bot
	if cfg.Telegram.Token != "" {
		group := cfg.Telegram.GroupChatID
		if v := d.GetSetting(ctx, "telegram.group_chat"); v != "" {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				group = id
			}
		}
		bot = telegram.New(telegram.Options{
			API: telegram.NewAPI(cfg.Telegram.Token, cfg.Telegram.APIBase), DB: d, Reg: reg, Users: poller.Users,
			PublicURL: cfg.Server.PublicURL, BasePath: cfg.Server.BasePath, GroupChat: group,
		})
	} else {
		slog.Info("telegram disabled (no telegram.token)")
	}
	tailnetDir := filepath.Join(filepath.Dir(cfg.DB.Path), "tailnet")
	controlURL := cfg.Agent.ControlURL
	if controlURL == "" {
		controlURL = cfg.Headscale.HTTPURL
	}
	var hostCache *tailnet.HostCache
	var agent *ts.Agent
	if cfg.Agent.Enabled {
		dir := cfg.Agent.StateDir
		if dir == "" {
			dir = filepath.Join(tailnetDir, "agent")
		}
		hostCache = &tailnet.HostCache{}
		agent = &ts.Agent{
			HS: client, HSUser: cfg.Agent.HSUser, Hostname: cfg.Agent.Hostname, ControlURL: controlURL,
			Dir: dir, Interval: cfg.Agent.Interval, Cache: hostCache, Debug: cfg.Log.Level == "debug",
		}
	}
	var sshMgr *tailnet.Manager
	var sessionKeys *tailnet.SessionKeys
	if cfg.WebSSH.Enabled {
		sessionKeys = &tailnet.SessionKeys{}
		poller.SetIgnore(sessionKeys.Owns)
		base := filepath.Join(tailnetDir, "ssh")
		_ = os.RemoveAll(base) // leftovers from sessions cut off by a restart
		sshMgr = &tailnet.Manager{
			Nodes:    &ts.TSFactory{HS: client, Keys: sessionKeys, ControlURL: controlURL, BaseDir: base, Debug: cfg.Log.Level == "debug"},
			MaxTotal: cfg.WebSSH.MaxSessions, MaxPerUser: cfg.WebSSH.MaxPerUser,
		}
	}

	deps := web.Deps{
		Cfg: cfg, DB: d, HS: client, Poller: poller, Bus: bus, Reg: reg,
		Sessions: auth.NewSessions(d), Limiter: auth.NewLimiter(), HSConfig: editor, Applier: applier, Version: version,
		HSVersion: func() string { hsVersion.Lock(); defer hsVersion.Unlock(); return hsVersion.v },
	}
	if bot != nil {
		deps.TG = bot
	}
	if hostCache != nil {
		deps.Agent = hostCache
	}
	hooks := webhook.New(d)
	deps.Webhooks = hooks
	if sshMgr != nil {
		deps.SSH = sshMgr
		deps.SessionNodes = sessionKeys
	}
	srv, err := web.New(deps)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() { poller.Run(ctx) })
	if agent != nil {
		run(func() { agent.Run(ctx) })
	}
	run(func() { reg.Run(ctx) })
	run(func() { hooks.Run(ctx, bus) })
	if bot != nil {
		run(func() { engine.Run(ctx, bus, bot) })
		run(func() { bot.Run(ctx, bus) })
	} else {
		run(func() { engine.Run(ctx, bus, nil) })
	}
	// Re-read the version after headscale restarts (e.g. upgrades).
	run(func() {
		ch, cancel := bus.Subscribe(8)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				if ev.Kind == events.HeadscaleUp {
					if err := checkVersion(); errors.Is(err, hs.ErrUnsupportedVersion) {
						slog.Error("headscale was changed to an unsupported version", "err", err)
					}
				}
			}
		}
	})

	httpSrv := &http.Server{
		Addr: cfg.Server.Listen, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 0, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("meshpanel listening", "addr", cfg.Server.Listen, "dashboard", cfg.Server.BasePath+"/", "version", version)
		if n, _ := d.CountAccounts(ctx); n == 0 {
			slog.Info("no accounts yet: open "+cfg.Server.BasePath+"/setup in a browser, or run `meshpanel setup`", "setup_code", srv.SetupToken())
		}
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case err := <-errc:
		stop()
		return fmt.Errorf("listening on %s: %w", cfg.Server.Listen, err)
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	wg.Wait()
	return nil
}
