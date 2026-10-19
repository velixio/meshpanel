package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/config"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/telegram"
)

func openDB(cfg *config.Config) (*db.DB, error) {
	d, err := db.Open(cfg.DB.Path)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", cfg.DB.Path, err)
	}
	return d, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func newPassword() (string, error) {
	pw, err := readPassword("New password (10+ characters): ")
	if err != nil {
		return "", err
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := readPassword("Again: ")
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", errors.New("passwords don't match")
		}
	}
	return pw, nil
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	cfgPath := configFlag(fs)
	username := fs.String("u", "", "owner username")
	hsUser := fs.String("hs-user", "", "headscale user for the owner's own devices (optional)")
	fs.Parse(args)
	if *username == "" {
		return errors.New("give a username with -u")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()
	if n, _ := d.CountAccounts(ctx); n > 0 {
		return errors.New("accounts already exist; invite people from the People page instead")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("fix the configuration first (the 2FA secret is sealed with server.session_secret):\n%w", err)
	}
	auth.SetSecretKey(cfg.Server.SessionSecret)
	pw, err := newPassword()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	secret, uri := auth.NewTOTPSecret("meshpanel", strings.ToLower(*username))
	acc, err := d.CreateAccount(ctx, db.Account{Username: strings.ToLower(*username), PasswordHash: hash, Role: "owner", HSUser: *hsUser, TOTPSecret: auth.SealSecret(secret), TOTPEnabled: true})
	if err != nil {
		return err
	}
	codes, err := auth.NewBackupCodes(ctx, d, acc.ID)
	if err != nil {
		return err
	}
	_ = d.InsertAudit(ctx, db.AuditEntry{Actor: acc.Username, Channel: "cli", Action: "setup", Target: acc.Username})
	fmt.Printf("\nOwner %q created.\n\nAdd this to your authenticator app:\n  %s\n  (key: %s)\n\nBackup codes (each works once):\n", acc.Username, uri, secret)
	for _, c := range codes {
		fmt.Println("  " + c)
	}
	fmt.Println()
	return nil
}

func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: meshpanel user reset-2fa|set-password|list [-c config] [NAME]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("user "+sub, flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args[1:])
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()
	if sub == "list" {
		accs, err := d.ListAccounts(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tROLE\tHEADSCALE USER\t2FA\tDISABLED")
		for _, a := range accs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%v\n", a.Username, a.Role, a.HSUser, a.TOTPEnabled, a.Disabled)
		}
		return tw.Flush()
	}
	if fs.NArg() != 1 {
		return errors.New("give the account's username")
	}
	acc, err := d.GetAccountByUsername(ctx, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("no account named %q", fs.Arg(0))
	}
	switch sub {
	case "reset-2fa":
		acc.TOTPEnabled, acc.TOTPSecret = false, ""
		if err := d.UpdateAccount(ctx, acc); err != nil {
			return err
		}
		_ = d.ReplaceBackupCodes(ctx, acc.ID, nil)
		_ = d.DeleteSessionsFor(ctx, acc.ID, "")
		_ = d.InsertAudit(ctx, db.AuditEntry{Actor: "cli", Channel: "cli", Action: "person.reset_2fa", Target: acc.Username})
		fmt.Printf("Two-factor reset for %s. They set it up again at their next sign-in.\n", acc.Username)
	case "set-password":
		pw, err := newPassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		acc.PasswordHash = hash
		if err := d.UpdateAccount(ctx, acc); err != nil {
			return err
		}
		_ = d.DeleteSessionsFor(ctx, acc.ID, "")
		_ = d.InsertAudit(ctx, db.AuditEntry{Actor: "cli", Channel: "cli", Action: "person.set_password", Target: acc.Username})
		fmt.Printf("Password set for %s.\n", acc.Username)
	default:
		return fmt.Errorf("unknown user command %q", sub)
	}
	return nil
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: meshpanel backup [-c config] DEST")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := os.Stat(fs.Arg(0)); err == nil {
		return fmt.Errorf("%s already exists", fs.Arg(0))
	}
	if err := d.Backup(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("Backup written to", fs.Arg(0))
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	failures := 0
	check := func(name string, err error, hint string) {
		if err == nil {
			fmt.Printf("  ✓ %s\n", name)
			return
		}
		failures++
		fmt.Printf("  ✗ %s: %v\n", name, err)
		if hint != "" {
			fmt.Printf("      → %s\n", hint)
		}
	}
	warn := func(name, msg string) { fmt.Printf("  ! %s: %s\n", name, msg) }

	fmt.Println("meshpanel doctor")
	if *cfgPath == "" {
		warn("config", "no config file; using defaults and MESHPANEL_* variables")
	} else {
		fmt.Printf("  · config %s\n", *cfgPath)
	}
	check("configuration is valid", cfg.Validate(), "")

	client := hs.New(cfg.Headscale.Socket, cfg.Headscale.HTTPURL)
	check("headscale socket "+cfg.Headscale.Socket, client.Health(ctx), "is headscale running, and is meshpanel's user in the socket's group?")
	v, err := client.Version(ctx)
	if err == nil {
		err = hs.CheckSupported(v)
		if err == nil && !hs.IsTested(v) {
			warn("headscale version", v+" is newer than tested (0.30.x)")
		}
	}
	check("headscale version "+v, err, "set headscale.http_url to headscale's listen_addr")

	if cfg.Headscale.ConfigPath != "" {
		f, err := os.OpenFile(cfg.Headscale.ConfigPath, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		check("headscale config writable "+cfg.Headscale.ConfigPath, err, "needed for DNS editing: chgrp meshpanel the file and chmod g+w it")
	} else {
		warn("headscale config", "headscale.config_path not set; DNS editing is off")
	}
	if p := cfg.Headscale.PolicyPath; p != "" {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		check("policy file writable "+p, err, "")
	}

	d, err := db.Open(cfg.DB.Path)
	check("database "+cfg.DB.Path, err, "the directory must be writable by meshpanel's user")
	if err == nil {
		n, _ := d.CountAccounts(ctx)
		if n == 0 {
			warn("accounts", "none yet; open /setup or run `meshpanel setup -u NAME`")
		}
		d.Close()
	}

	if cfg.Telegram.Token != "" {
		_, err := telegram.NewAPI(cfg.Telegram.Token, cfg.Telegram.APIBase).GetMe(ctx)
		check("telegram bot token", err, "check telegram.token from @BotFather")
	} else {
		warn("telegram", "disabled (no telegram.token)")
	}

	if cfg.Server.PublicURL == "" {
		warn("public_url", "server.public_url not set; invite links and key commands won't include your domain")
	} else {
		u, _ := url.Parse(cfg.Server.PublicURL)
		probe := cfg.Server.PublicURL + "/register/hskey-authreq-000000000000000000000000"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
		resp, err := (&http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.Header.Get("X-Meshpanel") == "" && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusNotFound {
				err = fmt.Errorf("HTTP %d without meshpanel's marker", resp.StatusCode)
			} else if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				err = errors.New("the response came from headscale, not meshpanel")
			}
		}
		check("proxy sends /register/* on "+u.Host+" to meshpanel", err, "route /register/*, /auth/* and "+cfg.Server.BasePath+"/* to meshpanel (see deploy/Caddyfile or deploy/nginx.conf)")
	}
	if failures > 0 {
		return fmt.Errorf("%d check(s) failed", failures)
	}
	fmt.Println("All good.")
	return nil
}
