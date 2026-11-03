package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/meshpanel/meshpanel/internal/config"
	"github.com/meshpanel/meshpanel/internal/update"
)

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	check := fs.Bool("check", false, "check for a newer release without downloading it")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: meshpanel update [-c config.yaml] [--check]")
	}
	// Updating needs only the configuration, not a database connection or a
	// session secret (which loadConfig may create).
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if !cfg.Update.Enabled {
		return errors.New("updates are turned off (update.enabled)")
	}
	u := update.New(cfg.Update.Repo, filepath.Dir(cfg.DB.Path), version)
	if err := u.Updatable(); err != nil {
		return err
	}
	// /usr/bin/meshpanel may be older than the verified staged executable.
	if tag, ok := u.Staged(); ok {
		fmt.Printf("Verified staged version: %s (starts on service restart).\n", tag)
		u.Current = tag
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	return downloadUpdate(ctx, u, u.Current, *check, os.Stdout)
}

type releaseUpdater interface {
	Latest(context.Context, bool) (*update.Release, error)
	Install(context.Context, *update.Release) error
}

func downloadUpdate(ctx context.Context, u releaseUpdater, current string, check bool, out io.Writer) error {
	rel, err := u.Latest(ctx, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Current: %s; latest release: %s\n", current, rel.Tag)
	if !update.Newer(rel.Tag, current) {
		fmt.Fprintln(out, "No newer release is available.")
		return nil
	}
	if check {
		fmt.Fprintln(out, "Run meshpanel update with the same config to download and verify this release.")
		return nil
	}
	fmt.Fprintf(out, "Downloading and verifying %s…\n", rel.Tag)
	if err := u.Install(ctx, rel); err != nil {
		return fmt.Errorf("staging update: %w", err)
	}
	fmt.Fprintf(out, "Staged %s (signature and checksum verified).\nRestart the service to activate it: sudo systemctl restart meshpanel\n", rel.Tag)
	return nil
}
