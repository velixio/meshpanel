package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meshpanel/meshpanel/internal/hsupdate"
	"github.com/meshpanel/meshpanel/internal/update"
)

// runHeadscale provides the same verified patch upgrade used by Settings.
func runHeadscale(args []string) error {
	if len(args) == 0 || args[0] != "update" {
		return errors.New("usage: meshpanel headscale update [--check] [-c /etc/meshpanel/headscale-update.yaml]")
	}
	fs := flag.NewFlagSet("headscale update", flag.ContinueOnError)
	path := fs.String("c", hsupdate.ConfigPath, "root-owned Headscale update configuration (not the panel config)")
	check := fs.Bool("check", false, "check the latest release without installing")
	fromUI := fs.Bool("from-ui", false, "read the exact confirmed release tag from standard input")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments to headscale update")
	}
	if *fromUI && (*path != hsupdate.ConfigPath || *check) {
		return errors.New("UI helper requires the default update configuration")
	}
	if !*check && os.Geteuid() != 0 {
		return errors.New("Headscale installation requires root; run with sudo")
	}
	var want string
	if *fromUI {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 65))
		if err != nil {
			return err
		}
		want = strings.TrimSpace(string(b))
		if len(b) > 64 {
			return errors.New("invalid release tag")
		}
		if _, ok := update.ParseVersion(want); !ok {
			return errors.New("invalid release tag")
		}
	}
	cfg, err := hsupdate.Load(*path)
	if err != nil {
		return err
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalCtx, 10*time.Minute)
	defer cancel()
	if *check {
		current, err := hsupdate.Current(ctx, cfg)
		if err != nil {
			return err
		}
		rel, err := update.NewHeadscale(current).Latest(ctx, true)
		if err != nil {
			return err
		}
		fmt.Printf("Headscale installed: %s; latest: %s\n", current, rel.Tag)
		if reason := update.HeadscaleUpgradeReason(current, rel.Tag); reason != "" {
			fmt.Println(reason)
		}
		return nil
	}
	msg, err := hsupdate.Upgrade(ctx, cfg, want)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
