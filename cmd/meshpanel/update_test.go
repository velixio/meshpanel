package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/meshpanel/meshpanel/internal/update"
)

type fakeReleaseUpdater struct {
	tag                   string
	lookupErr, installErr error
	installed             bool
}

func (f *fakeReleaseUpdater) Latest(context.Context, bool) (*update.Release, error) {
	return &update.Release{Tag: f.tag}, f.lookupErr
}

func (f *fakeReleaseUpdater) Install(context.Context, *update.Release) error {
	f.installed = true
	return f.installErr
}

func TestDownloadUpdate(t *testing.T) {
	for _, tt := range []struct {
		name, current, latest string
		check, install        bool
		lookupErr, installErr error
	}{
		{name: "check only", current: "0.1.4", latest: "v0.1.5", check: true},
		{name: "install newer", current: "0.1.4", latest: "v0.1.5", install: true},
		{name: "already current", current: "v0.1.5", latest: "v0.1.5"},
		{name: "no downgrade", current: "v0.1.6", latest: "v0.1.5"},
		{name: "lookup fails", current: "0.1.4", lookupErr: errors.New("offline")},
		{name: "verification fails", current: "0.1.4", latest: "v0.1.5", install: true, installErr: errors.New("invalid signature")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeReleaseUpdater{tag: tt.latest, lookupErr: tt.lookupErr, installErr: tt.installErr}
			var out bytes.Buffer
			err := downloadUpdate(context.Background(), f, tt.current, tt.check, &out)
			wantErr := tt.lookupErr
			if wantErr == nil {
				wantErr = tt.installErr
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			if f.installed != tt.install {
				t.Fatalf("installed = %v, want %v", f.installed, tt.install)
			}
			if got := strings.Contains(out.String(), "sudo systemctl restart meshpanel"); got != (tt.install && wantErr == nil) {
				t.Fatalf("unexpected restart instructions: %s", out.String())
			}
		})
	}
}

func TestUpdateArguments(t *testing.T) {
	if err := runUpdate([]string{"unexpected"}); err == nil {
		t.Fatal("accepted unexpected argument")
	}
	if err := runUpdate([]string{"--help"}); err != nil {
		t.Fatal(err)
	}
}
