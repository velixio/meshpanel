package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/update"
)

// updatePost handles Settings → Updates. Only an owner can check or install:
// installing replaces the program that runs with the panel's privileges.
func (s *Server) updatePost(w http.ResponseWriter, r *http.Request, here string) {
	if !s.need(w, r, perm.Owner) {
		return
	}
	u := s.Updater
	if u == nil {
		s.failed(w, r, here, errors.New("updates are turned off (update.enabled)"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	if r.PathValue("section") == "update_check" {
		rel, err := u.Latest(ctx, true)
		switch {
		case err != nil:
			s.failed(w, r, here, err)
		case update.Newer(rel.Tag, u.Current):
			s.ok(w, r, here, "Version "+rel.Version+" is available.")
		default:
			s.ok(w, r, here, "You're on the latest version ("+u.Current+").")
		}
		return
	}

	// Install exactly the version the owner confirmed, not whatever is newest
	// by now.
	want := r.PostFormValue("tag")
	rel, err := u.Latest(ctx, true)
	if err != nil {
		s.failed(w, r, here, err)
		return
	}
	if rel.Tag != want {
		s.failed(w, r, here, errors.New("a different version is now the latest ("+rel.Tag+"). Check again, then confirm."))
		return
	}
	if err := u.Install(ctx, rel); err != nil {
		s.audit(r, "update.install_failed", rel.Tag, u.Current, friendly(err))
		s.failed(w, r, here, err)
		return
	}
	s.audit(r, "update.install", rel.Tag, u.Current, "signature and checksum verified")
	s.ok(w, r, here, "Installed "+rel.Version+" (signature verified). meshpanel is restarting; reload this page in a few seconds.")
	if u.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond) // let this response reach the browser
			u.Restart()
		}()
	}
}
