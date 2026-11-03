package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/update"
)

// headscaleUpdatePost restricts both release checks and installs to owners.
func (s *Server) headscaleUpdatePost(w http.ResponseWriter, r *http.Request, here string) {
	if !s.need(w, r, perm.Owner) {
		return
	}
	u := s.HeadscaleUpdater
	if u == nil {
		s.failed(w, r, here, errors.New("Headscale release checking is unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	rel, err := u.Latest(ctx, true)
	if err != nil {
		s.failed(w, r, here, err)
		return
	}
	if r.PathValue("section") == "headscale_update_check" {
		if s.RefreshHSVersion != nil {
			if err := s.RefreshHSVersion(ctx); err != nil {
				s.failed(w, r, here, err)
				return
			}
		}
		s.ok(w, r, here, "Latest stable Headscale release: "+rel.Tag)
		return
	}
	if s.InstallHeadscale == nil {
		s.failed(w, r, here, errors.New("Headscale installation is not enabled; configure the update helper first"))
		return
	}
	if r.PostFormValue("tag") != rel.Tag {
		s.failed(w, r, here, errors.New("latest Headscale release changed; check again before installing"))
		return
	}
	current := ""
	if s.HSVersion != nil {
		current = s.HSVersion()
	}
	if reason := update.HeadscaleUpgradeReason(current, rel.Tag); reason != "" {
		s.failed(w, r, here, errors.New(reason))
		return
	}
	// The helper owns its lifecycle once started, so a browser disconnect must
	// not interrupt a stopped-service backup or leave Headscale half-updated.
	installCtx, stop := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer stop()
	msg, err := s.InstallHeadscale(installCtx, rel.Tag)
	if err != nil {
		s.audit(r, "headscale.update_failed", rel.Tag, current, friendly(err))
		s.failed(w, r, here, err)
		return
	}
	s.audit(r, "headscale.update", rel.Tag, current, "upstream checksum verified")
	// A fast restart can fall between poll intervals and emit no HeadscaleUp
	// event. Reload the version before redirecting to the Settings page.
	if s.RefreshHSVersion != nil {
		if err := s.RefreshHSVersion(installCtx); err != nil {
			slog.Warn("refresh Headscale version after update", "err", err)
			msg += " The running version could not be refreshed; use Check Headscale updates to retry."
		}
	}
	s.Poller.Refresh()
	s.ok(w, r, here, msg)
}
