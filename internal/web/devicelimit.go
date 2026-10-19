package web

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

// deviceLimit is the optional per-user device cap (0 = unlimited).
func (s *Server) deviceLimit(ctx context.Context) int {
	n, _ := strconv.Atoi(s.DB.GetSetting(ctx, "devices.max_per_user"))
	return max(n, 0)
}

// deviceCount counts a headscale user's devices, not counting meshpanel's
// own browser-SSH session nodes.
func (s *Server) deviceCount(hsUser string) int {
	if hsUser == "" {
		return 0
	}
	n := 0
	for _, node := range s.Poller.Snapshot() {
		if node.UserName() == hsUser && (s.SessionNodes == nil || !s.SessionNodes.Owns(node)) {
			n++
		}
	}
	return n
}

// atLimit reports whether hsUser can't add more devices without an approver.
func (s *Server) atLimit(ctx context.Context, hsUser string) (bool, int, int) {
	limit := s.deviceLimit(ctx)
	count := s.deviceCount(hsUser)
	return limit > 0 && count >= limit, count, limit
}

// overLimitSelfApprove reports whether id is approving its own device request
// while the target user is at the limit without holding approve_devices.
func (s *Server) overLimitSelfApprove(ctx context.Context, id *identity, p *db.Pending, asUser string) bool {
	if p.Kind != registration.KindRegister || p.RequesterID != id.Account.ID || id.Caps.Has(perm.ApproveDevices) {
		return false
	}
	target := p.HSUser
	if asUser != "" {
		target = asUser
	}
	limited, _, _ := s.atLimit(ctx, target)
	return limited
}

// checkKeyLimit stops a pre-auth key from bypassing the device limit: without
// approve_devices, keys for a limited user must be single-use, and devices
// plus still-unused keys must stay under the limit.
func (s *Server) checkKeyLimit(ctx context.Context, id *identity, userName string, req hs.CreateKeyReq) error {
	limit := s.deviceLimit(ctx)
	if limit == 0 || userName == "" || id.Caps.Has(perm.ApproveDevices) {
		return nil
	}
	if req.Reusable {
		return errors.New("with a device limit set, keys must be single-use")
	}
	keys, err := s.HS.ListPreAuthKeys(ctx)
	if err != nil {
		return err
	}
	n := s.deviceCount(userName)
	now := time.Now()
	for _, k := range keys {
		if k.User != nil && k.User.Name == userName && !k.Used && now.Before(k.Expiration) {
			n++
		}
	}
	if n >= limit {
		return fmt.Errorf("%s is at the device limit (%d, counting unused keys); ask an approver to add the device", userName, limit)
	}
	return nil
}
