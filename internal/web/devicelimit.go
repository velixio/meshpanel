package web

import (
	"context"
	"strconv"
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
