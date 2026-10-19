// Package registration owns pending device-registration and SSH-check
// requests: creation from the /register and /auth pages, the approve-once
// decision shared by web and Telegram, and expiry.
package registration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
)

const (
	KindRegister = "register"
	KindSSH      = "ssh"
	// TTL matches headscale's register cache. headscale's timer started a
	// little earlier, when the client first connected.
	TTL = 15 * time.Minute
)

var (
	ErrBadAuthID = errors.New("this link is not a valid device request")
	ErrNoHSUser  = errors.New("the requester's account is not linked to a headscale user; choose a user to approve as")
	ErrExpired   = errors.New("this request expired; reopen the Tailscale app to get a new link")
)

// AlreadyDecidedError reports that another approver got there first.
type AlreadyDecidedError struct {
	Status string
	By     string
	Via    string
}

func (e *AlreadyDecidedError) Error() string {
	return fmt.Sprintf("already %s by %s", e.Status, e.By)
}

// Registrar is the part of hs.Client registration needs.
type Registrar interface {
	AuthRegister(ctx context.Context, user, authID string) (hs.Node, error)
	RenameNode(ctx context.Context, id, name string) (hs.Node, error)
	AuthApprove(ctx context.Context, authID string) error
	AuthReject(ctx context.Context, authID string) error
}

type Service struct {
	db  *db.DB
	hs  Registrar
	bus *events.Bus
	now func() time.Time
}

func New(d *db.DB, r Registrar, bus *events.Bus) *Service {
	return &Service{db: d, hs: r, bus: bus, now: time.Now}
}

func (s *Service) Get(ctx context.Context, id int64) (*db.Pending, error) {
	return s.db.GetPending(ctx, id)
}

// Create records a request from a signed-in person. Reloading the page
// returns the same request.
func (s *Service) Create(ctx context.Context, kind, authID string, requester *db.Account, ip, ua string) (*db.Pending, error) {
	if !hs.ValidAuthID(authID) {
		return nil, ErrBadAuthID
	}
	if p, err := s.db.FindOpenPending(ctx, authID, requester.ID); err == nil {
		return p, nil
	}
	now := s.now()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	p, err := s.db.InsertPending(ctx, db.Pending{
		Kind: kind, AuthID: authID, RequesterID: requester.ID, HSUser: requester.HSUser,
		IP: ip, UserAgent: ua, CreatedAt: now, ExpiresAt: now.Add(TTL),
	})
	if err != nil {
		return nil, err
	}
	s.publish(events.RegistrationPending, p, requester.Name(), "web")
	return p, nil
}

// Decide approves or denies a request exactly once. asHSUser overrides the
// headscale user the device is registered under (empty = requester's own).
// The caller must already have checked the actor's permission.
func (s *Service) Decide(ctx context.Context, id int64, approve bool, actor *db.Account, channel, asHSUser string) (*db.Pending, error) {
	p, err := s.db.GetPending(ctx, id)
	if err != nil {
		return nil, err
	}
	if !p.Open() {
		return p, &AlreadyDecidedError{Status: p.Status, By: p.DecidedBy, Via: p.DecidedVia}
	}
	if !s.now().Before(p.ExpiresAt) {
		return p, ErrExpired
	}
	user := p.HSUser
	if asHSUser != "" {
		user = asHSUser
	}
	if approve && p.Kind == KindRegister && user == "" {
		return p, ErrNoHSUser
	}
	to := db.StatusDenied
	if approve {
		to = db.StatusApproving
	}
	ok, err := s.db.ClaimPending(ctx, id, to, actor.Name(), channel)
	if err != nil {
		return nil, err
	}
	if !ok {
		cur, err := s.db.GetPending(ctx, id)
		if err != nil {
			return nil, err
		}
		if cur.Status == db.StatusPending {
			return cur, ErrExpired
		}
		return cur, &AlreadyDecidedError{Status: cur.Status, By: cur.DecidedBy, Via: cur.DecidedVia}
	}

	// headscale calls get their own deadline: a slow socket must not leave
	// the request stuck in "approving".
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	var nodeName, nodeIP string
	var callErr error
	switch {
	case !approve:
		// Rejecting tells the waiting client right away. A request headscale
		// already dropped (404) is fine: the outcome is the same.
		if err := s.hs.AuthReject(hctx, p.AuthID); err != nil && !hs.IsNotFound(err) {
			callErr = err
		}
	case p.Kind == KindSSH:
		callErr = s.hs.AuthApprove(hctx, p.AuthID)
	default:
		var n hs.Node
		n, callErr = s.hs.AuthRegister(hctx, user, p.AuthID)
		if callErr == nil {
			n = s.friendlyName(hctx, n, user, p.UserAgent)
		}
		nodeName = n.DisplayName()
		if len(n.IPAddresses) > 0 {
			nodeIP = n.IPAddresses[0]
		}
	}
	final := to
	if approve {
		final = db.StatusApproved
	}
	errText := ""
	if callErr != nil {
		errText = callErr.Error()
		if approve {
			final = db.StatusFailed
		}
	}
	if err := s.db.FinishPending(hctx, id, final, nodeName, nodeIP, errText); err != nil {
		return nil, err
	}
	p, _ = s.db.GetPending(hctx, id)
	s.publish(events.RegistrationDecided, p, actor.Name(), channel)
	if callErr != nil && approve {
		if hs.IsNotFound(callErr) {
			return p, fmt.Errorf("headscale no longer has this request (it may have expired): %w", callErr)
		}
		return p, callErr
	}
	return p, nil
}

func (s *Service) Cancel(ctx context.Context, id int64, by *db.Account) (*db.Pending, error) {
	ok, err := s.db.ClaimPending(ctx, id, db.StatusCancelled, by.Name(), "web")
	if err != nil {
		return nil, err
	}
	p, err := s.db.GetPending(ctx, id)
	if err != nil {
		return nil, err
	}
	if ok {
		s.publish(events.RegistrationDecided, p, by.Name(), "web")
	}
	return p, nil
}

// ExpireSweep marks overdue requests expired and announces them.
func (s *Service) ExpireSweep(ctx context.Context) ([]*db.Pending, error) {
	exp, err := s.db.ExpirePending(ctx)
	for _, p := range exp {
		s.publish(events.RegistrationDecided, p, "", "system")
	}
	return exp, err
}

func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.ExpireSweep(ctx)
		}
	}
}

func (s *Service) publish(k events.Kind, p *db.Pending, actor, channel string) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(events.Event{
		Kind: k, At: s.now(), HSUser: p.HSUser, Actor: actor, Channel: channel, NodeName: p.NodeName,
		Data: map[string]any{"id": p.ID, "status": p.Status, "kind": p.Kind},
	})
}

// genericHostname reports names a client uses when it has no real one: iOS
// says "localhost", and headscale appends a suffix when that clashes.
func genericHostname(n string) bool {
	n = strings.ToLower(n)
	return n == "" || n == "localhost" || strings.HasPrefix(n, "localhost-")
}

// friendlyName renames a just-registered device that reported a generic
// hostname to "<user>-<kind>" (ravi-iphone), using the browser that opened
// the link as the hint. Anything that goes wrong leaves the name as it was.
func (s *Service) friendlyName(ctx context.Context, n hs.Node, user, ua string) hs.Node {
	kind := DeviceSlug(ua)
	if kind == "" || !genericHostname(n.GivenName) {
		return n
	}
	base := kind
	if u := slug(user); u != "" {
		base = u + "-" + kind
	}
	if len(base) > 55 {
		base = strings.Trim(base[:55], "-")
	}
	for i := 1; i <= 5; i++ { // a name already taken gets -2, -3, …
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		if renamed, err := s.hs.RenameNode(ctx, n.ID, name); err == nil {
			if len(renamed.IPAddresses) == 0 {
				renamed.IPAddresses = n.IPAddresses
			}
			return renamed
		}
	}
	return n
}
