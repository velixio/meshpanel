package hs

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type nodeResp struct {
	Node Node `json:"node"`
}

func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var out struct {
		Nodes []Node `json:"nodes"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/node", nil, &out)
	return out.Nodes, err
}

func (c *Client) GetNode(ctx context.Context, id string) (Node, error) {
	var out nodeResp
	err := c.do(ctx, http.MethodGet, "/api/v1/node/"+esc(id), nil, &out)
	return out.Node, err
}

func (c *Client) DeleteNode(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/node/"+esc(id), nil, nil)
}

// ExpireNode expires the node key now; the device must log in again.
func (c *Client) ExpireNode(ctx context.Context, id string) (Node, error) {
	var out nodeResp
	err := c.do(ctx, http.MethodPost, "/api/v1/node/"+esc(id)+"/expire", nil, &out)
	return out.Node, err
}

// SetKeyExpiryDisabled turns key expiry off (never expires) or back on. Turning
// it back on needs a date, so it sets expiry 180 days out (headscale's default).
func (c *Client) SetKeyExpiryDisabled(ctx context.Context, id string, disabled bool) (Node, error) {
	return c.SetKeyExpiry(ctx, id, disabled, nowFunc().AddDate(0, 0, 180))
}

// SetKeyExpiry makes the node key expire at the given time, or never.
func (c *Client) SetKeyExpiry(ctx context.Context, id string, never bool, at time.Time) (Node, error) {
	var out nodeResp
	path := "/api/v1/node/" + esc(id) + "/expire"
	if c.Legacy() {
		// The 0.29 gateway takes these as query parameters, not a body.
		q := url.Values{"disableExpiry": {"true"}}
		if !never {
			q = url.Values{"expiry": {at.UTC().Format(time.RFC3339)}}
		}
		err := c.do(ctx, http.MethodPost, path+"?"+q.Encode(), nil, &out)
		return out.Node, err
	}
	body := map[string]any{"disableExpiry": true}
	if !never {
		body = map[string]any{"expiry": at.UTC()}
	}
	err := c.do(ctx, http.MethodPost, path, body, &out)
	return out.Node, err
}

func (c *Client) RenameNode(ctx context.Context, id, name string) (Node, error) {
	var out nodeResp
	err := c.do(ctx, http.MethodPost, "/api/v1/node/"+esc(id)+"/rename/"+esc(name), nil, &out)
	return out.Node, err
}

func (c *Client) SetTags(ctx context.Context, id string, tags []string) (Node, error) {
	var out nodeResp
	err := c.do(ctx, http.MethodPost, "/api/v1/node/"+esc(id)+"/tags", map[string]any{"tags": tags}, &out)
	return out.Node, err
}

func (c *Client) ApproveRoutes(ctx context.Context, id string, routes []string) (Node, error) {
	if routes == nil {
		routes = []string{}
	}
	var out nodeResp
	err := c.do(ctx, http.MethodPost, "/api/v1/node/"+esc(id)+"/approve_routes", map[string]any{"routes": routes}, &out)
	return out.Node, err
}

func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/user", nil, &out)
	return out.Users, err
}

func (c *Client) CreateUser(ctx context.Context, name, display, email string) (User, error) {
	var out struct {
		User User `json:"user"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/user", map[string]string{"name": name, "displayName": display, "email": email}, &out)
	return out.User, err
}

func (c *Client) RenameUser(ctx context.Context, id, name string) (User, error) {
	var out struct {
		User User `json:"user"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/user/"+esc(id)+"/rename/"+esc(name), nil, &out)
	return out.User, err
}

func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/user/"+esc(id), nil, nil)
}

func (c *Client) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var out struct {
		PreAuthKeys []PreAuthKey `json:"preAuthKeys"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/preauthkey", nil, &out)
	return out.PreAuthKeys, err
}

func (c *Client) CreatePreAuthKey(ctx context.Context, r CreateKeyReq) (PreAuthKey, error) {
	var out struct {
		PreAuthKey PreAuthKey `json:"preAuthKey"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", r, &out)
	return out.PreAuthKey, err
}

func (c *Client) ExpirePreAuthKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", map[string]string{"id": id}, nil)
}

func (c *Client) DeletePreAuthKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/preauthkey?id="+url.QueryEscape(id), nil, nil)
}

func (c *Client) GetPolicy(ctx context.Context) (Policy, error) {
	var out Policy
	err := c.do(ctx, http.MethodGet, "/api/v1/policy", nil, &out)
	return out, err
}

// SetPolicy works only when headscale runs with policy.mode: database.
func (c *Client) SetPolicy(ctx context.Context, policy string) (Policy, error) {
	var out Policy
	err := c.do(ctx, http.MethodPut, "/api/v1/policy", map[string]string{"policy": policy}, &out)
	return out, err
}

// CheckPolicy validates a policy against live users and nodes without saving.
func (c *Client) CheckPolicy(ctx context.Context, policy string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/policy/check", map[string]string{"policy": policy}, nil)
}

// AuthRegister completes an interactive /register/<id> request for user.
func (c *Client) AuthRegister(ctx context.Context, user, authID string) (Node, error) {
	var out nodeResp
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/register", map[string]string{"user": user, "authId": authID}, &out)
	return out.Node, err
}

// AuthApprove approves a pending /auth/<id> request (e.g. an SSH check).
func (c *Client) AuthApprove(ctx context.Context, authID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/auth/approve", map[string]string{"authId": authID}, nil)
}

func (c *Client) AuthReject(ctx context.Context, authID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/auth/reject", map[string]string{"authId": authID}, nil)
}
