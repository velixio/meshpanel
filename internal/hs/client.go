// Package hs is meshpanel's only door to headscale. It speaks headscale's
// HTTP API (v1) over the local unix socket, where headscale trusts callers
// without an API key (headscale 0.30 and main). Released 0.29.x serves no
// HTTP API on the socket, but its REST gateway on the TCP listener speaks
// nearly the same JSON, so with an API key the client uses that instead.
// Every headscale-version difference lives here.
package hs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrSocket wraps failures to reach headscale's socket at all.
var ErrSocket = errors.New("cannot reach headscale socket")

type Client struct {
	socket  string
	httpURL string
	sock    *http.Client
	tcp     *http.Client
	apiKey  string
	rest    *http.Client
}

// New returns a client for the socket. httpURL is headscale's TCP listener,
// used only for /version, which headscale does not serve on the socket.
func New(socket, httpURL string) *Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 60 * time.Second,
	}
	return &Client{
		socket:  socket,
		httpURL: strings.TrimRight(httpURL, "/"),
		sock:    &http.Client{Transport: tr, Timeout: 20 * time.Second},
		tcp:     &http.Client{Timeout: 5 * time.Second},
		rest:    &http.Client{Timeout: 20 * time.Second},
	}
}

// UseAPIKey switches the client to headscale's REST gateway on the TCP
// listener (http_url), authenticated with an API key. It is how meshpanel
// talks to headscale 0.29.x. An empty key keeps the unix socket.
func (c *Client) UseAPIKey(key string) *Client {
	c.apiKey = strings.TrimSpace(key)
	return c
}

// Legacy reports whether the client talks to the 0.29.x REST gateway.
func (c *Client) Legacy() bool { return c.apiKey != "" }

func (c *Client) Socket() string { return c.socket }

// APIError is headscale's RFC 7807 problem response.
type APIError struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	// Message is the gateway's error text in headscale 0.29.x.
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("headscale: %s (HTTP %d)", e.Detail, e.Status)
	}
	return fmt.Sprintf("headscale: %s (HTTP %d)", e.Title, e.Status)
}

func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// do sends a request over the socket. A nil in means no body; a nil out
// discards the response.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	hc, base := c.sock, "http://unix"
	if c.Legacy() {
		hc, base = c.rest, c.httpURL
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.Legacy() {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.Legacy() {
			return fmt.Errorf("cannot reach headscale at %s: %v", c.httpURL, err)
		}
		return fmt.Errorf("%w %s: %v", ErrSocket, c.socket, unwrapNet(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(data, ae) != nil || (ae.Title == "" && ae.Detail == "" && ae.Message == "") {
			ae.Title = strings.TrimSpace(string(data))
			if ae.Title == "" {
				ae.Title = http.StatusText(resp.StatusCode)
			}
		}
		if ae.Detail == "" {
			ae.Detail = ae.Message
		}
		if c.Legacy() && resp.StatusCode == http.StatusUnauthorized {
			ae.Detail = "headscale rejected the API key (expired or wrong?). Create one with: headscale apikeys create --expiration 999d"
		}
		ae.Status = resp.StatusCode
		return ae
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding headscale response for %s %s: %w", method, path, err)
	}
	return nil
}

// unwrapNet turns low-level dial errors into a short actionable cause.
func unwrapNet(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "permission denied"):
		return "permission denied (add meshpanel's user to the socket's group, usually 'headscale')"
	case strings.Contains(s, "no such file"):
		return "socket does not exist (is headscale running? check unix_socket in headscale's config)"
	case strings.Contains(s, "connection refused"):
		return "connection refused (headscale is not listening on this socket)"
	}
	return s
}

func esc(s string) string { return url.PathEscape(s) }

// Health checks headscale's database connectivity.
func (c *Client) Health(ctx context.Context) error {
	var out struct {
		DatabaseConnectivity bool `json:"databaseConnectivity"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/health", nil, &out); err != nil {
		return err
	}
	if !out.DatabaseConnectivity {
		return errors.New("headscale reports no database connectivity")
	}
	return nil
}

// Version reads headscale's version from its TCP listener.
func (c *Client) Version(ctx context.Context) (string, error) {
	if c.httpURL == "" {
		return "", errors.New("headscale.http_url not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.httpURL+"/version", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.tcp.Do(req)
	if err != nil {
		return "", fmt.Errorf("reading headscale version from %s: %w", c.httpURL, err)
	}
	defer resp.Body.Close()
	var v struct {
		Version string `json:"version"`
	}
	notHS := fmt.Errorf("%s/version did not answer like headscale (HTTP %d); is headscale.http_url headscale's listen_addr?", c.httpURL, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return "", notHS
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&v); err != nil || v.Version == "" {
		return "", notHS
	}
	return v.Version, nil
}

var ErrUnsupportedVersion = errors.New("unsupported headscale version")

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// CheckSupportedFor is CheckSupported for this client: with an API key it
// also accepts the 0.29 line, whose REST gateway it uses.
func (c *Client) CheckSupportedFor(v string) error {
	if c.Legacy() {
		if m := semverRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil && m[1] == "0" {
			if minor, _ := strconv.Atoi(m[2]); minor == 29 {
				return nil
			}
		}
	}
	err := CheckSupported(v)
	if errors.Is(err, ErrUnsupportedVersion) && !c.Legacy() {
		if m := semverRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil && m[1] == "0" {
			if minor, _ := strconv.Atoi(m[2]); minor == 29 {
				return fmt.Errorf("%w: headscale %s has no HTTP API on its socket. Create an API key with `headscale apikeys create --expiration 999d` and set headscale.api_key (or api_key_path) so meshpanel can use headscale's REST API at headscale.http_url", ErrUnsupportedVersion, v)
			}
		}
	}
	return err
}

// CheckSupported accepts headscale 0.30.0 and newer, plus unversioned
// development builds. Older versions speak a different API (gRPC on the
// socket) and are refused.
func CheckSupported(v string) error {
	v = strings.TrimSpace(v)
	if v == "dev" || v == "main" || strings.HasPrefix(v, "dev-") {
		return nil
	}
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("%w: %q", ErrUnsupportedVersion, v)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major == 0 && minor < 30 {
		return fmt.Errorf("%w: headscale %s is not supported; meshpanel needs 0.30.x or newer", ErrUnsupportedVersion, v)
	}
	return nil
}

// IsTested reports whether v is a release line meshpanel was built against;
// newer lines run but show a warning.
func IsTested(v string) bool {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(v))
	return m == nil || (m[1] == "0" && (m[2] == "30" || m[2] == "29"))
}

var authIDRe = regexp.MustCompile(`^hskey-authreq-[0-9a-f]{24}$`)

// ValidAuthID checks the format of a registration/auth request id.
func ValidAuthID(s string) bool { return authIDRe.MatchString(s) }
