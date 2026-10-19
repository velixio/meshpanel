package ts

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"

	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/tailnet"
)

// HS is the headscale surface needed to register and clean up nodes.
type HS interface {
	ListUsers(ctx context.Context) ([]hs.User, error)
	CreateUser(ctx context.Context, name, display, email string) (hs.User, error)
	CreatePreAuthKey(ctx context.Context, r hs.CreateKeyReq) (hs.PreAuthKey, error)
	ListNodes(ctx context.Context) ([]hs.Node, error)
	DeleteNode(ctx context.Context, id string) error
}

// authKey creates a single-use pre-auth key for hsUser, creating the user
// when create is set. It returns the key and its id.
func authKey(ctx context.Context, h HS, hsUser string, ephemeral, create bool) (string, string, error) {
	users, err := h.ListUsers(ctx)
	if err != nil {
		return "", "", err
	}
	id := ""
	for _, u := range users {
		if u.Name == hsUser {
			id = u.ID
		}
	}
	if id == "" {
		if !create {
			return "", "", fmt.Errorf("headscale user %q does not exist", hsUser)
		}
		u, err := h.CreateUser(ctx, hsUser, "meshpanel", "")
		if err != nil {
			return "", "", fmt.Errorf("creating headscale user %q: %w", hsUser, err)
		}
		id = u.ID
	}
	exp := time.Now().Add(10 * time.Minute).UTC()
	k, err := h.CreatePreAuthKey(ctx, hs.CreateKeyReq{User: id, Ephemeral: ephemeral, Expiration: &exp})
	if err != nil {
		return "", "", fmt.Errorf("creating a pre-auth key: %w", err)
	}
	return k.Key, k.ID, nil
}

// deleteByNodeKey removes the node with this key from headscale.
func deleteByNodeKey(ctx context.Context, h HS, nodeKey string) error {
	nodes, err := h.ListNodes(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.NodeKey == nodeKey {
			return h.DeleteNode(ctx, n.ID)
		}
	}
	return nil
}

func quietLogf(string, ...any) {}

// TSFactory starts ephemeral tsnet nodes for SSH sessions.
type TSFactory struct {
	HS         HS
	Keys       *tailnet.SessionKeys // records the keys so alerts skip these nodes
	ControlURL string
	BaseDir    string
	Debug      bool
}

type tsNode struct {
	keyID   string
	keys    *tailnet.SessionKeys
	s       *tsnet.Server
	dir     string
	nodeKey string
	hs      HS
}

func (f *TSFactory) Start(ctx context.Context, hsUser string) (tailnet.Node, error) {
	key, keyID, err := authKey(ctx, f.HS, hsUser, true, false)
	if err != nil {
		return nil, err
	}
	// Recorded before the node registers, so the first poll that sees it
	// already knows it is ours.
	if f.Keys != nil {
		f.Keys.Add(keyID)
	}
	release := func() {
		if f.Keys != nil {
			f.Keys.Release(keyID)
		}
	}
	if err := os.MkdirAll(f.BaseDir, 0o700); err != nil {
		release()
		return nil, err
	}
	dir, err := os.MkdirTemp(f.BaseDir, "ssh-*")
	if err != nil {
		release()
		return nil, err
	}
	s := &tsnet.Server{
		Dir: dir, Store: new(mem.Store), Hostname: tailnet.SSHHostname(hsUser), ControlURL: f.ControlURL,
		AuthKey: key, Ephemeral: true, Logf: quietLogf, UserLogf: quietLogf,
	}
	if f.Debug {
		s.Logf = log.New(os.Stderr, "tsnet-ssh: ", log.LstdFlags).Printf
	}
	st, err := s.Up(ctx)
	if err != nil {
		s.Close()
		os.RemoveAll(dir)
		release()
		return nil, err
	}
	n := &tsNode{s: s, dir: dir, hs: f.HS, keyID: keyID, keys: f.Keys}
	if st.Self != nil {
		if b, err := st.Self.PublicKey.MarshalText(); err == nil {
			n.nodeKey = string(b)
		}
	}
	return n, nil
}

func (n *tsNode) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return n.s.Dial(ctx, network, addr)
}

// Close shuts the node down and deletes it from headscale right away
// instead of waiting for headscale's ephemeral timeout.
func (n *tsNode) Close() error {
	err := n.s.Close()
	os.RemoveAll(n.dir)
	if n.nodeKey != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = deleteByNodeKey(ctx, n.hs, n.nodeKey)
	}
	if n.keys != nil {
		n.keys.Release(n.keyID)
	}
	return err
}

// stateExists reports whether a tsnet state directory already holds an
// identity, so no new pre-auth key is needed.
func stateExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	return err == nil
}
