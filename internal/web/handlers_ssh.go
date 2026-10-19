package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/tailnet"
)

var loginNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)

type sshData struct {
	Node   hs.Node
	User   string
	Target string
}

// sshAllowed runs the checks shared by the page and the socket. It writes
// the error response itself and reports whether to continue.
func (s *Server) sshAllowed(w http.ResponseWriter, r *http.Request) (hs.Node, bool) {
	if s.SSH == nil {
		s.renderError(w, r, http.StatusNotFound, "Browser SSH is off", "An admin can turn it on with web_ssh.enabled in meshpanel's config.")
		return hs.Node{}, false
	}
	id := who(r)
	if !id.Caps.Has(perm.WebSSH) {
		s.renderError(w, r, http.StatusForbidden, "Not allowed", "Your role doesn't include browser SSH.")
		return hs.Node{}, false
	}
	n, ok := s.findNode(r)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Machine not found", "It may have been deleted, or it belongs to someone else.")
		return hs.Node{}, false
	}
	if id.Account.HSUser == "" {
		s.renderError(w, r, http.StatusForbidden, "No tailnet identity", "Browser SSH connects as your own headscale user, and your account isn't linked to one. Ask an admin to link it under People.")
		return hs.Node{}, false
	}
	if len(n.IPAddresses) == 0 {
		s.renderError(w, r, http.StatusConflict, "No address", "This machine has no tailnet address yet.")
		return hs.Node{}, false
	}
	return n, true
}

func (s *Server) sshPage(w http.ResponseWriter, r *http.Request) {
	n, ok := s.sshAllowed(w, r)
	if !ok {
		return
	}
	user := r.URL.Query().Get("user")
	if !loginNameRe.MatchString(user) {
		user = s.Cfg.WebSSH.DefaultUser
	}
	d := sshData{Node: n, User: user, Target: n.IPAddresses[0]}
	s.render(w, r, "ssh", s.page(w, r, "machines", "SSH · "+n.DisplayName(), d))
}

func (s *Server) sshWS(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if !loginNameRe.MatchString(user) {
		http.Error(w, "invalid login name", http.StatusBadRequest)
		return
	}
	n, ok := s.sshAllowed(w, r)
	if !ok {
		return
	}
	id := who(r)
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.originPatterns(r)})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	cols, _ := strconv.Atoi(r.URL.Query().Get("c"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("r"))
	term := newWSTerm(ctx, c, cancel)
	go term.readLoop()

	target := n.IPAddresses[0]
	started := time.Now()
	s.audit(r, "ssh.open", n.DisplayName(), nil, map[string]string{"login": user, "as": id.Account.HSUser, "ip": target})
	err = s.SSH.Open(ctx, id.Account.ID, id.Account.HSUser, target, user, term, tailnet.Size{Cols: cols, Rows: rows})
	msg := ""
	if err != nil && !errors.Is(err, context.Canceled) {
		msg = friendly(err)
	}
	term.Status("closed", msg)
	s.audit(r, "ssh.close", n.DisplayName(), nil, map[string]string{"login": user, "duration": time.Since(started).Round(time.Second).String(), "error": msg})
	c.Close(websocket.StatusNormalClosure, "")
}

// wsTerm adapts a WebSocket to tailnet.Term. Binary frames carry terminal
// bytes; text frames carry JSON control messages.
type wsTerm struct {
	ctx     context.Context
	c       *websocket.Conn
	cancel  func()
	inR     *io.PipeReader
	inW     *io.PipeWriter
	resizes chan tailnet.Size
	answers chan string
	wmu     sync.Mutex
}

func newWSTerm(ctx context.Context, c *websocket.Conn, cancel func()) *wsTerm {
	r, w := io.Pipe()
	return &wsTerm{ctx: ctx, c: c, cancel: cancel, inR: r, inW: w, resizes: make(chan tailnet.Size, 4), answers: make(chan string, 1)}
}

type ctlMsg struct {
	T    string `json:"t"`
	C    int    `json:"c,omitempty"`
	R    int    `json:"r,omitempty"`
	V    string `json:"v,omitempty"`
	Q    string `json:"q,omitempty"`
	Echo bool   `json:"echo,omitempty"`
	S    string `json:"s,omitempty"`
	M    string `json:"m,omitempty"`
}

func (t *wsTerm) readLoop() {
	defer t.cancel()
	defer t.inW.Close()
	for {
		typ, b, err := t.c.Read(t.ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageBinary {
			if _, err := t.inW.Write(b); err != nil {
				return
			}
			continue
		}
		var m ctlMsg
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		switch m.T {
		case "resize":
			select {
			case t.resizes <- tailnet.Size{Cols: m.C, Rows: m.R}:
			default:
			}
		case "answer":
			select {
			case t.answers <- m.V:
			default:
			}
		}
	}
}

func (t *wsTerm) Read(p []byte) (int, error) { return t.inR.Read(p) }

func (t *wsTerm) Write(p []byte) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	ctx, cancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer cancel()
	if err := t.c.Write(ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *wsTerm) send(m ctlMsg) {
	b, _ := json.Marshal(m)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.c.Write(ctx, websocket.MessageText, b)
}

func (t *wsTerm) Resizes() <-chan tailnet.Size { return t.resizes }

func (t *wsTerm) Prompt(ctx context.Context, q string, echo bool) (string, error) {
	t.send(ctlMsg{T: "prompt", Q: q, Echo: echo})
	select {
	case a := <-t.answers:
		return a, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(3 * time.Minute):
		return "", errors.New("no answer")
	}
}

func (t *wsTerm) Status(state, msg string) { t.send(ctlMsg{T: "status", S: state, M: msg}) }
