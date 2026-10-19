package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

// deployOpts are the choices on the "Add device" page.
type deployOpts struct {
	Server       string
	AuthKey      string
	Hostname     string
	SSH          bool
	ExitNode     bool
	Routes       []string
	AcceptRoutes bool
	NoDNS        bool
	Tags         []string
}

type deployCommands struct {
	Linux, MacOS, Windows, Docker string
}

func (o deployOpts) flags() []string {
	f := []string{"--login-server=" + o.Server}
	if o.AuthKey != "" {
		f = append(f, "--authkey="+o.AuthKey)
	}
	if o.Hostname != "" {
		f = append(f, "--hostname="+o.Hostname)
	}
	if o.SSH {
		f = append(f, "--ssh")
	}
	if o.ExitNode {
		f = append(f, "--advertise-exit-node")
	}
	if len(o.Routes) > 0 {
		f = append(f, "--advertise-routes="+strings.Join(o.Routes, ","))
	}
	if o.AcceptRoutes {
		f = append(f, "--accept-routes")
	}
	if o.NoDNS {
		f = append(f, "--accept-dns=false")
	}
	if len(o.Tags) > 0 {
		f = append(f, "--advertise-tags="+strings.Join(o.Tags, ","))
	}
	return f
}

// buildCommands renders the tailscale command for each platform.
func buildCommands(o deployOpts) deployCommands {
	up := "tailscale up " + strings.Join(o.flags(), " ")
	var docker strings.Builder
	docker.WriteString("docker run -d --name=tailscale --restart=unless-stopped \\\n")
	if o.Hostname != "" {
		fmt.Fprintf(&docker, "  -e TS_HOSTNAME=%s \\\n", o.Hostname)
	}
	if o.AuthKey != "" {
		fmt.Fprintf(&docker, "  -e TS_AUTHKEY=%s \\\n", o.AuthKey)
	}
	extra := []string{}
	for _, f := range o.flags() {
		if !strings.HasPrefix(f, "--authkey=") && !strings.HasPrefix(f, "--hostname=") {
			extra = append(extra, f)
		}
	}
	fmt.Fprintf(&docker, "  -e TS_EXTRA_ARGS=\"%s\" \\\n", strings.Join(extra, " "))
	docker.WriteString("  -e TS_STATE_DIR=/var/lib/tailscale -v tailscale-state:/var/lib/tailscale \\\n")
	docker.WriteString("  --cap-add=NET_ADMIN --device=/dev/net/tun tailscale/tailscale")
	return deployCommands{
		Linux:   "curl -fsSL https://tailscale.com/install.sh | sh && sudo " + up,
		MacOS:   up,
		Windows: strings.Replace(up, "tailscale up", "tailscale.exe up", 1),
		Docker:  docker.String(),
	}
}

// parseDeployForm reads and validates the generator form.
func parseDeployForm(get func(string) string) (deployOpts, error) {
	o := deployOpts{
		Hostname: strings.TrimSpace(get("hostname")), SSH: get("ssh") == "on", ExitNode: get("exit_node") == "on",
		AcceptRoutes: get("accept_routes") == "on", NoDNS: get("no_dns") == "on",
	}
	if o.Hostname != "" && !hostnameRe.MatchString(o.Hostname) {
		return o, errors.New("the hostname must be lowercase letters, digits or dashes")
	}
	for _, r := range splitList(get("routes")) {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return o, fmt.Errorf("%q is not a subnet like 192.168.1.0/24", r)
		}
		o.Routes = append(o.Routes, p.Masked().String())
	}
	if raw := strings.TrimSpace(get("tags")); raw != "" {
		tags, err := parseTags(raw)
		if err != nil {
			return o, err
		}
		o.Tags = tags
	}
	return o, nil
}

type deployData struct {
	Opts    deployOpts
	Cmds    *deployCommands
	Users   []hs.User
	CanKeys bool
	OwnOnly bool
	CanTags bool
	QR      template.URL
	Error   string
	Form    map[string]string
	KeyMade bool
}

func (s *Server) deployServer() string {
	if s.Cfg.Server.PublicURL != "" {
		return s.Cfg.Server.PublicURL
	}
	return "https://your-headscale-url"
}

func (s *Server) deployBase(r *http.Request) *deployData {
	id := who(r)
	d := &deployData{CanKeys: s.canKeys(id), OwnOnly: !id.Caps.Has(perm.GenerateAuthkeys), CanTags: id.Caps.Has(perm.UseTags), Form: map[string]string{}}
	for _, u := range s.Poller.Users() {
		if u.ID != hs.TaggedDevicesUserID && (!d.OwnOnly || u.Name == id.Account.HSUser) {
			d.Users = append(d.Users, u)
		}
	}
	return d
}

func (s *Server) deployPage(w http.ResponseWriter, r *http.Request) {
	d := s.deployBase(r)
	d.Opts.Server = s.deployServer()
	s.render(w, r, "deploy", s.page(w, r, "machines", "Add a device", d))
}

func (s *Server) deployPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	d := s.deployBase(r)
	for _, k := range []string{"hostname", "routes", "tags", "ssh", "exit_node", "accept_routes", "no_dns", "auth", "user", "reusable", "ephemeral", "expiry_hours"} {
		d.Form[k] = r.PostFormValue(k)
	}
	opts, err := parseDeployForm(r.PostFormValue)
	opts.Server = s.deployServer()
	d.Opts = opts
	if err == nil && len(opts.Tags) > 0 && !id.Caps.Has(perm.UseTags) {
		err = errors.New("you can't use tags")
	}
	if err == nil && r.PostFormValue("auth") == "key" {
		if !d.CanKeys {
			err = errors.New("your role can't create pre-auth keys; use the sign-in option instead")
		} else {
			req := hs.CreateKeyReq{Reusable: r.PostFormValue("reusable") == "on", Ephemeral: r.PostFormValue("ephemeral") == "on", ACLTags: opts.Tags}
			hours, _ := strconv.Atoi(r.PostFormValue("expiry_hours"))
			if hours <= 0 || hours > 24*365 {
				hours = 24
			}
			exp := time.Now().Add(time.Duration(hours) * time.Hour).UTC()
			req.Expiration = &exp
			userName := r.PostFormValue("user")
			if d.OwnOnly {
				userName = id.Account.HSUser
			}
			for _, u := range d.Users {
				if u.Name == userName {
					req.User = u.ID
				}
			}
			if req.User == "" && len(req.ACLTags) == 0 {
				err = errors.New("choose whose device this is, or give it tags")
			} else {
				var key hs.PreAuthKey
				key, err = s.HS.CreatePreAuthKey(ctx, req)
				if err == nil {
					d.Opts.AuthKey, d.KeyMade = key.Key, true
					s.audit(r, "key.create", userName+strings.Join(req.ACLTags, ","), nil, map[string]any{"via": "add-device", "reusable": req.Reusable, "ephemeral": req.Ephemeral, "expires": exp, "tags": req.ACLTags, "id": key.ID})
				}
			}
		}
	}
	if err != nil {
		d.Error = friendly(err)
		w.WriteHeader(http.StatusBadRequest)
	} else {
		cmds := buildCommands(d.Opts)
		d.Cmds = &cmds
		d.QR = qrDataURI(cmds.MacOS)
	}
	s.render(w, r, "deploy", s.page(w, r, "machines", "Add a device", d))
}
