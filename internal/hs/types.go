package hs

import (
	"net/netip"
	"time"
)

// TaggedDevicesUserID is the pseudo-user headscale reports for tagged nodes.
const TaggedDevicesUserID = "2147455555"

type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"createdAt"`
	DisplayName   string    `json:"displayName"`
	Email         string    `json:"email"`
	ProviderID    string    `json:"providerId"`
	Provider      string    `json:"provider"`
	ProfilePicURL string    `json:"profilePicUrl"`
}

type Node struct {
	ID              string     `json:"id"`
	MachineKey      string     `json:"machineKey"`
	NodeKey         string     `json:"nodeKey"`
	IPAddresses     []string   `json:"ipAddresses"`
	Name            string     `json:"name"`
	User            *User      `json:"user"`
	LastSeen        *time.Time `json:"lastSeen"`
	Expiry          *time.Time `json:"expiry"`
	CreatedAt       time.Time  `json:"createdAt"`
	RegisterMethod  string     `json:"registerMethod"`
	GivenName       string     `json:"givenName"`
	Online          bool       `json:"online"`
	ApprovedRoutes  []string   `json:"approvedRoutes"`
	AvailableRoutes []string   `json:"availableRoutes"`
	SubnetRoutes    []string   `json:"subnetRoutes"`
	Tags            []string   `json:"tags"`
}

func (n *Node) DisplayName() string {
	if n.GivenName != "" {
		return n.GivenName
	}
	return n.Name
}

// IsTagged follows headscale's tags-XOR-user rule.
func (n *Node) IsTagged() bool {
	return len(n.Tags) > 0 || (n.User != nil && n.User.ID == TaggedDevicesUserID)
}

// UserName is the owning headscale user, or "" for tagged nodes.
func (n *Node) UserName() string {
	if n.IsTagged() || n.User == nil {
		return ""
	}
	return n.User.Name
}

func isExitRoute(r string) bool { return r == "0.0.0.0/0" || r == "::/0" }

func (n *Node) IsExitNodeAdvertised() bool {
	for _, r := range n.AvailableRoutes {
		if isExitRoute(r) {
			return true
		}
	}
	return false
}

func (n *Node) IsExitNodeApproved() bool {
	for _, r := range n.ApprovedRoutes {
		if isExitRoute(r) {
			return true
		}
	}
	return false
}

// PendingRoutes are advertised but not approved.
func (n *Node) PendingRoutes() []string {
	ok := map[string]bool{}
	for _, r := range n.ApprovedRoutes {
		ok[r] = true
	}
	var out []string
	for _, r := range n.AvailableRoutes {
		if !ok[r] {
			out = append(out, r)
		}
	}
	return out
}

// RouteRisk grades a route for the approval UI: "exit" for default routes,
// "wide" for prefixes shorter than /16 (IPv4) or /32 (IPv6), else "".
func RouteRisk(r string) string {
	if isExitRoute(r) {
		return "exit"
	}
	p, err := netip.ParsePrefix(r)
	if err != nil {
		return ""
	}
	if (p.Addr().Is4() && p.Bits() < 16) || (p.Addr().Is6() && p.Bits() < 32) {
		return "wide"
	}
	return ""
}

func (n *Node) KeyExpired(now time.Time) bool { return n.Expiry != nil && !n.Expiry.IsZero() && n.Expiry.Before(now) }

type PreAuthKey struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	User       *User     `json:"user"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"`
}

type CreateKeyReq struct {
	User       string     `json:"user,omitempty"` // headscale user id
	Reusable   bool       `json:"reusable,omitempty"`
	Ephemeral  bool       `json:"ephemeral,omitempty"`
	Expiration *time.Time `json:"expiration,omitempty"`
	ACLTags    []string   `json:"aclTags,omitempty"`
}

type Policy struct {
	Policy    string    `json:"policy"`
	UpdatedAt time.Time `json:"updatedAt"`
}

var nowFunc = time.Now
