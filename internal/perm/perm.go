// Package perm defines meshpanel's capability flags, the built-in roles that
// bundle them, and ownership scoping for people who may only see their own
// devices.
package perm

import (
	"sort"

	"github.com/meshpanel/meshpanel/internal/hs"
)

type Cap uint64

const (
	UIAccess Cap = 1 << iota
	ReadPolicy
	WritePolicy
	ReadNetwork
	WriteNetwork
	ReadFeature
	WriteFeature
	ConfigureIAM
	ReadMachines
	WriteMachines
	ReadUsers
	WriteUsers
	GenerateAuthkeys
	GenerateOwnAuthkeys
	UseTags
	WriteTailnet
	Owner
	ApproveDevices
	ApproveDevicesOwn
	ManageNotifications
	ReadAudit
	ApproveSSH
)

func (c Cap) Has(x Cap) bool { return c&x == x }

type Named struct {
	Cap  Cap
	Name string
	Help string
}

// All lists every capability with its stable name and a one-line help text
// for the role editor.
var All = []Named{
	{UIAccess, "ui_access", "Open the dashboard"},
	{ReadPolicy, "read_policy", "View the access policy"},
	{WritePolicy, "write_policy", "Edit the access policy"},
	{ReadNetwork, "read_network", "View DNS and routes"},
	{WriteNetwork, "write_network", "Edit DNS and approve routes"},
	{ReadFeature, "read_feature", "View server features"},
	{WriteFeature, "write_feature", "Change server features"},
	{ConfigureIAM, "configure_iam", "Manage roles and panel accounts"},
	{ReadMachines, "read_machines", "See every machine"},
	{WriteMachines, "write_machines", "Change any machine"},
	{ReadUsers, "read_users", "See headscale users"},
	{WriteUsers, "write_users", "Create, rename and delete headscale users"},
	{GenerateAuthkeys, "generate_authkeys", "Create pre-auth keys for anyone"},
	{GenerateOwnAuthkeys, "generate_own_authkeys", "Create pre-auth keys for yourself"},
	{UseTags, "use_tags", "Set tags on machines and keys"},
	{WriteTailnet, "write_tailnet", "Change tailnet-wide settings"},
	{Owner, "owner", "Owner: everything, including transferring ownership"},
	{ApproveDevices, "approve_devices", "Approve anyone's new devices"},
	{ApproveDevicesOwn, "approve_devices_own", "Add your own devices without waiting"},
	{ManageNotifications, "manage_notifications", "Create alert rules for other people"},
	{ReadAudit, "read_audit", "Read the audit log"},
	{ApproveSSH, "approve_ssh", "Approve SSH sign-in checks"},
}

func everything() Cap {
	var c Cap
	for _, n := range All {
		c |= n.Cap
	}
	return c
}

var (
	readAll = UIAccess | ReadPolicy | ReadNetwork | ReadFeature | ReadMachines | ReadUsers

	// Roles are the built-in bundles. Extra caps per account add on top.
	Roles = map[string]Cap{
		"owner":         everything(),
		"admin":         everything() &^ Owner,
		"network_admin": readAll | WritePolicy | WriteNetwork | WriteTailnet | UseTags | ReadAudit,
		"it_admin":      readAll | WriteMachines | WriteUsers | GenerateAuthkeys | UseTags | ApproveDevices | ApproveSSH | ReadAudit,
		"auditor":       readAll | ReadAudit,
		"viewer":        readAll,
		"member":        UIAccess | GenerateOwnAuthkeys,
	}

	// RoleOrder is the display order, most powerful first.
	RoleOrder = []string{"owner", "admin", "network_admin", "it_admin", "auditor", "viewer", "member"}

	RoleHelp = map[string]string{
		"owner":         "Full control, including other owners",
		"admin":         "Full control except owner-only actions",
		"network_admin": "Policy, DNS and routes",
		"it_admin":      "Machines, users, keys and device approvals",
		"auditor":       "Read everything, including the audit log",
		"viewer":        "Read-only dashboard",
		"member":        "Only their own devices",
	}
)

// Effective is the role's caps plus per-account extras.
func Effective(role string, extra Cap) Cap {
	base, ok := Roles[role]
	if !ok {
		return 0
	}
	return base | extra
}

// Within reports whether every capability in target is also in actor. People
// may only grant, or manage accounts with, permissions they hold.
func Within(target, actor Cap) bool { return target&^actor == 0 }

func ValidRole(r string) bool { _, ok := Roles[r]; return ok }

// Parse turns capability names into flags, ignoring unknown names.
func Parse(names []string) Cap {
	idx := map[string]Cap{}
	for _, n := range All {
		idx[n.Name] = n.Cap
	}
	var c Cap
	for _, n := range names {
		c |= idx[n]
	}
	return c
}

func (c Cap) Names() []string {
	var out []string
	for _, n := range All {
		if c.Has(n.Cap) {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Scope decides which devices an account can see.
type Scope struct {
	HSUser string
	All    bool
}

func ScopeFor(caps Cap, hsUser string) Scope {
	return Scope{HSUser: hsUser, All: caps.Has(ReadMachines)}
}

func (s Scope) Node(n hs.Node) bool {
	if s.All {
		return true
	}
	return s.HSUser != "" && n.UserName() == s.HSUser
}

func (s Scope) Nodes(in []hs.Node) []hs.Node {
	if s.All {
		return in
	}
	var out []hs.Node
	for _, n := range in {
		if s.Node(n) {
			out = append(out, n)
		}
	}
	return out
}

// User reports whether the scope may see headscale user name.
func (s Scope) User(name string) bool { return s.All || (s.HSUser != "" && name == s.HSUser) }

// CanApprove reports whether an account (caps, linked headscale user) may
// approve a device for the requester's headscale user.
func CanApprove(caps Cap, approverHSUser, requesterHSUser string) bool {
	if caps.Has(ApproveDevices) {
		return true
	}
	return caps.Has(ApproveDevicesOwn) && approverHSUser != "" && approverHSUser == requesterHSUser
}

// CanApproveAs extends CanApprove for "approve as another user": choosing
// a different headscale user than the requester's needs approve_devices.
func CanApproveAs(caps Cap, approverHSUser, requesterHSUser, asHSUser string) bool {
	if asHSUser != "" && asHSUser != requesterHSUser {
		return caps.Has(ApproveDevices)
	}
	return CanApprove(caps, approverHSUser, requesterHSUser)
}

// CanManageNode: write_machines, or the device's own user.
func CanManageNode(caps Cap, hsUser string, n hs.Node) bool {
	if caps.Has(WriteMachines) {
		return true
	}
	return caps.Has(UIAccess) && hsUser != "" && n.UserName() == hsUser
}
