package perm

import (
	"testing"

	"github.com/meshpanel/meshpanel/internal/hs"
)

func TestRolesMatrix(t *testing.T) {
	if Effective("member", 0).Has(ReadMachines) {
		t.Fatal("member must not read all machines")
	}
	if !Effective("member", 0).Has(UIAccess) {
		t.Fatal("member needs ui access")
	}
	owner := Effective("owner", 0)
	for _, c := range All {
		if !owner.Has(c.Cap) {
			t.Fatalf("owner lacks %s", c.Name)
		}
	}
	if Effective("admin", 0).Has(Owner) {
		t.Fatal("admin is not owner")
	}
	if !Effective("admin", 0).Has(ApproveDevices) || !Effective("admin", 0).Has(ApproveSSH) {
		t.Fatal("admin approves")
	}
	if Effective("auditor", 0).Has(WriteMachines) || !Effective("auditor", 0).Has(ReadAudit) {
		t.Fatal("auditor is read-only with audit")
	}
	if !Effective("viewer", ApproveDevices).Has(ApproveDevices) {
		t.Fatal("extra caps apply")
	}
	if Effective("bogus", 0) != 0 {
		t.Fatal("unknown role has caps")
	}
}

func node(id, user string, tags ...string) hs.Node {
	return hs.Node{ID: id, User: &hs.User{ID: "1", Name: user}, Tags: tags}
}

func TestScopeFiltersNodes(t *testing.T) {
	nodes := []hs.Node{node("1", "ravi"), node("2", "anna"), node("3", "ravi", "tag:server")}
	s := ScopeFor(Effective("member", 0), "ravi")
	got := s.Nodes(nodes)
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("member sees %+v", got)
	}
	if s.Node(nodes[1]) {
		t.Fatal("member sees anna's node")
	}
	if ScopeFor(Effective("member", 0), "").Nodes(nodes) != nil {
		t.Fatal("unlinked member sees nodes")
	}
	if len(ScopeFor(Effective("viewer", 0), "").Nodes(nodes)) != 3 {
		t.Fatal("viewer sees all")
	}
}

func TestCanApproveOwn(t *testing.T) {
	own := Effective("member", ApproveDevicesOwn)
	if !CanApprove(own, "ravi", "ravi") || CanApprove(own, "ravi", "anna") {
		t.Fatal("own-only approval")
	}
	if CanApprove(Effective("member", 0), "ravi", "ravi") {
		t.Fatal("plain member self-approves")
	}
	if !CanApprove(Effective("admin", 0), "x", "anna") {
		t.Fatal("admin approves anyone")
	}
	if CanApprove(own, "", "") {
		t.Fatal("unlinked account self-approves the empty user")
	}
}

func TestCanManageNode(t *testing.T) {
	n := node("1", "ravi")
	if !CanManageNode(Effective("member", 0), "ravi", n) || CanManageNode(Effective("member", 0), "anna", n) {
		t.Fatal("member manages own only")
	}
	if CanManageNode(Effective("viewer", 0), "", n) || !CanManageNode(Effective("it_admin", 0), "", n) {
		t.Fatal("write_machines gate")
	}
}

func TestParseNames(t *testing.T) {
	c := Parse([]string{"approve_devices", "read_audit", "nope"})
	if !c.Has(ApproveDevices) || !c.Has(ReadAudit) || c.Has(Owner) {
		t.Fatal(c.Names())
	}
}
