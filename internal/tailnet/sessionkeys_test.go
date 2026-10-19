package tailnet

import (
	"testing"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
)

func TestSessionKeysOwns(t *testing.T) {
	k := &SessionKeys{}
	now := time.Unix(1000, 0)
	k.now = func() time.Time { return now }
	k.Add("77")
	if !k.Owns(hs.Node{PreAuthKey: &hs.NodeKeyRef{ID: "77"}}) {
		t.Fatal("own key not recognised")
	}
	if k.Owns(hs.Node{Name: "meshpanel-ssh-evil"}) || k.Owns(hs.Node{PreAuthKey: &hs.NodeKeyRef{ID: "78"}}) {
		t.Fatal("foreign node recognised")
	}
	k.Release("77")
	if !k.Owns(hs.Node{PreAuthKey: &hs.NodeKeyRef{ID: "77"}}) {
		t.Fatal("released key forgotten before its grace period")
	}
	now = now.Add(11 * time.Minute)
	if k.Owns(hs.Node{PreAuthKey: &hs.NodeKeyRef{ID: "77"}}) {
		t.Fatal("released key kept forever")
	}
}
