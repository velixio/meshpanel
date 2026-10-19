package tailnet

import (
	"testing"
	"time"
)

func TestHostCache(t *testing.T) {
	c := &HostCache{}
	c.Store(map[string]HostInfo{"nodekey:aa": {OS: "Linux"}}, time.Now(), nil)
	if hi, ok := c.Info("nodekey:aa"); !ok || hi.OS != "Linux" {
		t.Fatal("cache miss")
	}
	if _, ok := c.Info("nodekey:bb"); ok {
		t.Fatal("phantom entry")
	}
	if st := c.State(); !st.Running || st.Peers != 1 {
		t.Fatalf("%+v", st)
	}
}
