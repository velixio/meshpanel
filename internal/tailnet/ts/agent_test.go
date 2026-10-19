package ts

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestHostInfoFromHostinfo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := &tailcfg.Hostinfo{OS: "linux", OSVersion: "6.1.0", Distro: "debian", DistroVersion: "12", IPNVersion: "1.84.0-t1234", Hostname: "build-01", DeviceModel: ""}
	eps := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	got := hostInfoFrom(h, eps, 7, now)
	if got.OS != "Linux" || got.OSVersion != "debian 12 (kernel 6.1.0)" || got.Tailscale != "1.84.0" || got.Hostname != "build-01" {
		t.Fatalf("%+v", got)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0] != "203.0.113.5:41641" || got.HomeDERP != 7 || !got.Updated.Equal(now) {
		t.Fatalf("%+v", got)
	}
	ios := hostInfoFrom(&tailcfg.Hostinfo{OS: "iOS", OSVersion: "18.1", DeviceModel: "iPhone16,1", IPNVersion: "1.86.2"}, nil, 0, now)
	if ios.OS != "iOS" || ios.OSVersion != "18.1" || ios.Device != "iPhone16,1" {
		t.Fatalf("%+v", ios)
	}
}
