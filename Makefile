VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
# Trims Tailscale features meshpanel doesn't use (keeps the binary < 40 MB).
TSTAGS := ts_omit_aws,ts_omit_kube,ts_omit_drive,ts_omit_taildrop,ts_omit_tpm,ts_omit_bird,ts_omit_capture,ts_omit_clientupdate,ts_omit_completion,ts_omit_debugeventbus,ts_omit_desktop_sessions,ts_omit_doctor,ts_omit_synology,ts_omit_systray,ts_omit_syspolicy,ts_omit_tap,ts_omit_wakeonlan,ts_omit_webclient,ts_omit_ssh,ts_omit_appconnectors,ts_omit_relayserver,ts_omit_portmapper,ts_omit_netlog,ts_omit_tailnetlock,ts_omit_posture,ts_omit_flashappliance,ts_omit_qrcodes,ts_omit_networkmanager,ts_omit_resolved,ts_omit_iptables,ts_omit_dbus,ts_omit_linuxdnsfight,ts_omit_oauthkey,ts_omit_identityfederation,ts_omit_cloud,ts_omit_captiveportal,ts_omit_advertiseexitnode,ts_omit_advertiseroutes,ts_omit_useexitnode,ts_omit_outboundproxy,ts_omit_webbrowser,ts_omit_colorable,ts_omit_hujsonconf,ts_omit_remoteconfig,ts_omit_usermetrics,ts_omit_clientmetrics,ts_omit_debugportmapper,ts_omit_conn25,ts_omit_cliconndiag,ts_omit_sdnotify,ts_omit_syslog,ts_omit_linkspeed,ts_omit_gro,ts_omit_tundevstats
BIN := bin/meshpanel

.PHONY: build test vet fmt lint check run release-snapshot clean size

build:
	CGO_ENABLED=0 go build -tags "$(TSTAGS)" -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/meshpanel

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

lint:
	@test -z "$$(gofmt -l cmd internal)" || (echo "gofmt needed:"; gofmt -l cmd internal; exit 1)
	go vet ./...

check: lint test

size: build
	@bytes=$$(wc -c < $(BIN)); echo "binary: $$((bytes/1024/1024)) MB"; test $$bytes -lt 41943040

run: build
	./$(BIN) serve -c deploy/config.example.yaml

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
