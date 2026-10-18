VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := meshpanel

.PHONY: build test vet fmt lint check run release-snapshot clean size

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/meshpanel

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
	rm -rf $(BIN) dist
