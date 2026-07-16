VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo "0.1.0")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X github.com/DataDog/pathrunner/pkg/version.Version=$(VERSION) \
           -X github.com/DataDog/pathrunner/pkg/version.GitCommit=$(GIT_COMMIT) \
           -X github.com/DataDog/pathrunner/pkg/version.BuildDate=$(BUILD_DATE)

.PHONY: build dev clean test generate

generate:
	go generate ./pkg/exploits/

build: generate
	go build -ldflags "$(LDFLAGS)" -o pathrunner cmd/pathrunner/main.go

dev:
	go run -ldflags "$(LDFLAGS)" cmd/pathrunner/main.go

clean:
	rm -f pathrunner

test:
	go test ./tests/...
