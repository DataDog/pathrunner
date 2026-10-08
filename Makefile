VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo "0.1.0")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X github.com/DataDog/pathrunner/pkg/version.Version=$(VERSION) \
           -X github.com/DataDog/pathrunner/pkg/version.GitCommit=$(GIT_COMMIT) \
           -X github.com/DataDog/pathrunner/pkg/version.BuildDate=$(BUILD_DATE)

DOCS_OUT ?= docs/reference

.PHONY: build dev clean test generate build-jars docs docs-check update-docs render-module-tapes

generate:
	go generate ./pkg/exploits/

build: generate
	go build -ldflags "$(LDFLAGS)" -o pathrunner cmd/pathrunner/main.go

# Regenerate the documentation reference artifacts (pathrunner-reference.json +
# per-command/per-module markdown) consumed by pathfinding.cloud/pathrunner.
# Runs the standalone gendocs binary so all module/payload init() hooks fire.
docs:
	go run -ldflags "$(LDFLAGS)" ./cmd/gendocs --out "$(DOCS_OUT)"

# Regen JSON reference, re-render GIFs, stage everything, and print the
# pathfinding.cloud reminder. Pass tape names as args to render only specific
# tapes: make update-docs TAPES="identity-switch workspace-list"
update-docs: build
	@./scripts/update-docs.sh $(TAPES)

# Render "use <id> → show payloads" WebMs for every exploit module (or a subset).
# Pass MODULE to filter by ID or service prefix: make render-module-tapes MODULE=lambda
render-module-tapes: build
	@./scripts/render-module-tapes.sh $(MODULE)

# Fail if the committed docs artifacts are stale (used in CI, like register.go).
# Volatile generator fields (pathrunnerVersion, gitCommit) are excluded from the
# diff because CI shallow-clones lack tags, producing a different git describe
# output than the locally committed value. Real content changes still fail.
docs-check: docs
	@CONTENT_DIFF=$$(git diff -- "$(DOCS_OUT)" | grep '^[+-][^+-]' | grep -Ev '"pathrunnerVersion":|"gitCommit":'); \
	if [ -n "$$CONTENT_DIFF" ]; then \
		echo "ERROR: docs/reference is out of date. Run 'make docs' and commit."; \
		git diff -- "$(DOCS_OUT)"; \
		exit 1; \
	fi

dev:
	go run -ldflags "$(LDFLAGS)" cmd/pathrunner/main.go

clean:
	rm -f pathrunner

test:
	go test ./tests/...

# Rebuild Flink payload JARs after changing Java source under pkg/payloads/*/jars/.
# Requires Docker. The built JARs are committed and embedded in the binary via go:embed.
build-jars:
	@bash pkg/payloads/kinesisanalytics/jars/build.sh
