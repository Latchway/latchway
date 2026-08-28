SHELL := /bin/sh

GO ?= go
PNPM ?= pnpm
SQLC_IMAGE ?= sqlc/sqlc:1.31.1
FUZZ_TIME ?= 3s
FUZZ_PARALLEL ?= 2
VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/latchway/latchway/internal/buildinfo.Version=$(VERSION) -X github.com/latchway/latchway/internal/buildinfo.Commit=$(COMMIT) -X github.com/latchway/latchway/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: all build build-go build-web check check-generated clean compose-up compose-down fmt fuzz-smoke generate test test-race vet

all: check build

build: build-web build-go

build-go:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/latchway ./cmd/latchway

build-web:
	cd web/console && $(PNPM) install --frozen-lockfile
	cd web/console && $(PNPM) build

check: fmt check-generated vet test
	cd web/console && $(PNPM) install --frozen-lockfile
	cd web/console && $(PNPM) check

fmt:
	@files="$$(gofmt -l adapters cmd conformance internal migrations web/console/*.go)"; \
	if test -n "$$files"; then echo "$$files"; exit 1; fi

fuzz-smoke:
	$(GO) test ./internal/attestation -run '^$$' -fuzz '^FuzzBindingCanonicalJSON$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/dpop -run '^$$' -fuzz '^FuzzValidate$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/dpop -run '^$$' -fuzz '^FuzzParsePublicJWK$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/dpop -run '^$$' -fuzz '^FuzzNormalizeHTU$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/session -run '^$$' -fuzz '^FuzzPreflightAccessToken$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/clientapi -run '^$$' -fuzz '^FuzzProtectedCredentialHeaders$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/configuration -run '^$$' -fuzz '^FuzzActiveSnapshotCompilation$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/configuration -run '^$$' -fuzz '^FuzzCompiledInputAccountingProfile$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./adapters/protocol/openaichat -run '^$$' -fuzz '^FuzzTrustedInputPreflight$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/policy -run '^$$' -fuzz '^FuzzResolve$$' -fuzztime=$(FUZZ_TIME) -parallel=$(FUZZ_PARALLEL)

generate:
	docker run --rm --volume "$(CURDIR):/src" --workdir /src $(SQLC_IMAGE) generate

check-generated: generate
	git diff --exit-code -- internal/database/dbsql

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race ./...

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

clean:
	$(GO) clean -testcache
	$(RM) -r bin web/console/dist web/console/coverage
