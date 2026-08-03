VERSION := $(shell git describe --tags)
# Packages under test, minus generated mocks (they'd dilute coverage).
COVER_PKGS := $(shell go list ./... | grep -v /mocks)

.PHONY: all mocks test build lint

all: mocks lint test build

# --- Mocks ---
# Pinned via `go run` so no separate install is needed and the version is reproducible.
mocks:
	go run github.com/vektra/mockery/v2@v2.53.6

# --- Test ---
test:
	@mkdir -p build
	go test -race -coverprofile=build/coverage.out $(COVER_PKGS)
	@go tool cover -func=build/coverage.out | tail -n 1
	@go tool cover -html=build/coverage.out -o build/coverage.html
	@echo "coverage report: build/coverage.html"

# --- Build ---
build:
	@mkdir -p build
	go build -trimpath -v -ldflags="-X 'main.Version=$(VERSION)'" -o build/hsm-doctor .

# --- Lint ---
lint:
	golangci-lint run ./...
