VERSION := $(shell git describe --tags)

.PHONY: all test build lint

all: lint test build

# --- Test ---
test:
	go test -race ./...

# --- Build ---
build:
	@mkdir -p build
	go build -v -ldflags="-X 'main.Version=$(VERSION)'" -o build/main .

# --- Lint ---
lint:
	golangci-lint run ./...
