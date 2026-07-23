VERSION := $(shell git describe --tags)

.PHONY: all test build lint

all: lint test build

# --- Test ---
test:
	@mkdir -p build
	go test -race -coverprofile=build/coverage.out ./...
	@go tool cover -func=build/coverage.out | tail -n 1
	@go tool cover -html=build/coverage.out -o build/coverage.html
	@echo "coverage report: build/coverage.html"

# --- Build ---
build:
	@mkdir -p build
	go build -v -ldflags="-X 'main.Version=$(VERSION)'" -o build/main .

# --- Lint ---
lint:
	golangci-lint run ./...
