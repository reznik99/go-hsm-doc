#!/usr/bin/env bash
VERSION=$(git describe --tags)

go build -v -ldflags="-X 'main.Version=${VERSION}'" -o build/main