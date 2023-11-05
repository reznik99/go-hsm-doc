#!/usr/bin/env bash
VERSION=$(git describe --always)

go build -v -ldflags="-X 'main.Version=${VERSION}'" -o build/main