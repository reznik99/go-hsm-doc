package main

import (
	"os"

	"github.com/reznik99/go-hsm-doc/internal/cli"
)

var Version = "Development"

func main() {
	if err := cli.New(Version).Run(); err != nil {
		os.Exit(1)
	}
}
