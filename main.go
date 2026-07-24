package main

import "os"

var Version = "Development"

func main() {
	app := NewApp()
	if err := app.run(); err != nil {
		app.log.Error("Application failed", app.log.Args("error", err))
		os.Exit(1)
	}
}
