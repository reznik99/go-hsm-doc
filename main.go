package main

import (
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

var (
	logger          = pterm.DefaultLogger
	TitlePrefix     = putils.LettersFromStringWithStyle("HSM", pterm.FgCyan.ToStyle())
	Title           = putils.LettersFromStringWithStyle("-DOCTOR", pterm.FgLightMagenta.ToStyle())
	TopLevelOptions = []string{"List Slots", "List Tokens", "Search Token", "Crypto Tests", "Performance Tests", "Exit"}
)

func exitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	os.Exit(0)
}
func fatal(message string, args ...any) {
	pterm.Error.WithFatal(true).Printfln(message, args...)
}

func main() {
	pterm.DefaultBigText.WithLetters(TitlePrefix, Title).Render()
	logger.Info("Started HSM-DOCTOR v0.0.1...\n")

	modulePath, err := pterm.DefaultInteractiveTextInput.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		fatal("Error loading module: %s", err)
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	multi.Start()
	time.Sleep(1 * time.Second)

	mod, err := NewP11(modulePath)
	loader.Info("Loaded cryptoki module %s", modulePath)

	multi.Stop()

	pin, err := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Slot/Partition PIN")
	if err != nil {
		fatal("Error reading Slot/Partition PIN: %s", err)
	}
	mod.Login(pin)

	// Main program loop
	for {
		option, err := pterm.DefaultInteractiveSelect.WithOnInterruptFunc(exitFunc).WithOptions(TopLevelOptions).Show()
		if err != nil {
			fatal("Option selection error: %s", err)
		}

		logger.Info("Selected", logger.Args("Option", option))
		switch option {
		case "ListTokens":
			// mod.ctx.GetSlotList(true)
		}
	}
}
