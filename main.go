package main

import (
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

var (
	logger          = pterm.DefaultLogger
	interactive     = pterm.DefaultInteractiveTextInput.WithOnInterruptFunc(ExitFunc)
	TitlePrefix     = putils.LettersFromStringWithStyle("HSM", pterm.FgCyan.ToStyle())
	Title           = putils.LettersFromStringWithStyle("-DOCTOR", pterm.FgLightMagenta.ToStyle())
	TopLevelOptions = []string{"List Slots", "List Tokens", "Search Token", "Crypto Tests", "Performance Tests", "Exit"}
)

func fatal(message string, args ...any) {
	pterm.Error.WithFatal(true).Printfln(message, args...)
}

func PrintTitle() {
	logger.Print("\033[H\033[2J")
	pterm.DefaultBigText.WithLetters(TitlePrefix, Title).Render()
	logger.Info("Version 0.0.1\n")
}

func PressEnterToContinue() {
	_, err := pterm.DefaultInteractiveContinue.Show("Return to menu?")
	if err != nil {
		fatal("Option selection error: %s", err)
	}
}

func main() {
	PrintTitle()

	modulePath, err := interactive.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		fatal("Error loading module: %s", err)
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	multi.Start()

	time.Sleep(1 * time.Second)
	mod, err := NewP11(modulePath)
	if err != nil {
		fatal("Error loading module: %s", err)
	}

	loader.Info("Loaded cryptoki module -> ", modulePath)
	multi.Stop()

	// Main program loop
	for {
		option, err := pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc).WithOptions(TopLevelOptions).Show()
		if err != nil {
			fatal("Option selection error: %s", err)
		}

		switch option {
		case "List Slots":
			slots, err := mod.GetSlots()
			if err != nil {
				logger.Error("Error getting slots", logger.Args("", err))
				break
			}
			logger.Info("Slots found", logger.Args("", len(slots)))
			for slotID, slot := range slots {
				logger.Info("->", logger.Args("Label", slot.Label), logger.Args("SlotID", slotID))
			}
		case "List Tokens":
			objects, err := ListTokens(mod)
			if err != nil {
				logger.Error("Error Listing tokens", logger.Args("", err))
				break
			}
			if len(objects) == 0 {
				logger.Warn("No objects found")
				break
			}
			for _, o := range objects {
				attribs, _ := mod.ctx.GetAttributeValue(mod.sh, o, []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
					pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				})
				logger.Info("->",
					logger.Args("ID", o),
					logger.Args("Label", string(attribs[0].Value)),
					logger.Args("Type", ClassToString(attribs[1].Value)))
			}
		case "Exit":
			ExitFunc()
		}

		// Pause CLI to let user read output of command. On keypress, clear screen and restart CLI options.
		PressEnterToContinue()
		PrintTitle()
	}
}
