package main

import (
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/reznik99/go-hsm-doc/internal"
)

const (
	HSMInfoCMD      = "List HSM Info"
	SlotsCMD        = "List Slots"
	TokensCMD       = "List Tokens"
	FindTokenCMD    = "Find Token"
	GenerateKeysCMD = "Generate Keys"
	ImportKeysCMD   = "Import Keys"
	ExitCMD         = "Exit"
)

var (
	Version = "Development"
	logger  = pterm.Logger{
		Formatter: pterm.LogFormatterColorful,
		Writer:    os.Stdout,
		Level:     pterm.LogLevelTrace,
		KeyStyles: map[string]pterm.Style{},
		MaxWidth:  80,
	}
	TopLevelOptions    = []string{HSMInfoCMD, SlotsCMD, TokensCMD, FindTokenCMD, GenerateKeysCMD, ImportKeysCMD, ExitCMD}
	InteractiveText    = pterm.DefaultInteractiveTextInput.WithOnInterruptFunc(ExitFunc)
	InteractiveConfirm = pterm.DefaultInteractiveConfirm.WithOnInterruptFunc(ExitFunc)
	InteractiveSelect  = pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc).WithMaxHeight(len(TopLevelOptions))
	TitlePrefix        = putils.LettersFromStringWithStyle("HSM", pterm.FgCyan.ToStyle())
	Title              = putils.LettersFromStringWithStyle("-DOCTOR", pterm.FgLightMagenta.ToStyle())
)

func fatal(message string, args ...any) {
	pterm.Error.Printfln(message, args...)
	os.Exit(1)
}

func PrintTitle() {
	pterm.Info.Println("\033[H\033[2J")
	pterm.DefaultBigText.WithLetters(TitlePrefix, Title).Render()
	pterm.Info.Printfln("Version %q", Version)
}

func PressEnterToContinue() {
	_, err := InteractiveText.Show("Press any key to continue")
	if err != nil {
		logger.Error("Error reading user input", logger.Args("", err))
	}
}

func main() {
	PrintTitle()

	modulePath, err := InteractiveText.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		fatal("Error reading user input: %s", err)
	}
	if modulePath == "" {
		fatal("Module path is empty but required")
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	multi.Start()

	time.Sleep(time.Second / 2)
	mod, err := internal.NewP11(modulePath, logger)
	if err != nil {
		fatal("Error loading module: '%s'", err)
	}

	loader.Info("Loaded cryptoki module -> ", modulePath)
	multi.Stop()

	// Main program loop
	for {
		PrintTitle()

		option, err := InteractiveSelect.WithOptions(TopLevelOptions).Show("Select Operation")
		if err != nil {
			logger.Error("Option selection error", logger.Args("", err))
			continue
		}

		switch option {
		case HSMInfoCMD:
			err := ListHSMInfo(mod)
			if err != nil {
				logger.Error("Error getting HSM info", logger.Args("", err))
			}
		case SlotsCMD:
			err := ListSlots(mod)
			if err != nil {
				logger.Error("Error listing slots", logger.Args("", err))
			}
		case TokensCMD:
			err := ListTokens(mod)
			if err != nil {
				logger.Error("Error listing tokens", logger.Args("", err))
			}
		case FindTokenCMD:
			err := FindToken(mod)
			if err != nil {
				logger.Error("Error during Find Token operation", logger.Args("", err))
			}
		case GenerateKeysCMD:
			err := GenerateKey(mod)
			if err != nil {
				logger.Error("Error generating key", logger.Args("", err))
			}
		case ImportKeysCMD:
			err := ImportKey(mod)
			if err != nil {
				logger.Error("Error importing key", logger.Args("", err))
			}
		case ExitCMD:
			ExitFunc()
		}

		// Pause CLI to let user read output of command. On keypress, clear screen and relist CLI options.
		PressEnterToContinue()
	}
}
