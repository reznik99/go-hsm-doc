package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
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
		MaxWidth:  100,
	}
	TopLevelOptions    = []string{HSMInfoCMD, SlotsCMD, TokensCMD, FindTokenCMD, GenerateKeysCMD, ImportKeysCMD, ExitCMD}
	InteractiveText    = pterm.DefaultInteractiveTextInput.WithOnInterruptFunc(ExitFunc)
	InteractiveConfirm = pterm.DefaultInteractiveConfirm.WithOnInterruptFunc(ExitFunc)
	InteractiveSelect  = pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc).WithMaxHeight(len(TopLevelOptions))
	TitlePrefix        = putils.LettersFromStringWithStyle("HSM", pterm.FgCyan.ToStyle())
	Title              = putils.LettersFromStringWithStyle("-DOCTOR", pterm.FgLightMagenta.ToStyle())
	mod                *internal.P11
)

func fatal(message string, args ...any) {
	pterm.Error.Printfln(message, args...)
	os.Exit(1)
}

func ExitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	if mod != nil {
		if err := mod.CloseAllSessions(); err != nil {
			logger.Error("Error closing sessions", logger.Args("", err))
		}
		if err := mod.Finalize(); err != nil {
			logger.Error("Error finalizing module", logger.Args("", err))
		}
	}
	os.Exit(0)
}

func PrintTitle() {
	pterm.Info.Println("\033[H\033[2J")
	if err := pterm.DefaultBigText.WithLetters(TitlePrefix, Title).Render(); err != nil {
		logger.Error("Error rendering title", logger.Args("", err))
	}
	pterm.Info.Printfln("Version %q", Version)
}

func PressEnterToContinue() {
	_, err := InteractiveText.Show("Press any key to continue")
	if err != nil {
		logger.Error("Error reading user input", logger.Args("", err))
	}
}

func main() {
	if err := run(); err != nil {
		fatal("%s", err)
	}
}

func run() error {
	PrintTitle()

	modulePath, err := InteractiveText.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		return fmt.Errorf("read module path: %w", err)
	}
	if modulePath == "" {
		return errors.New("module path is required")
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	if _, err := multi.Start(); err != nil {
		logger.Error("Error starting output printer", logger.Args("", err))
	}

	time.Sleep(time.Second / 2)
	mod, err = internal.NewP11(modulePath, logger)
	if err != nil {
		if _, serr := multi.Stop(); serr != nil {
			logger.Error("Error stopping output printer", logger.Args("", serr))
		}
		return fmt.Errorf("load module: %w", err)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ExitFunc()
	}()

	loader.Info("Loaded cryptoki module -> ", modulePath)
	if _, err := multi.Stop(); err != nil {
		logger.Error("Error stopping output printer", logger.Args("", err))
	}

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
