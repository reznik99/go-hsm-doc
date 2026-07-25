package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/reznik99/go-hsm-doc/internal/hsm"
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

type App struct {
	version             string
	log                 pterm.Logger
	mod                 *hsm.P11
	interactiveText     *pterm.InteractiveTextInputPrinter
	interactiveConfirm  *pterm.InteractiveConfirmPrinter
	interactiveSelect   *pterm.InteractiveSelectPrinter
	titlePrefix         pterm.Letters
	title               pterm.Letters
	topLevelOptions     []string
	capabilities        map[uint]slotCapabilities
	secretKeyAlgorithms []string
	keyOperations       []string
}

func New(version string) *App {
	app := &App{
		version: version,
		log: pterm.Logger{
			Formatter: pterm.LogFormatterColorful,
			Writer:    os.Stdout,
			Level:     pterm.LogLevelTrace,
			KeyStyles: map[string]pterm.Style{},
			MaxWidth:  100,
		},
		titlePrefix: putils.LettersFromStringWithStyle(
			"HSM", pterm.FgCyan.ToStyle(),
		),
		title: putils.LettersFromStringWithStyle(
			"-DOCTOR", pterm.FgLightMagenta.ToStyle(),
		),
		topLevelOptions:     []string{HSMInfoCMD, SlotsCMD, TokensCMD, FindTokenCMD, GenerateKeysCMD, ImportKeysCMD, ExitCMD},
		capabilities:        make(map[uint]slotCapabilities),
		secretKeyAlgorithms: []string{"AES", "3DES", "DES"},
		keyOperations:       []string{"Go Back", "Info", "Export", "Delete"},
	}
	app.interactiveText = pterm.DefaultInteractiveTextInput.WithOnInterruptFunc(app.close)
	app.interactiveConfirm = pterm.DefaultInteractiveConfirm.WithOnInterruptFunc(app.close)
	app.interactiveSelect = pterm.DefaultInteractiveSelect.WithOnInterruptFunc(app.close).WithMaxHeight(len(app.topLevelOptions))
	return app
}

func (a *App) close() {
	a.log.Info("Exiting HSM-DOCTOR...")
	if a.mod != nil {
		if err := errors.Join(a.mod.CloseAllSessions(), a.mod.Finalize()); err != nil {
			a.log.Error("Failed to close application", a.log.Args("error", err))
		}
		a.mod = nil
	}
	os.Exit(0)
}

func (a *App) printTitle() {
	pterm.Info.Println("\033[H\033[2J")
	if err := pterm.DefaultBigText.WithLetters(a.titlePrefix, a.title).Render(); err != nil {
		a.log.Error("Failed to render title", a.log.Args("error", err))
	}
	pterm.Info.Printfln("Version %q", a.version)
}

func (a *App) pressEnterToContinue() {
	_, err := a.interactiveText.Show("Press any key to continue")
	if err != nil {
		a.log.Error("Failed to read user input", a.log.Args("error", err))
	}
}

// Run starts the interactive session, logging a fatal error if it fails.
func (a *App) Run() error {
	if err := a.run(); err != nil {
		a.log.Error("Application failed", a.log.Args("error", err))
		return err
	}
	return nil
}

func (a *App) run() error {
	a.printTitle()

	modulePath, err := a.interactiveText.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		return fmt.Errorf("read module path: %w", err)
	}
	if modulePath == "" {
		return errors.New("module path is required")
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	if _, err := multi.Start(); err != nil {
		a.log.Error("Failed to start output printer", a.log.Args("error", err))
	}

	time.Sleep(time.Second / 2)
	a.mod, err = hsm.NewP11(modulePath)
	if err != nil {
		if _, serr := multi.Stop(); serr != nil {
			a.log.Error("Failed to stop output printer", a.log.Args("error", serr))
		}
		return fmt.Errorf("load module: %w", err)
	}
	if err := a.loadCapabilities(); err != nil {
		a.log.Warn("Some capabilities could not be loaded", a.log.Args("error", err))
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		a.close()
	}()

	loader.Info("Loaded cryptoki module -> ", modulePath)
	if _, err := multi.Stop(); err != nil {
		a.log.Error("Failed to stop output printer", a.log.Args("error", err))
	}

	for {
		a.printTitle()

		option, err := a.interactiveSelect.WithOptions(a.topLevelOptions).Show("Select Operation")
		if err != nil {
			a.log.Error("Failed to select operation", a.log.Args("error", err))
			continue
		}

		switch option {
		case HSMInfoCMD:
			if err := a.listHSMInfo(); err != nil {
				a.log.Error("Failed to get HSM info", a.log.Args("error", err))
			}
		case SlotsCMD:
			if err := a.listSlots(); err != nil {
				a.log.Error("Failed to list slots", a.log.Args("error", err))
			}
		case TokensCMD:
			if err := a.listTokens(); err != nil {
				a.log.Error("Failed to list tokens", a.log.Args("error", err))
			}
		case FindTokenCMD:
			if err := a.findToken(); err != nil {
				a.log.Error("Failed to find token", a.log.Args("error", err))
			}
		case GenerateKeysCMD:
			if err := a.generateKey(); err != nil {
				a.log.Error("Failed to generate key", a.log.Args("error", err))
			}
		case ImportKeysCMD:
			if err := a.importKey(); err != nil {
				a.log.Error("Failed to import key", a.log.Args("error", err))
			}
		case ExitCMD:
			a.close()
		}

		a.pressEnterToContinue()
	}
}
