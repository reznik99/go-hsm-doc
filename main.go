package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

var (
	logger = pterm.Logger{
		Formatter: pterm.LogFormatterColorful,
		Writer:    os.Stdout,
		Level:     pterm.LogLevelTrace,
		KeyStyles: map[string]pterm.Style{},
		MaxWidth:  80,
	}
	Interactive       = pterm.DefaultInteractiveTextInput.WithOnInterruptFunc(ExitFunc)
	InteractiveSelect = pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc)
	TitlePrefix       = putils.LettersFromStringWithStyle("HSM", pterm.FgCyan.ToStyle())
	Title             = putils.LettersFromStringWithStyle("-DOCTOR", pterm.FgLightMagenta.ToStyle())
	TopLevelOptions   = []string{"List HSM Info", "List Slots", "List Tokens", "Generate Key", "Exit"}
)

func fatal(message string, args ...any) {
	pterm.Error.Printfln(message, args...)
	os.Exit(1)
}

func PrintTitle() {
	pterm.Info.Println("\033[H\033[2J")
	pterm.DefaultBigText.WithLetters(TitlePrefix, Title).Render()
	pterm.Info.Println("Version 0.0.1")
}

func PressEnterToContinue() {
	_, err := Interactive.Show("Press any key to continue")
	if err != nil {
		logger.Error("Error reading user input", logger.Args("", err))
	}
}

func main() {
	PrintTitle()

	modulePath, err := Interactive.Show("Input Cryptoki Library path (.dll / .so)")
	if err != nil {
		fatal("Error reading user input: %s", err)
	}
	if modulePath == "" {
		fatal("Module path is empty but required")
	}

	multi := pterm.DefaultMultiPrinter
	loader, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Loading Cryptoki module")
	multi.Start()

	time.Sleep(1 * time.Second)
	mod, err := NewP11(modulePath)
	if err != nil {
		fatal("Error loading module: '%s'", err)
	}

	loader.Info("Loaded cryptoki module -> ", modulePath)
	multi.Stop()

	// Main program loop
	for {
		option, err := InteractiveSelect.WithOptions(TopLevelOptions).Show("Select Operation")
		if err != nil {
			logger.Error("Option selection error", logger.Args("", err))
			continue
		}

		switch option {
		case "List HSM Info":
			info, err := mod.ctx.GetInfo()
			if err != nil {
				logger.Error("Error getting HSM info", logger.Args("", err))
				break
			}
			logger.Info(modulePath,
				logger.Args("ManufacturerID", info.ManufacturerID),
				logger.Args("LibraryDescription", info.LibraryDescription),
				logger.Args("LibraryVersion", fmt.Sprintf("v%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)),
				logger.Args("CryptokiVersion", fmt.Sprintf("v%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)),
				logger.Args("Flags", info.Flags),
			)
		case "List Slots":
			slots, err := mod.GetSlots()
			if err != nil {
				logger.Error("Error getting slots", logger.Args("", err))
				break
			}
			for slotID, slot := range slots {
				si, err := mod.ctx.GetSlotInfo(slotID)
				if err != nil {
					continue
				}
				logger.Info(fmt.Sprintf("-> %s(%d)", slot.Label, slotID),
					logger.Args("Label", slot.Label),
					logger.Args("Model", slot.Model),
					logger.Args("SerialNumber", slot.SerialNumber),
					logger.Args("MaxRwSessionCount", slot.MaxRwSessionCount),
					logger.Args("ManufacturerID", si.ManufacturerID),
					logger.Args("SlotDescription", si.SlotDescription),
					logger.Args("HardwareVersion", fmt.Sprintf("v%d.%d", si.HardwareVersion.Major, si.HardwareVersion.Minor)),
					logger.Args("FirmwareVersion", fmt.Sprintf("v%d.%d", si.FirmwareVersion.Major, si.FirmwareVersion.Minor)),
				)
			}
		case "List Tokens":
			err := ListTokens(mod)
			if err != nil {
				logger.Error("Error listing tokens", logger.Args("", err))
			}
		case "Generate Key":
			err := GenerateKey(mod)
			if err != nil {
				logger.Error("Error generating key", logger.Args("", err))
			}
		case "Exit":
			ExitFunc()
		}

		// Pause CLI to let user read output of command. On keypress, clear screen and restart CLI options.
		PressEnterToContinue()
		PrintTitle()
	}
}
