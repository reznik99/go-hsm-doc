package main

import (
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
)

func ListTokens(mod *P11) ([]pkcs11.ObjectHandle, error) {
	options := []string{}
	for _, slot := range mod.GetSlots() {
		options = append(options, slot.Label)
	}

	slotLabel, err := pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc).WithOptions(options).Show("Select Slot")
	if err != nil {
		return nil, fmt.Errorf("slot selection error: %s", err)
	}

	selectedSlot := -1
	for slotID, slot := range mod.GetSlots() {
		if slot.Label == slotLabel {
			selectedSlot = int(slotID)
		}
	}

	err = mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return nil, fmt.Errorf("open session error: %s", err)
	}

	pin, err := interactive.WithMask("*").Show("Slot/Partition PIN (optional)")
	if err != nil {
		return nil, fmt.Errorf("error reading Slot/Partition PIN: %s", err)
	}
	if pin != "" {
		mod.Login(pin)
	}

	return mod.FindObjects([]*pkcs11.Attribute{})
}

func ExitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	os.Exit(0)
}
