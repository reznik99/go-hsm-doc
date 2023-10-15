package main

import (
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
)

func ListTokens(mod *P11) error {
	options := []string{}
	for _, slot := range mod.GetSlots() {
		options = append(options, slot.Label)
	}

	slotLabel, err := pterm.DefaultInteractiveSelect.WithOnInterruptFunc(ExitFunc).WithOptions(options).Show("Select Slot")
	if err != nil {
		return fmt.Errorf("slot selection error: %s", err)
	}

	selectedSlot := -1
	for slotID, slot := range mod.GetSlots() {
		if slot.Label == slotLabel {
			selectedSlot = int(slotID)
		}
	}

	err = mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %s", err)
	}

	pin, err := interactive.WithMask("*").Show("Slot/Partition PIN (optional)")
	if err != nil {
		return fmt.Errorf("error reading Slot/Partition PIN: %s", err)
	}
	if pin != "" {
		mod.Login(pin)
	}

	objects, err := mod.FindObjects([]*pkcs11.Attribute{})
	if err != nil {
		return err
	}

	if len(objects) == 0 {
		logger.Info("No objects found")
		return nil
	}
	for _, o := range objects {
		attribs, _ := mod.ctx.GetAttributeValue(mod.sh, o, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		})
		logger.Info("->", logger.Args("ID", o), logger.Args("Label", string(attribs[0].Value)), logger.Args("Type", attribs[1].Value))
	}

	return nil
}

func ExitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	os.Exit(0)
}
