package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/miekg/pkcs11"
)

var algorithms = []string{"RSA", "EC", "AES", "3DES", "DES"}
var keyLengths = map[string][]string{
	"RSA":  {"1024", "2048", "4096"},
	"EC":   {"256", "384", "512"},
	"AES":  {"128", "192", "256"},
	"3DES": {"128", "192"},
	"DES":  {"64"},
}

func GenerateKey(mod *P11) error {

	// Select Slot for key
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	// Select Key Label for key
	keyLabel, err := Interactive.Show("Key Label")
	if err != nil {
		return err
	}

	// Select Key Algorithm
	algorithm, err := InteractiveSelect.WithOptions(algorithms).Show("Select Algorithm")
	if err != nil {
		return err
	}

	// Select Key length
	keyLength, err := InteractiveSelect.WithOptions(keyLengths[algorithm]).Show("Select Keylength")
	if err != nil {
		return err
	}
	length, _ := strconv.Atoi(keyLength)

	// Open session and login to slot
	if err = mod.OpenSession(selectedSlot); err != nil {
		return err
	}
	if err = Login(mod, selectedSlot); err != nil {
		return err
	}

	switch algorithm {
	case "RSA":

	case "EC":

	case "AES":
		err = mod.GenerateAESKey(selectedSlot, keyLabel, length, false)
	case "3DES":

	}
	if err != nil {
		return err
	}

	return nil
}

func ListTokens(mod *P11) error {
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	err = mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %s", err)
	}

	err = Login(mod, selectedSlot)
	if err != nil {
		return err
	}

	objects, err := mod.FindObjects(selectedSlot, []*pkcs11.Attribute{})
	if err != nil {
		return err
	}
	if len(objects) == 0 {
		return fmt.Errorf("no objects found")
	}

	sh, ok := mod.sessions[selectedSlot]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", selectedSlot)
	}

	for _, o := range objects {
		attribs, _ := mod.ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		logger.Info(fmt.Sprintf("-> %s(%d)", attribs[0].Value, o),
			logger.Args("Label", string(attribs[0].Value)),
			logger.Args("Type", TypeToString(attribs[1].Value)),
			logger.Args("Type", ClassToString(attribs[2].Value)),
			logger.Args("Handle", o),
		)
	}

	return nil
}

func Login(mod *P11, slotID uint) error {
	pin, err := Interactive.WithMask("*").Show("Slot/Partition PIN (optional)")
	if err != nil {
		return fmt.Errorf("error reading Slot/Partition PIN: %s", err)
	}
	if pin != "" {
		err = mod.Login(slotID, pin)
		if err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
			return err
		}
	}
	return nil
}

func ExitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	os.Exit(0)
}

func PromptSlotSelection(mod *P11) (uint, error) {
	options := []string{}
	slots, err := mod.GetSlots()
	if err != nil {
		return 0, err
	}

	for _, slot := range slots {
		options = append(options, slot.Label)
	}

	slotLabel, err := InteractiveSelect.WithOptions(options).Show("Select Slot")
	if err != nil {
		return 0, fmt.Errorf("slot selection error: %s", err)
	}

	for slotID, slot := range slots {
		if slot.Label == slotLabel {
			return slotID, nil
		}
	}

	return 0, fmt.Errorf("slot not selected")
}
