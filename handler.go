package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
)

var (
	keyLengths = map[string][]string{
		"RSA":  {"1024", "2048", "4096"},
		"EC":   {"256", "384", "512"},
		"AES":  {"128", "192", "256"},
		"3DES": {"128", "192"},
		"DES":  {"64"},
	}
	algorithms    = []string{"RSA", "EC", "AES", "3DES", "DES"}
	keyOperations = []string{
		"Go Back",
		"Info",
		"Export",
		"Delete",
	}
)

func PrintObjectInfo(mod *P11, sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	attribs, err := mod.ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		return err
	}
	logger.Info("",
		logger.Args("Algorithm", AttributeToString(attribs[1])),
		logger.Args("Type", AttributeToString(attribs[2])),
		logger.Args("Label", AttributeToString(attribs[0])),
		logger.Args("Handle", o),
	)
	return nil
}

func ExportToken(mod *P11, sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	attribs, err := mod.ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		return err
	}

	algorithmType := binary.LittleEndian.Uint32(attribs[0].Value)
	objectType := binary.LittleEndian.Uint32(attribs[1].Value)

	switch objectType {
	case pkcs11.CKO_CERTIFICATE: // Export certificate without wrapping
		return mod.ExportCertificate(sh, o)
	case pkcs11.CKO_DATA, pkcs11.CKO_PUBLIC_KEY: // Export public key without wrapping
		return mod.ExportPublicKey(sh, o, algorithmType)
	case pkcs11.CKO_PRIVATE_KEY: // Export private key with Symmetric wrapping
		return mod.ExportPrivateKey(sh, o, algorithmType)
	case pkcs11.CKO_SECRET_KEY: // export secret key with Asymmetric wrapping
		return mod.ExportSecretKey(sh, o, algorithmType)
	}

	return nil
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

	start := time.Now()

	switch algorithm {
	case "RSA":
		err = mod.GenerateRSAKeypair(selectedSlot, keyLabel, length, false)
	case "EC":
		err = mod.GenerateECKeypair(selectedSlot, keyLabel, length, false)
	case "AES":
		err = mod.GenerateAESKey(selectedSlot, keyLabel, length, false)
	case "DES", "3DES":
		err = mod.GenerateDESKey(selectedSlot, keyLabel, length, false)
	default:
		err = fmt.Errorf("unrecognized algorithm %s", algorithm)
	}
	if err != nil {
		return err
	}

	pterm.Info.Printfln("Command completed in %dms", time.Since(start).Milliseconds())

	return nil
}

func FindToken(mod *P11) error {

	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	err = mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}

	err = Login(mod, selectedSlot)
	if err != nil {
		return fmt.Errorf("login error: %w", err)
	}

	objects, err := mod.FindObjects(selectedSlot, []*pkcs11.Attribute{})
	if err != nil {
		return fmt.Errorf("find objects error: %w", err)
	}
	if len(objects) == 0 {
		return fmt.Errorf("no objects found")
	}

	sh, ok := mod.sessions[selectedSlot]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", selectedSlot)
	}

	options := []string{}
	handleMap := map[string]pkcs11.ObjectHandle{}
	for _, o := range objects {
		attribs, err := mod.ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			logger.Error("Failed to read token attributes", logger.Args("handle", o), logger.Args("", err))
			continue
		}
		option := fmt.Sprintf("[%d]%s -> (%s-%s)", o,
			AttributeToString(attribs[0]),
			AttributeToString(attribs[1]),
			AttributeToString(attribs[2]),
		)
		options = append(options, option)
		handleMap[option] = o
	}

	selected, err := InteractiveSelect.WithMaxHeight(15).WithOptions(options).Show("Select Key")
	if !ok {
		return err
	}

	oh, ok := handleMap[selected]
	if !ok {
		return fmt.Errorf("invalid token selection: %q", selected)
	}

	for {
		operation, err := InteractiveSelect.WithOptions(keyOperations).Show("Select operation")
		if !ok {
			return err
		}
		start := time.Now()
		switch operation {
		case "Go Back":
			return nil
		case "Info":
			err = PrintObjectInfo(mod, sh, oh)
		case "Export":
			err = ExportToken(mod, sh, oh)
		case "Delete":
			err = mod.ctx.DestroyObject(sh, oh)
		}
		if err != nil {
			return err
		}

		logger.Info(fmt.Sprintf("%q completed in %dms", operation, time.Since(start).Milliseconds()))
	}
}

func ListSlots(mod *P11) error {
	slots, err := mod.GetSlots()
	if err != nil {
		return err
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
	return nil
}

func ListHSMInfo(mod *P11) error {
	info, err := mod.ctx.GetInfo()
	if err != nil {
		return err
	}
	logger.Info("",
		logger.Args("ManufacturerID", info.ManufacturerID),
		logger.Args("LibraryDescription", info.LibraryDescription),
		logger.Args("LibraryVersion", fmt.Sprintf("v%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)),
		logger.Args("CryptokiVersion", fmt.Sprintf("v%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)),
		logger.Args("Flags", info.Flags),
	)

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

	start := time.Now()

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
		attribs, err := mod.ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return err
		}
		logger.Info("",
			logger.Args("Algorithm", AttributeToString(attribs[1])),
			logger.Args("Type", AttributeToString(attribs[2])),
			logger.Args("Label", AttributeToString(attribs[0])),
			logger.Args("Handle", o),
		)
	}

	pterm.Info.Printfln("Found %d objects. Command completed in %dms", len(objects), time.Since(start).Milliseconds())

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
