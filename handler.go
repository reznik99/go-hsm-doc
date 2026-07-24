package main

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
	"github.com/reznik99/go-hsm-doc/internal"
)

// Handlers for Commands

func (a *App) listHSMInfo() error {
	info, err := a.mod.Ctx.GetInfo()
	if err != nil {
		return err
	}
	a.log.Info("HSM info",
		a.log.Args("ManufacturerID", info.ManufacturerID),
		a.log.Args("LibraryDescription", info.LibraryDescription),
		a.log.Args("LibraryVersion", fmt.Sprintf("v%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor)),
		a.log.Args("CryptokiVersion", fmt.Sprintf("v%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)),
		a.log.Args("Flags", info.Flags),
	)

	return nil
}

func (a *App) listSlots() error {
	slots, err := a.mod.GetSlots()
	if err != nil {
		a.log.Warn("Some slots could not be read", a.log.Args("error", err))
		if len(slots) == 0 {
			return err
		}
	}
	for slotID, slot := range slots {
		si, err := a.mod.Ctx.GetSlotInfo(slotID)
		if err != nil {
			a.log.Warn("Failed to get slot info", a.log.Args("slot_id", slotID), a.log.Args("error", err))
			continue
		}
		a.log.Info(fmt.Sprintf("-> %s [%d]", slot.Label, slotID),
			a.log.Args("Label", slot.Label),
			a.log.Args("Model", slot.Model),
			a.log.Args("SerialNumber", slot.SerialNumber),
			a.log.Args("MaxRwSessionCount", slot.MaxRwSessionCount),
			a.log.Args("ManufacturerID", si.ManufacturerID),
			a.log.Args("SlotDescription", si.SlotDescription),
			a.log.Args("HardwareVersion", fmt.Sprintf("v%d.%d", si.HardwareVersion.Major, si.HardwareVersion.Minor)),
			a.log.Args("FirmwareVersion", fmt.Sprintf("v%d.%d", si.FirmwareVersion.Major, si.FirmwareVersion.Minor)),
		)
	}
	return nil
}

func (a *App) listTokens() error {
	selectedSlot, err := a.promptSlotSelection()
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := a.mod.OpenSession(selectedSlot)
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = a.login(selectedSlot); err != nil {
		return err
	}

	start := time.Now()

	objects, err := a.mod.FindObjects(selectedSlot, []*pkcs11.Attribute{})
	if err != nil {
		return err
	}
	if len(objects) == 0 {
		return errors.New("no objects found")
	}

	for _, o := range objects {
		if err := a.printObjectInfo(sh, o); err != nil {
			a.log.Error("Failed to print object info", a.log.Args("object_handle", o), a.log.Args("error", err))
		}
	}

	pterm.Info.Printfln("Found %d objects. Command completed in %dms", len(objects), time.Since(start).Milliseconds())

	return nil
}

func (a *App) findToken() error {
	selectedSlot, err := a.promptSlotSelection()
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := a.mod.OpenSession(selectedSlot)
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = a.login(selectedSlot); err != nil {
		return err
	}

	objects, err := a.mod.FindObjects(selectedSlot, []*pkcs11.Attribute{})
	if err != nil {
		return fmt.Errorf("find objects error: %w", err)
	}
	if len(objects) == 0 {
		return errors.New("no objects found")
	}

	options := []string{}
	handleMap := map[string]pkcs11.ObjectHandle{}
	for _, o := range objects {
		attribs, err := a.getAttributeValue(sh, o)
		if err != nil {
			a.log.Error("Failed to read token attributes", a.log.Args("object_handle", o), a.log.Args("error", err))
			continue
		}
		option := fmt.Sprintf("[%02d] %s %s %s", o,
			padString(internal.AttributeToString(attribs[1]), 4),
			padString(internal.AttributeToString(attribs[2]), 11),
			internal.AttributeToString(attribs[0]),
		)
		options = append(options, option)
		handleMap[option] = o
	}

	selected, err := a.interactiveSelect.WithMaxHeight(15).WithOptions(options).Show("Select Key")
	if err != nil {
		return err
	}

	oh, ok := handleMap[selected]
	if !ok {
		return fmt.Errorf("invalid token selection: %q", selected)
	}

	for {
		operation, err := a.interactiveSelect.WithOptions(a.keyOperations).Show("Select operation")
		if err != nil {
			return err
		}
		start := time.Now()
		switch operation {
		case "Go Back":
			return nil
		case "Info":
			err = a.printObjectInfo(sh, oh)
		case "Export":
			_, err = a.exportToken(sh, oh)
		case "Delete":
			return a.deleteToken(sh, oh)
		}
		if err != nil {
			return err
		}

		pterm.Info.Printfln("%q completed in %dms", operation, time.Since(start).Milliseconds())
	}
}

func (a *App) generateKey() error {
	selectedSlot, err := a.promptSlotSelection()
	if err != nil {
		return err
	}

	capabilities, capabilityErr := a.getSlotCapabilities(selectedSlot)
	if capabilityErr != nil {
		a.log.Warn("Some slot capabilities could not be loaded", a.log.Args("slot_id", selectedSlot), a.log.Args("error", capabilityErr))
	}
	generationOptions := supportedKeyGenerationOptions(capabilities)
	if len(generationOptions) == 0 {
		return errors.Join(errors.New("slot has no supported key generation mechanisms"), capabilityErr)
	}

	algorithms := make([]string, 0, len(generationOptions))
	parametersByAlgorithm := make(map[string][]string, len(generationOptions))
	for _, option := range generationOptions {
		algorithms = append(algorithms, option.algorithm)
		parametersByAlgorithm[option.algorithm] = option.parameters
	}

	algorithm, err := a.interactiveSelect.WithOptions(algorithms).Show("Select Algorithm")
	if err != nil {
		return err
	}

	lengthOrCurve, err := a.interactiveSelect.WithOptions(parametersByAlgorithm[algorithm]).Show("Select Key Size or Curve")
	if err != nil {
		return err
	}
	length, _ := strconv.Atoi(lengthOrCurve)

	// Select Key Label for key
	keyLabel, err := a.interactiveText.Show("Key Label")
	if err != nil {
		return err
	}

	extractable, err := a.interactiveConfirm.Show("Extractable")
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := a.mod.OpenSession(selectedSlot)
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = a.login(selectedSlot); err != nil {
		return err
	}

	start := time.Now()

	switch algorithm {
	case "RSA":
		_, _, err = a.mod.GenerateRSAKeypair(sh, keyLabel, length, extractable, false)
	case "EC":
		_, err = a.mod.GenerateECKeypair(sh, keyLabel, lengthOrCurve, extractable, false)
	case "AES":
		_, err = a.mod.GenerateAESKey(sh, keyLabel, length, extractable, false)
	case "DES", "2DES", "3DES":
		_, err = a.mod.GenerateDESKey(sh, keyLabel, length, extractable, false)
	default:
		err = fmt.Errorf("unrecognized algorithm %s", algorithm)
	}
	if err != nil {
		return err
	}

	pterm.Info.Printfln("Generated Key\\s in %dms", time.Since(start).Milliseconds())

	return nil
}

func (a *App) importKey() error {
	selectedSlot, err := a.promptSlotSelection()
	if err != nil {
		return err
	}

	capabilities, capabilityErr := a.getSlotCapabilities(selectedSlot)
	if capabilityErr != nil {
		a.log.Warn("Some slot capabilities could not be loaded", a.log.Args("slot_id", selectedSlot), a.log.Args("error", capabilityErr))
	}
	objectType, err := a.interactiveSelect.WithOptions(supportedImportObjectTypes(capabilities)).Show("Object Type")
	if err != nil {
		return err
	}

	keyLabel, err := a.interactiveText.Show("Key Label")
	if err != nil {
		return err
	}

	rawToken, err := a.interactiveText.WithMultiLine(true).Show(fmt.Sprintf("Enter %q", objectType))
	if err != nil {
		return err
	}

	sh, err := a.mod.OpenSession(selectedSlot)
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = a.login(selectedSlot); err != nil {
		return err
	}

	start := time.Now()

	switch objectType {
	case "Certificate":
		block, parseErr := parsePEMBlock(rawToken, objectType)
		if parseErr != nil {
			return parseErr
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return parseErr
		}
		_, err = a.mod.ImportCertificate(sh, certificate, keyLabel, false)
	case "PublicKey":
		block, parseErr := parsePEMBlock(rawToken, objectType)
		if parseErr != nil {
			return parseErr
		}
		publicKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return parseErr
		}
		algorithm, detectionErr := detectKeyAlgorithm(publicKey)
		if detectionErr != nil {
			return detectionErr
		}
		pterm.Info.Printfln("Detected Algorithm: %s", algorithm)
		_, err = a.mod.ImportPublicKey(sh, publicKey, keyLabel, false)
	case "PrivateKey":
		block, parseErr := parsePEMBlock(rawToken, objectType)
		if parseErr != nil {
			return parseErr
		}
		privateKey, parseErr := parsePrivateKey(block.Bytes)
		if parseErr != nil {
			return parseErr
		}
		algorithm, detectionErr := detectKeyAlgorithm(privateKey)
		if detectionErr != nil {
			return detectionErr
		}
		pterm.Info.Printfln("Detected Algorithm: %s", algorithm)
		_, err = a.mod.ImportPrivateKey(sh, block.Bytes, keyLabel, false, algorithm)
	case "SecretKey":
		algorithm, promptErr := a.interactiveSelect.WithOptions(a.secretKeyAlgorithms).Show("Select Algorithm")
		if promptErr != nil {
			return promptErr
		}
		secretKey, decodeErr := hex.DecodeString(rawToken)
		if decodeErr != nil {
			return fmt.Errorf("secret key not in HEX string format: %w", decodeErr)
		}
		_, err = a.mod.ImportSecretKey(sh, secretKey, keyLabel, false, algorithm)
	default:
		return fmt.Errorf("unrecognized object type %s", objectType)
	}
	if err != nil {
		return err
	}

	pterm.Info.Printfln("Imported %q in %dms", objectType, time.Since(start).Milliseconds())

	return nil
}

// Helper functions

func (a *App) promptSlotSelection() (uint, error) {
	options := []string{}
	slots, err := a.mod.GetSlots()
	if err != nil {
		a.log.Warn("Some slots could not be read", a.log.Args("error", err))
		if len(slots) == 0 {
			return 0, err
		}
	}

	for _, slot := range slots {
		options = append(options, slot.Label)
	}

	slotLabel, err := a.interactiveSelect.WithOptions(options).Show("Select Slot")
	if err != nil {
		return 0, fmt.Errorf("slot selection error: %w", err)
	}

	for slotID, slot := range slots {
		if slot.Label == slotLabel {
			return slotID, nil
		}
	}

	return 0, errors.New("slot not selected")
}

func (a *App) getAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) ([]*pkcs11.Attribute, error) {
	attribs, err := a.mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		attribs, err = a.mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return nil, err
		}
		attribs = append(attribs, attribs[1])
		attribs[1] = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 1000) // Add fake attribute so it shows up as N/A
	}

	return attribs, nil
}

func (a *App) printObjectInfo(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	attribs, err := a.getAttributeValue(sh, o)
	if err != nil {
		return err
	}
	a.log.Info(fmt.Sprintf("[%02d]", o),
		a.log.Args("Algorithm", padString(internal.AttributeToString(attribs[1]), 4)),
		a.log.Args("Type", padString(internal.AttributeToString(attribs[2]), 11)),
		a.log.Args("Label", internal.AttributeToString(attribs[0])),
	)
	return nil
}

func (a *App) deleteToken(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	confirmed, err := a.interactiveConfirm.Show("Delete selected object?")
	if err != nil || !confirmed {
		return err
	}
	return a.mod.Ctx.DestroyObject(sh, o)
}

func (a *App) exportToken(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) ([]byte, error) {
	attribs, err := a.mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		return nil, err
	}

	algorithmType := binary.LittleEndian.Uint32(attribs[0].Value)
	objectType := binary.LittleEndian.Uint32(attribs[1].Value)

	var token []byte
	switch objectType {
	case pkcs11.CKO_CERTIFICATE:
		token, err = a.mod.ExportCertificate(sh, o)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_DATA, pkcs11.CKO_PUBLIC_KEY:
		token, err = a.mod.ExportPublicKey(sh, o, algorithmType)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_PRIVATE_KEY:
		token, err = a.mod.ExportPrivateKey(sh, o)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_SECRET_KEY:
		token, err = a.mod.ExportSecretKey(sh, o)
		fmt.Printf("%X\n", token)
	default:
		return nil, fmt.Errorf("unrecognized object type: %d", objectType)
	}
	return token, err
}

func (a *App) login(slotID uint) error {
	pin, err := a.interactiveText.WithMask("*").Show("Slot/Partition PIN (optional)")
	if err != nil {
		return fmt.Errorf("error reading Slot/Partition PIN: %w", err)
	}
	if pin != "" {
		err = a.mod.Login(slotID, pin)
		if err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
			return err
		}
	}
	return nil
}

// padString returns the string right-padded with specified number of spaces
func padString(value string, number int) string {
	number = int(math.Abs(float64(number - len(value))))
	padding := strings.Repeat(" ", number)
	return fmt.Sprintf("%s%s", value, padding)
}
