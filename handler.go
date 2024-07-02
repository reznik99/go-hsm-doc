package main

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
	"github.com/reznik99/go-hsm-doc/internal"
)

var (
	keyLengths = map[string][]string{
		"RSA":  {"1024", "2048", "4096"},
		"EC":   {"P224", "P256", "P384", "P512"},
		"AES":  {"128", "192", "256"},
		"3DES": {"128", "192"},
		"DES":  {"64"},
	}
	algorithmsByObjectType = map[string][]string{
		"SecretKey":  {"AES", "3DES", "DES"},
		"PrivateKey": {"RSA", "EC"},
		"PublicKey":  {"RSA", "EC"},
	}
	algorithms    = []string{"RSA", "EC", "AES", "3DES", "DES"}
	keyOperations = []string{
		"Go Back",
		"Info",
		"Export",
		"Delete",
	}
	objectTypes = []string{"Certificate", "PublicKey", "PrivateKey", "SecretKey"}
)

// Handlers for Commands

func ListHSMInfo(mod *internal.P11) error {
	info, err := mod.Ctx.GetInfo()
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

func ListSlots(mod *internal.P11) error {
	slots, err := mod.GetSlots()
	if err != nil {
		return err
	}
	for slotID, slot := range slots {
		si, err := mod.Ctx.GetSlotInfo(slotID)
		if err != nil {
			continue
		}
		logger.Info(fmt.Sprintf("-> %s [%d]", slot.Label, slotID),
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

func ListTokens(mod *internal.P11) error {
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = Login(mod, selectedSlot); err != nil {
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

	for _, o := range objects {
		PrintObjectInfo(mod, sh, o)
	}

	pterm.Info.Printfln("Found %d objects. Command completed in %dms", len(objects), time.Since(start).Milliseconds())

	return nil
}

func FindToken(mod *internal.P11) error {
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = Login(mod, selectedSlot); err != nil {
		return err
	}

	objects, err := mod.FindObjects(selectedSlot, []*pkcs11.Attribute{})
	if err != nil {
		return fmt.Errorf("find objects error: %w", err)
	}
	if len(objects) == 0 {
		return fmt.Errorf("no objects found")
	}

	options := []string{}
	handleMap := map[string]pkcs11.ObjectHandle{}
	for _, o := range objects {
		attribs, err := GetAttributeValue(mod, sh, o)
		if err != nil {
			logger.Error("Failed to read token attributes", logger.Args("handle", o), logger.Args("", err))
			continue
		}
		option := fmt.Sprintf("[%02d] %s %s %s", o,
			PadString(internal.AttributeToString(attribs[1]), 4),
			PadString(internal.AttributeToString(attribs[2]), 11),
			internal.AttributeToString(attribs[0]),
		)
		options = append(options, option)
		handleMap[option] = o
	}

	selected, err := InteractiveSelect.WithMaxHeight(15).WithOptions(options).Show("Select Key")
	if err != nil {
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
			_, err = ExportToken(mod, sh, oh)
		case "Delete":
			err = mod.Ctx.DestroyObject(sh, oh)
		}
		if err != nil {
			return err
		}

		pterm.Info.Printfln("%q completed in %dms", operation, time.Since(start).Milliseconds())
	}
}

func GenerateKey(mod *internal.P11) error {

	// Select Slot for key
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	// Select Key Algorithm
	algorithm, err := InteractiveSelect.WithOptions(algorithms).Show("Select Algorithm")
	if err != nil {
		return err
	}

	// Select Key length
	lengthOrCurve, err := InteractiveSelect.WithOptions(keyLengths[algorithm]).Show("Select Keylength")
	if err != nil {
		return err
	}
	length, _ := strconv.Atoi(lengthOrCurve)

	// Select Key Label for key
	keyLabel, err := InteractiveText.Show("Key Label")
	if err != nil {
		return err
	}

	extractable, err := InteractiveConfirm.Show("Extractable")
	if err != nil {
		return err
	}

	// Open session and login to slot
	sh, err := mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = Login(mod, selectedSlot); err != nil {
		return err
	}

	start := time.Now()

	switch algorithm {
	case "RSA":
		_, _, err = mod.GenerateRSAKeypair(sh, keyLabel, length, extractable, false)
	case "EC":
		_, err = mod.GenerateECKeypair(sh, keyLabel, lengthOrCurve, extractable, false)
	case "AES":
		_, err = mod.GenerateAESKey(sh, keyLabel, length, extractable, false)
	case "DES", "2DES", "3DES":
		_, err = mod.GenerateDESKey(sh, keyLabel, length, extractable, false)
	default:
		err = fmt.Errorf("unrecognized algorithm %s", algorithm)
	}
	if err != nil {
		return err
	}

	pterm.Info.Printfln("Generated Key\\s in %dms", time.Since(start).Milliseconds())

	return nil
}

func ImportKey(mod *internal.P11) error {
	var err error

	// Select Slot for key
	selectedSlot, err := PromptSlotSelection(mod)
	if err != nil {
		return err
	}

	// Select Object Type
	objectType, err := InteractiveSelect.WithOptions(objectTypes).Show("Object Type")
	if err != nil {
		return err
	}

	// Select Key Algorithm
	var algorithm = "N/A"
	if objectType != "Certificate" {
		algorithm, err = InteractiveSelect.WithOptions(algorithmsByObjectType[objectType]).Show("Select Algorithm")
		if err != nil {
			return err
		}
	}

	// Select Key Label for key
	keyLabel, err := InteractiveText.Show("Key Label")
	if err != nil {
		return err
	}

	// Get raw key value from user
	rawToken, err := InteractiveText.WithMultiLine(true).Show(fmt.Sprintf("Enter %q", objectType))
	if err != nil {
		return err
	}
	// TODO: This works for pasting key on Windows. Linux won't have carrige return so might break with pem.Decode
	rawToken = strings.Replace(rawToken, "\r", "\r\n", -1)

	// Open session and login to slot
	sh, err := mod.OpenSession(uint(selectedSlot))
	if err != nil {
		return fmt.Errorf("open session error: %w", err)
	}
	if err = Login(mod, selectedSlot); err != nil {
		return err
	}

	start := time.Now()

	switch objectType {
	case "Certificate":
		b, rest := pem.Decode([]byte(rawToken))
		if b == nil || len(rest) != 0 {
			return fmt.Errorf("failed to decode PEM %s", objectType)
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return err
		}
		_, err = mod.ImportCertificate(sh, cert, keyLabel, false)
		if err != nil {
			return err
		}
	case "PublicKey":
		b, rest := pem.Decode([]byte(rawToken))
		if b == nil || len(rest) != 0 {
			return fmt.Errorf("failed to decode PEM %s", objectType)
		}
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return err
		}
		_, err = mod.ImportPublicKey(sh, pub, keyLabel, false)
		if err != nil {
			return err
		}
	case "PrivateKey":
		b, rest := pem.Decode([]byte(rawToken))
		if b == nil || len(rest) != 0 {
			return fmt.Errorf("failed to decode PEM %s", objectType)
		}
		_, err = mod.ImportPrivateKey(sh, b.Bytes, keyLabel, false, algorithm)
		if err != nil {
			return err
		}
	case "SecretKey":
		key, err := hex.DecodeString(rawToken)
		if err != nil {
			return fmt.Errorf("secret key not in HEX string format: %s", err)
		}
		_, err = mod.ImportSecretKey(sh, key, keyLabel, false, algorithm)
		if err != nil {
			return err
		}
	}

	pterm.Info.Printfln("Imported %q in %dms", objectType, time.Since(start).Milliseconds())

	return nil
}

func ExitFunc() {
	logger.Info("Exiting HSM-DOCTOR...")
	os.Exit(0)
}

// Helper functions

func PromptSlotSelection(mod *internal.P11) (uint, error) {
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

func GetAttributeValue(mod *internal.P11, sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) ([]*pkcs11.Attribute, error) {
	attribs, err := mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		attribs, err = mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
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

func PrintObjectInfo(mod *internal.P11, sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	attribs, err := GetAttributeValue(mod, sh, o)
	if err != nil {
		return err
	}
	logger.Info(fmt.Sprintf("[%02d]", o),
		logger.Args("Algorithm", PadString(internal.AttributeToString(attribs[1]), 4)),
		logger.Args("Type", PadString(internal.AttributeToString(attribs[2]), 11)),
		logger.Args("Label", internal.AttributeToString(attribs[0])),
	)
	return nil
}

func ExportToken(mod *internal.P11, sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) ([]byte, error) {
	attribs, err := mod.Ctx.GetAttributeValue(sh, o, []*pkcs11.Attribute{
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
		token, err = mod.ExportCertificate(sh, o)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_DATA, pkcs11.CKO_PUBLIC_KEY:
		token, err = mod.ExportPublicKey(sh, o, algorithmType)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_PRIVATE_KEY:
		token, err = mod.ExportPrivateKey(sh, o)
		fmt.Printf("%s\n", token)
	case pkcs11.CKO_SECRET_KEY:
		token, err = mod.ExportSecretKey(sh, o)
		fmt.Printf("%X\n", token)
	default:
		return nil, fmt.Errorf("unrecognized object type: %d", objectType)
	}
	return token, err
}

func Login(mod *internal.P11, slotID uint) error {
	pin, err := InteractiveText.WithMask("*").Show("Slot/Partition PIN (optional)")
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

// PadString returns the string right-padded with specified number of spaces
func PadString(value string, number int) string {
	number = int(math.Abs(float64(number - len(value))))
	padding := strings.Repeat(" ", number)
	return fmt.Sprintf("%s%s", value, padding)
}
