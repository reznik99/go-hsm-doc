package cli

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	idSchemeAuto      = "Auto (link to related key | SKI hash)"
	idSchemeManual    = "Manual (hex)"
	idSchemeSmartcard = "PIV (Smartcard / OpenSC)"
	idSchemeYubiKey   = "PIV (YubiKey / ykcs11)"
)

// pivSlot maps a human-readable PIV slot to the single-byte CKA_ID a given
// PKCS#11 module uses to address it. The byte differs between modules for the
// retired slots (ykcs11 is contiguous, OpenSC reads its labels as hex), so each
// module needs its own table. Attestation (F9) is read-only and omitted.
type pivSlot struct {
	label string
	id    byte
}

// yubikeyPIVSlots is ykcs11's CKA_ID numbering: contiguous 0x01..0x18.
var yubikeyPIVSlots = []pivSlot{
	{"9A Authentication", 0x01},
	{"9C Digital Signature", 0x02},
	{"9D Key Management", 0x03},
	{"9E Card Authentication", 0x04},
	{"82 Retired 1", 0x05},
	{"83 Retired 2", 0x06},
	{"84 Retired 3", 0x07},
	{"85 Retired 4", 0x08},
	{"86 Retired 5", 0x09},
	{"87 Retired 6", 0x0A},
	{"88 Retired 7", 0x0B},
	{"89 Retired 8", 0x0C},
	{"8A Retired 9", 0x0D},
	{"8B Retired 10", 0x0E},
	{"8C Retired 11", 0x0F},
	{"8D Retired 12", 0x10},
	{"8E Retired 13", 0x11},
	{"8F Retired 14", 0x12},
	{"90 Retired 15", 0x13},
	{"91 Retired 16", 0x14},
	{"92 Retired 17", 0x15},
	{"93 Retired 18", 0x16},
	{"94 Retired 19", 0x17},
	{"95 Retired 20", 0x18},
}

// openscPIVSlots is OpenSC's CKA_ID numbering. The four primary slots match
// ykcs11, but OpenSC parses its retired-slot labels ("10".."24") as hex, so
// retired 6..20 land on 0x10..0x24 rather than a contiguous run.
var openscPIVSlots = []pivSlot{
	{"9A Authentication", 0x01},
	{"9C Digital Signature", 0x02},
	{"9D Key Management", 0x03},
	{"9E Card Authentication", 0x04},
	{"82 Retired 1", 0x05},
	{"83 Retired 2", 0x06},
	{"84 Retired 3", 0x07},
	{"85 Retired 4", 0x08},
	{"86 Retired 5", 0x09},
	{"87 Retired 6", 0x10},
	{"88 Retired 7", 0x11},
	{"89 Retired 8", 0x12},
	{"8A Retired 9", 0x13},
	{"8B Retired 10", 0x14},
	{"8C Retired 11", 0x15},
	{"8D Retired 12", 0x16},
	{"8E Retired 13", 0x17},
	{"8F Retired 14", 0x18},
	{"90 Retired 15", 0x19},
	{"91 Retired 16", 0x20},
	{"92 Retired 17", 0x21},
	{"93 Retired 18", 0x22},
	{"94 Retired 19", 0x23},
	{"95 Retired 20", 0x24},
}

// detectToken sets a heuristic flag for YubiKey (ykcs11) from the library info.
// There is no reliable PKCS#11 way to detect PIV in general, so this only picks
// the default CKA_ID scheme — it never gates which schemes are offered.
func (a *App) detectToken() {
	info, err := a.mod.Ctx.GetInfo()
	if err != nil {
		return
	}
	haystack := strings.ToLower(info.LibraryDescription + " " + info.ManufacturerID)
	a.tokenIsYubiKey = strings.Contains(haystack, "ykcs11") || strings.Contains(haystack, "yubico")
}

// promptObjectID asks how the CKA_ID should be chosen. On a generic HSM the ID
// is free-form; on PIV it must be the single byte that selects the target slot.
// isPIV reports whether a PIV scheme was chosen, so callers can skip the label
// prompt (PIV tokens derive the label from the slot and ignore CKA_LABEL).
func (a *App) promptObjectID() (objectID []byte, isPIV bool, err error) {
	options := []string{idSchemeAuto, idSchemeManual, idSchemeSmartcard, idSchemeYubiKey}
	defaultScheme := idSchemeAuto
	if a.tokenIsYubiKey {
		defaultScheme = idSchemeYubiKey
	}
	scheme, err := a.interactiveSelect.WithOptions(options).WithDefaultOption(defaultScheme).Show("CKA_ID scheme")
	if err != nil {
		return nil, false, err
	}

	switch scheme {
	case idSchemeAuto:
		return nil, false, nil
	case idSchemeManual:
		objectID, err = a.promptManualObjectID()
		return objectID, false, err
	case idSchemeSmartcard:
		objectID, err = a.promptPIVSlot(openscPIVSlots)
		return objectID, true, err
	case idSchemeYubiKey:
		objectID, err = a.promptPIVSlot(yubikeyPIVSlots)
		return objectID, true, err
	default:
		return nil, false, fmt.Errorf("unrecognized ID scheme %q", scheme)
	}
}

func (a *App) promptManualObjectID() ([]byte, error) {
	raw, err := a.interactiveText.Show("Object ID (HEX)")
	if err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	objectID, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("object ID must be hexadecimal: %w", err)
	}
	return objectID, nil
}

func (a *App) promptPIVSlot(slots []pivSlot) ([]byte, error) {
	labels := make([]string, len(slots))
	ids := make(map[string]byte, len(slots))
	for i, slot := range slots {
		labels[i] = slot.label
		ids[slot.label] = slot.id
	}
	selected, err := a.interactiveSelect.WithMaxHeight(15).WithOptions(labels).Show("PIV Slot")
	if err != nil {
		return nil, err
	}
	return []byte{ids[selected]}, nil
}
