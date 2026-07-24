package main

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

type slotCapabilities struct {
	mechanisms map[uint]pkcs11.MechanismInfo
}

type keyGenerationOption struct {
	algorithm  string
	parameters []string
}

type keySizePreset struct {
	label string
	size  uint
}

func (a *App) loadCapabilities() error {
	slots, loadErr := a.mod.GetSlots()
	a.capabilities = make(map[uint]slotCapabilities, len(slots))

	for slotID := range slots {
		mechanisms, err := a.mod.GetMechanisms(slotID)
		a.capabilities[slotID] = slotCapabilities{mechanisms: mechanisms}
		if err != nil {
			loadErr = errors.Join(loadErr, fmt.Errorf("load capabilities for slot %d: %w", slotID, err))
		}
	}

	return loadErr
}

func (a *App) getSlotCapabilities(slotID uint) (slotCapabilities, error) {
	if capabilities, ok := a.capabilities[slotID]; ok {
		return capabilities, nil
	}

	mechanisms, err := a.mod.GetMechanisms(slotID)
	capabilities := slotCapabilities{mechanisms: mechanisms}
	a.capabilities[slotID] = capabilities
	return capabilities, err
}

func supportedKeyGenerationOptions(capabilities slotCapabilities) []keyGenerationOption {
	options := make([]keyGenerationOption, 0, 5)

	if info, ok := mechanismInfo(capabilities, pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11.CKF_GENERATE_KEY_PAIR); ok {
		if parameters := filterKeySizes(info, []keySizePreset{{"1024", 1024}, {"2048", 2048}, {"4096", 4096}}); len(parameters) > 0 {
			options = append(options, keyGenerationOption{algorithm: "RSA", parameters: parameters})
		}
	}

	if info, ok := mechanismInfo(capabilities, pkcs11.CKM_EC_KEY_PAIR_GEN, pkcs11.CKF_GENERATE_KEY_PAIR|pkcs11.CKF_EC_NAMEDCURVE); ok {
		if parameters := filterKeySizes(info, []keySizePreset{{"P224", 224}, {"P256", 256}, {"P384", 384}, {"P521", 521}}); len(parameters) > 0 {
			options = append(options, keyGenerationOption{algorithm: "EC", parameters: parameters})
		}
	}

	if info, ok := mechanismInfo(capabilities, pkcs11.CKM_AES_KEY_GEN, pkcs11.CKF_GENERATE); ok {
		if parameters := filterKeySizes(info, []keySizePreset{{"128", 16}, {"192", 24}, {"256", 32}}); len(parameters) > 0 {
			options = append(options, keyGenerationOption{algorithm: "AES", parameters: parameters})
		}
	}

	var tripleDES []string
	if supportsMechanism(capabilities, pkcs11.CKM_DES2_KEY_GEN, pkcs11.CKF_GENERATE) {
		tripleDES = append(tripleDES, "128")
	}
	if supportsMechanism(capabilities, pkcs11.CKM_DES3_KEY_GEN, pkcs11.CKF_GENERATE) {
		tripleDES = append(tripleDES, "192")
	}
	if len(tripleDES) > 0 {
		options = append(options, keyGenerationOption{algorithm: "3DES", parameters: tripleDES})
	}

	if supportsMechanism(capabilities, pkcs11.CKM_DES_KEY_GEN, pkcs11.CKF_GENERATE) {
		options = append(options, keyGenerationOption{algorithm: "DES", parameters: []string{"64"}})
	}

	return options
}

func supportedImportObjectTypes(capabilities slotCapabilities) []string {
	options := []string{"Certificate", "PublicKey"}
	secretKeyImport := supportsMechanism(capabilities, pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11.CKF_GENERATE_KEY_PAIR) &&
		supportsMechanism(capabilities, pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKF_UNWRAP)
	if secretKeyImport && supportsMechanism(capabilities, pkcs11.CKM_AES_KEY_WRAP_PAD, pkcs11.CKF_UNWRAP) {
		options = append(options, "PrivateKey")
	}
	if secretKeyImport {
		options = append(options, "SecretKey")
	}
	return options
}

func mechanismInfo(capabilities slotCapabilities, mechanism, flags uint) (pkcs11.MechanismInfo, bool) {
	info, ok := capabilities.mechanisms[mechanism]
	return info, ok && info.Flags&flags == flags
}

func supportsMechanism(capabilities slotCapabilities, mechanism, flags uint) bool {
	_, ok := mechanismInfo(capabilities, mechanism, flags)
	return ok
}

func filterKeySizes(info pkcs11.MechanismInfo, presets []keySizePreset) []string {
	output := make([]string, 0, len(presets))
	for _, preset := range presets {
		if (info.MinKeySize == 0 || preset.size >= info.MinKeySize) && (info.MaxKeySize == 0 || preset.size <= info.MaxKeySize) {
			output = append(output, preset.label)
		}
	}
	return output
}
