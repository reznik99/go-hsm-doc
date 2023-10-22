package main

import "github.com/miekg/pkcs11"

func TypeToString(key_type []byte) string {
	switch key_type[0] {
	case pkcs11.CKK_RSA:
		return "RSA"
	case pkcs11.CKK_DSA:
		return "DSA"
	case pkcs11.CKK_DH:
		return "DH"
	case pkcs11.CKK_EC:
		return "EC"
	case pkcs11.CKK_AES:
		return "AES"
	case pkcs11.CKK_DES:
		return "DES"
	case pkcs11.CKK_DES2:
		return "DES2"
	case pkcs11.CKK_DES3:
		return "DES3"
	default:
		return "N/A"
	}
}

func ClassToString(class []byte) string {
	switch class[0] {
	case pkcs11.CKO_DATA:
		return "DATA"
	case pkcs11.CKO_CERTIFICATE:
		return "CERTIFICATE"
	case pkcs11.CKO_PUBLIC_KEY:
		return "PUBLIC_KEY"
	case pkcs11.CKO_PRIVATE_KEY:
		return "PRIVATE_KEY"
	case pkcs11.CKO_SECRET_KEY:
		return "SECRET_KEY"
	default:
		return "N/A"
	}
}

func StringToGenMech(mech string) *pkcs11.Mechanism {
	switch mech {
	case "RSA":
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
	case "EC":
		return pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil) //TODO: test
	case "AES":
		return pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	case "DES3":
		return pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)
	}
	return nil
}
