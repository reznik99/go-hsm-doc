package main

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

var (
	P224oid = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	P256oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	P384oid = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	P521oid = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

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
		return "DATA       "
	case pkcs11.CKO_CERTIFICATE:
		return "CERTIFICATE"
	case pkcs11.CKO_PUBLIC_KEY:
		return "PUBLIC_KEY "
	case pkcs11.CKO_PRIVATE_KEY:
		return "PRIVATE_KEY"
	case pkcs11.CKO_SECRET_KEY:
		return "SECRET_KEY "
	default:
		return "N/A        "
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

// StringToCurve converts a curve name to a elliptic.Curve for HSM ECC PublicKey extraction
func StringToCurve(curveName string) (curve elliptic.Curve, err error) {
	switch strings.ToLower(curveName) {
	case "p224", "p-224":
		curve = elliptic.P224()
	case "p256", "p-256":
		curve = elliptic.P256()
	case "p384", "p-384":
		curve = elliptic.P384()
	case "p521", "p-521":
		curve = elliptic.P521()
	default:
		err = fmt.Errorf("input string does not match known curve")
	}
	return
}

// OidToCurveName converts an ObjectIdentifier to a named curve
func OidToCurveName(curve asn1.ObjectIdentifier) (name string, err error) {

	if curve.Equal(P224oid) {
		return "p224", nil
	} else if curve.Equal(P256oid) {
		return "p256", nil
	} else if curve.Equal(P384oid) {
		return "p384", nil
	} else if curve.Equal(P521oid) {
		return "p521", nil
	} else {
		return "", fmt.Errorf("unrecognized curve ObjectIdentifier")
	}
}

// ECParamsToCurve converts ecParam bytes (from the HSM) into a golang curve obj
func ECParamsToCurve(ecParams []byte) (elliptic.Curve, error) {
	params := &asn1.ObjectIdentifier{}
	if _, err := asn1.Unmarshal(ecParams, params); err != nil {
		return nil, err
	}

	curveName, err := OidToCurveName(*params)
	if err != nil {
		return nil, err
	}

	curve, err := StringToCurve(curveName)
	if err != nil {
		return nil, err
	}

	return curve, nil
}
