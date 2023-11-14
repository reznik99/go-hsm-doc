package internal

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
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

// AttributeToString converts a PKCS11 Attribute to a string
func AttributeToString(attribute *pkcs11.Attribute) string {
	switch attribute.Type {
	case pkcs11.CKA_CLASS:
		v := binary.LittleEndian.Uint32(attribute.Value)
		switch v {
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
	case pkcs11.CKA_KEY_TYPE:
		v := binary.LittleEndian.Uint32(attribute.Value)
		switch v {
		case pkcs11.CKK_RSA:
			return "RSA"
		case pkcs11.CKK_DSA:
			return "DSA"
		case pkcs11.CKK_DH:
			return "DH"
		case pkcs11.CKK_EC:
			return "EC "
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
	case pkcs11.CKA_LABEL:
		return fmt.Sprintf("%q", string(attribute.Value))
	}

	return "N/A"
}

// StringToAttribute converts an algo string like "RSA" to a pkcs11 uint
func StringToAttribute(algo string) (*pkcs11.Attribute, error) {
	switch strings.ToUpper(algo) {
	case "RSA":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA), nil
	case "EC", "ECDSA":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC), nil
	case "AES":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES), nil
	case "DES":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES), nil
	case "2DES":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES2), nil
	case "3DES":
		return pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES3), nil
	}
	return nil, fmt.Errorf("unrecognized algorithm %q", algo)
}

// CurveNameToCurve converts a curve name to a elliptic.Curve for HSM ECC PublicKey extraction
func CurveNameToCurve(curveName string) (curve elliptic.Curve, err error) {
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

// CurveNameToOid converts a named curve to a ObjectIdentifier
func CurveNameToOid(curveName string) (curve asn1.ObjectIdentifier, err error) {
	switch strings.ToLower(curveName) {
	case "p224", "p-224":
		curve = P224oid
	case "p256", "p-256":
		curve = P256oid
	case "p384", "p-384":
		curve = P384oid
	case "p521", "p-521":
		curve = P521oid
	default:
		err = fmt.Errorf("input string does not match known curve")
	}
	return
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

	curve, err := CurveNameToCurve(curveName)
	if err != nil {
		return nil, err
	}

	return curve, nil
}

// CurveNameToECParams converts a named curve into ecParam bytes
func CurveNameToECParams(curveName string) ([]byte, error) {
	curveOID, err := CurveNameToOid(curveName)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(curveOID)
}
