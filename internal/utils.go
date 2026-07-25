package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
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
		v, err := AttributeToUint(attribute)
		if err != nil {
			return "N/A"
		}
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
		v, err := AttributeToUint(attribute)
		if err != nil {
			return "N/A"
		}
		switch v {
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
	case pkcs11.CKA_LABEL:
		return fmt.Sprintf("%q", string(attribute.Value))
	case pkcs11.CKA_ID:
		if len(attribute.Value) == 0 {
			return "<empty>"
		}
		return fmt.Sprintf("%X", attribute.Value)
	}

	return "N/A"
}

func AttributeToUint(attribute *pkcs11.Attribute) (uint, error) {
	switch len(attribute.Value) {
	case 4:
		return uint(binary.NativeEndian.Uint32(attribute.Value)), nil
	case 8:
		return uint(binary.NativeEndian.Uint64(attribute.Value)), nil
	default:
		return 0, fmt.Errorf("attribute %d has invalid integer length %d", attribute.Type, len(attribute.Value))
	}
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
		err = errors.New("input string does not match known curve")
	}
	return
}

// OidToCurveName converts an ObjectIdentifier to a named curve
func OidToCurveName(curve asn1.ObjectIdentifier) (name string, err error) {

	switch {
	case curve.Equal(P224oid):
		return "p224", nil
	case curve.Equal(P256oid):
		return "p256", nil
	case curve.Equal(P384oid):
		return "p384", nil
	case curve.Equal(P521oid):
		return "p521", nil
	default:
		return "", errors.New("unrecognized curve ObjectIdentifier")
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
		err = errors.New("input string does not match known curve")
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

// MarshalECPoint encodes an EC public key as the CKA_EC_POINT value: the X9.62 point wrapped in a DER OCTET STRING.
func MarshalECPoint(pub *ecdsa.PublicKey) ([]byte, error) {
	// elliptic.Marshal kept over crypto/ecdh: the latter has no P-224.
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck
	return asn1.Marshal(asn1.RawValue{Tag: asn1.TagOctetString, Bytes: point})
}

// ParseECPoint decodes a CKA_EC_POINT value into curve coordinates.
// The spec wraps the point in a DER OCTET STRING, but some HSMs return it raw, so try the unwrap then fall back.
func ParseECPoint(curve elliptic.Curve, raw []byte) (*big.Int, *big.Int, error) {
	ecPoint := raw
	var octetString asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &octetString); err == nil && len(octetString.Bytes) > 0 {
		ecPoint = octetString.Bytes
	}

	// elliptic.Unmarshal kept over crypto/ecdh: the latter has no P-224.
	x, y := elliptic.Unmarshal(curve, ecPoint) //nolint:staticcheck
	if x == nil {
		// Unwrap can mis-parse a raw point (0x04 doubles as the OCTET STRING tag); retry with the untouched value.
		x, y = elliptic.Unmarshal(curve, raw) //nolint:staticcheck
	}
	if x == nil {
		return nil, nil, errors.New("failed to parse EC point")
	}
	return x, y, nil
}

// PadString returns the string right-padded with specified number of spaces
func PadString(value string, number int) string {
	number = int(math.Abs(float64(number - len(value))))
	padding := strings.Repeat(" ", number)
	return fmt.Sprintf("%s%s", value, padding)
}
