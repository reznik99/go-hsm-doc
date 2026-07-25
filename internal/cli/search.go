package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 method 1 uses SHA-1 only as a key identifier
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func subjectKeyID(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	var info subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, fmt.Errorf("parse public key info: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parse public key info: %d trailing bytes", len(rest))
	}
	digest := sha1.Sum(info.PublicKey.Bytes) //nolint:gosec // RFC 5280 method 1 uses SHA-1 only as a key identifier
	return digest[:], nil
}

func publicKeyFromPrivateKey(privateKey any) (any, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func publicKeySearchTemplate(publicKey any) ([]*pkcs11.Attribute, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		params, err := pkcs11util.CurveNameToECParams(key.Params().Name)
		if err != nil {
			return nil, err
		}
		point, err := pkcs11util.MarshalECPoint(key)
		if err != nil {
			return nil, err
		}
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point),
		}, nil
	default:
		return nil, nil
	}
}

func (a *App) resolveImportObjectID(slotID uint, sh pkcs11.SessionHandle, publicKey any, defaultID, requestedID []byte) []byte {
	if requestedID != nil {
		return requestedID
	}

	template, err := publicKeySearchTemplate(publicKey)
	if err != nil || template == nil {
		return defaultID
	}
	matchingPublicKeys, err := a.mod.FindObjects(slotID, template)
	if err != nil {
		return defaultID
	}

	var matchingID []byte
	for _, handle := range matchingPublicKeys {
		attributes, err := a.mod.Ctx.GetAttributeValue(sh, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			return defaultID
		}
		if len(attributes[0].Value) == 0 {
			continue
		}
		if matchingID == nil {
			matchingID = attributes[0].Value
			continue
		}
		if !bytes.Equal(matchingID, attributes[0].Value) {
			return defaultID
		}
	}
	if matchingID != nil {
		return matchingID
	}
	return defaultID
}
