package hsm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OAEP key-wrapping hash, kept for broad HSM compatibility
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// ImportCertificate imports a certificate into the HSM without wrapping.
func (p *P11) ImportCertificate(sh pkcs11.SessionHandle, cert *x509.Certificate, label string, objectID []byte, ephemeral bool) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	}
	return p.Ctx.CreateObject(sh, template)
}

// ImportPublicKey imports an RSA or EC public key into the HSM without wrapping.
func (p *P11) ImportPublicKey(sh pkcs11.SessionHandle, pub any, keyLabel string, objectID []byte, ephemeral bool) (pkcs11.ObjectHandle, error) {
	switch publicKey := pub.(type) {
	case *rsa.PublicKey:
		// CKA_PUBLIC_EXPONENT is a minimal big-endian integer.
		exponent := big.NewInt(int64(publicKey.E)).Bytes()
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, publicKey.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.Ctx.CreateObject(sh, template)
	case *ecdsa.PublicKey:
		// Parse curve into Params
		params, err := pkcs11util.CurveNameToECParams(publicKey.Params().Name)
		if err != nil {
			return pkcs11.ObjectHandle(0), err
		}
		ecPoint, err := pkcs11util.MarshalECPoint(publicKey)
		if err != nil {
			return pkcs11.ObjectHandle(0), err
		}
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.Ctx.CreateObject(sh, template)
	default:
		// TODO: Support X25519 and/or DH keys?
		return 0, fmt.Errorf("unrecognized key type: %T", publicKey)
	}
}

// ImportSecretKey imports an AES/DES/3DES secret key using an ephemeral RSA 2048 wrapping key.
func (p *P11) ImportSecretKey(sh pkcs11.SessionHandle, rawKey []byte, keyLabel string, objectID []byte, algorithm string, extractable, ephemeral bool) (handle pkcs11.ObjectHandle, err error) {
	switch strings.ToUpper(algorithm) {
	case "AES":
		if len(rawKey) != 16 && len(rawKey) != 24 && len(rawKey) != 32 {
			return 0, fmt.Errorf("invalid AES key length %d: must be 16, 24, or 32 bytes", len(rawKey))
		}
	case "DES":
		if len(rawKey) != 8 {
			return 0, fmt.Errorf("invalid DES key length %d: must be 8 bytes", len(rawKey))
		}
	case "2DES":
		if len(rawKey) != 16 {
			return 0, fmt.Errorf("invalid 2DES key length %d: must be 16 bytes", len(rawKey))
		}
	case "3DES":
		if len(rawKey) != 24 {
			return 0, fmt.Errorf("invalid 3DES key length %d: must be 24 bytes", len(rawKey))
		}
	default:
		return 0, fmt.Errorf("unrecognized secret key algorithm %q", algorithm)
	}

	// Generate Ephemeral RSA wrapping keypair and extract the public key
	wrappingKeyHandle, unwrappingKeyHandle, err := p.GenerateRSAKeypair(sh, time.Now().Format(time.DateTime), nil, 2048, false, true)
	if err != nil {
		return 0, fmt.Errorf("wrapping key generation error: %w", err)
	}
	defer func() {
		err = errors.Join(err, p.destroyObjects(sh, wrappingKeyHandle, unwrappingKeyHandle))
	}()

	wrappingKeyPEM, err := p.ExportPublicKeyRSA(sh, wrappingKeyHandle)
	if err != nil {
		return 0, fmt.Errorf("wrapping key export error: %w", err)
	}
	b, rest := pem.Decode(wrappingKeyPEM)
	if b == nil || len(rest) != 0 {
		return 0, errors.New("wrapping key PEM parsing error")
	}
	wrappingKeyAny, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return 0, fmt.Errorf("wrapping key parsing error: %w", err)
	}
	wrappingKey, ok := wrappingKeyAny.(*rsa.PublicKey)
	if !ok {
		return 0, errors.New("wrapping key is not RSA? This should never happen")
	}

	// Wrap the symmetric key
	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, wrappingKey, rawKey, nil) //nolint:gosec // OAEP key-wrapping hash, kept for broad HSM compatibility
	if err != nil {
		return 0, fmt.Errorf("rsa oaep wrapping error: %w", err)
	}

	// Import/unwrap the wrapped symmetric key
	algo, err := pkcs11util.StringToAttribute(algorithm)
	if err != nil {
		return 0, err
	}
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, algo.Value),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}
	params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	return p.Ctx.UnwrapKey(sh, mech, unwrappingKeyHandle, wrappedKey, attribs)
}

// ImportPrivateKey imports an RSA or EC private key using an ephemeral AES 256 wrapping key.
func (p *P11) ImportPrivateKey(sh pkcs11.SessionHandle, rawKey []byte, keyLabel string, objectID []byte, algorithm string, extractable, ephemeral bool) (handle pkcs11.ObjectHandle, err error) {
	// Generate AES wrapping Key
	var wrappingKey = make([]byte, 32)
	if _, err := rand.Read(wrappingKey); err != nil {
		return 0, err
	}

	kwp, err := subtle.NewKWP(wrappingKey)
	if err != nil {
		return 0, err
	}

	// Wrap user key
	wrappedKey, err := kwp.Wrap(rawKey)
	if err != nil {
		return 0, err
	}

	// Import wrapping key
	wrappingKeyHandle, err := p.ImportSecretKey(sh, wrappingKey, time.Now().Format(time.DateTime), nil, "AES", false, true)
	if err != nil {
		return 0, err
	}
	defer func() {
		err = errors.Join(err, p.destroyObjects(sh, wrappingKeyHandle))
	}()

	// Import/unwrap user key
	algo, err := pkcs11util.StringToAttribute(algorithm)
	if err != nil {
		return 0, err
	}
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, algo.Value),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}
	return p.Ctx.UnwrapKey(sh, mech, wrappingKeyHandle, wrappedKey, attribs)
}
