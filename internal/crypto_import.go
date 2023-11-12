package internal

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/miekg/pkcs11"
	keywrap "github.com/nickball/go-aes-key-wrap"
)

// ImportPublicKey imports a Certificate into the hsm without wrapping
func (p *P11) ImportCertificate(sh pkcs11.SessionHandle, cert *x509.Certificate, label string, ephemeral bool) (pkcs11.ObjectHandle, error) {

	wrapkeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	}
	return p.Ctx.CreateObject(sh, wrapkeyTemplate)
}

// ImportPublicKey imports an RSA/EC Public Key into the hsm without wrapping
func (p *P11) ImportPublicKey(sh pkcs11.SessionHandle, pub any, keyLabel string, ephemeral bool) (pkcs11.ObjectHandle, error) {
	switch publicKey := pub.(type) {
	case *rsa.PublicKey:
		// Allow for 128-bit integer for future-proofing
		exponent := make([]byte, 8)
		binary.BigEndian.PutUint64(exponent, uint64(publicKey.E))
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, publicKey.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.Ctx.CreateObject(sh, template)
	case *ecdsa.PublicKey:
		// Parse curve into Params
		params, err := CurveNameToECParams(publicKey.Params().Name)
		if err != nil {
			return pkcs11.ObjectHandle(0), err
		}
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.Ctx.CreateObject(sh, template)
	default:
		// TODO: Support X25519 and/or DH keys?
		return 0, fmt.Errorf("unrecognized key type: %T", publicKey)
	}
}

// ImportSecretKey imports an AES/DES/3DES Secret Key into the HSM using an ephemeral RSA 2048 wrapping key
func (p *P11) ImportSecretKey(sh pkcs11.SessionHandle, rawKey []byte, keylabel string, ephemeral bool, algorithm string) (pkcs11.ObjectHandle, error) {
	// Generate Ephemeral RSA wrapping keypair and extract the public key
	wrappingKeyHandle, unwrappingKeyHandle, err := p.GenerateRSAKeypair(sh, time.Now().Format(time.DateTime), 2048, false, true)
	if err != nil {
		return 0, fmt.Errorf("wrapping key generation error: %s", err)
	}
	defer p.Ctx.DestroyObject(sh, wrappingKeyHandle)
	defer p.Ctx.DestroyObject(sh, unwrappingKeyHandle)

	wrappingKeyPEM, err := p.ExportPublicKeyRSA(sh, wrappingKeyHandle)
	if err != nil {
		return 0, fmt.Errorf("wrapping key export error: %s", err)
	}
	b, rest := pem.Decode(wrappingKeyPEM)
	if len(rest) != 0 {
		return 0, fmt.Errorf("wrapping key pem parsing error: %s", err)
	}
	wrappingKeyAny, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return 0, fmt.Errorf("wrapping key parsing error: %s", err)
	}
	wrappingKey, ok := wrappingKeyAny.(*rsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("wrapping key is not RSA? This should never happen")
	}

	// Wrap the symmetric key
	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, wrappingKey, rawKey, nil)
	if err != nil {
		return 0, fmt.Errorf("rsa oaep wrapping error: %s", err)
	}

	// Import/unwrap the wrapped symmetric key
	algo, err := StringToAttribute(algorithm)
	if err != nil {
		return 0, err
	}
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keylabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, algo.Value),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	return p.Ctx.UnwrapKey(sh, mech, unwrappingKeyHandle, wrappedKey, attribs)
}

// ImportPrivateKey imports an RSA/EC Private Key into the HSM using an ephemeral AES 256 wrapping key
func (p *P11) ImportPrivateKey(sh pkcs11.SessionHandle, rawKey []byte, keylabel string, ephemeral bool, algorithm string) (pkcs11.ObjectHandle, error) {
	// Generate AES wrapping Key
	var wrappingKey = make([]byte, 32)
	if _, err := rand.Read(wrappingKey); err != nil {
		return 0, err
	}

	b, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return 0, err
	}

	// Wrap user key
	wrappedKey, err := keywrap.Wrap(b, rawKey)
	if err != nil {
		return 0, err
	}

	// Import wrapping key
	wrappingKeyHandle, err := p.ImportSecretKey(sh, wrappingKey, time.Now().Format(time.DateTime), true, "AES")
	if err != nil {
		return 0, err
	}
	defer p.Ctx.DestroyObject(sh, wrappingKeyHandle)

	// Import/unwrap user key
	algo, err := StringToAttribute(algorithm)
	if err != nil {
		return 0, err
	}
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keylabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, algo.Value),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}
	return p.Ctx.UnwrapKey(sh, mech, wrappingKeyHandle, wrappedKey, attribs)
}
