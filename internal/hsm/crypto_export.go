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
	"time"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// ExportCertificate extracts, parses and prints a Certificate from the HSM
func (p *P11) ExportCertificate(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	attr, err := p.Ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, err
	}

	certificateDER := attr[0].Value

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	}

	return pem.EncodeToMemory(block), nil
}

// ExportPublicKey extracts, parses and prints a Public Key from the HSM
func (p *P11) ExportPublicKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, algorithm uint) ([]byte, error) {
	switch algorithm {
	case pkcs11.CKK_RSA:
		return p.ExportPublicKeyRSA(sh, oh)
	case pkcs11.CKK_EC:
		return p.ExportPublicKeyEC(sh, oh)
	default:
		return nil, fmt.Errorf("unrecognized algorithm: %d", algorithm)
	}
}

// ExportPublicKeyRSA extracts, parses and prints an RSA Public Key from the HSM
func (p *P11) ExportPublicKeyRSA(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	attr, err := p.Ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, err
	}

	// Create an RSA public key.
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(attr[0].Value),
		E: int(new(big.Int).SetBytes(attr[1].Value).Int64()),
	}

	// Marshal the RSA public key into PKIX PEM format.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		return nil, err
	}

	// Generate a PEM block for the RSA public key.
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pubKeyPEM), nil
}

// ExportPublicKeyEC extracts, parses and prints an EC Public Key from the HSM
func (p *P11) ExportPublicKeyEC(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	attr, err := p.Ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}

	// Parse EC_PARAMS
	curve, err := pkcs11util.ECParamsToCurve(attr[0].Value)
	if err != nil {
		return nil, err
	}

	// Parse EC_POINT
	x, y, err := pkcs11util.ParseECPoint(curve, attr[1].Value)
	if err != nil {
		return nil, err
	}

	// Create an ECDSA public key.
	ecPublicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Marshal the EC public key into PKIX PEM format.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ecPublicKey)
	if err != nil {
		return nil, err
	}

	// Generate a PEM block for the EC public key.
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pubKeyPEM), nil
}

// ExportSecretKey extracts, parses and prints an AES/DES/3DES key using an ephemeral RSA_OAEP wrapping key.
func (p *P11) ExportSecretKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (key []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	wrapKey, err := p.ImportPublicKey(sh, &priv.PublicKey, time.Now().Format(time.DateTime), nil, true)
	if err != nil {
		return nil, fmt.Errorf("wrapping key import error: %w", err)
	}
	defer func() {
		err = errors.Join(err, p.destroyObjects(sh, wrapKey))
	}()

	// Wrap AES key with imported wrapping key
	wrapParam := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil)
	wrapMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, wrapParam)}
	wrappedKey, err := p.Ctx.WrapKey(sh, wrapMech, wrapKey, oh)
	if err != nil {
		return nil, fmt.Errorf("wrapping error: %w", err)
	}

	// Unwrap key
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, wrappedKey, nil) //nolint:gosec // OAEP key-wrapping hash, kept for broad HSM compatibility
}

// ExportPrivateKey extracts, parses and prints an RSA/EC key using an ephemeral AES wrapping key.
func (p *P11) ExportPrivateKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (key []byte, err error) {

	// Generate Ephemeral AES KEK
	wrapKeyName := "KEK-" + time.Now().Format(time.DateTime)
	wrapKey, err := p.GenerateAESKey(sh, wrapKeyName, nil, 256, true, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, p.destroyObjects(sh, wrapKey))
	}()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}
	wrappedKey, err := p.Ctx.WrapKey(sh, mech, wrapKey, oh)
	if err != nil {
		return nil, err
	}

	// Extract AES KEK
	wrappingKey, err := p.ExportSecretKey(sh, wrapKey)
	if err != nil {
		return nil, err
	}

	// Unwrap Private Key
	kwp, err := subtle.NewKWP(wrappingKey)
	if err != nil {
		return nil, err
	}

	key, err = kwp.Unwrap(wrappedKey)
	if err != nil {
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key,
	})
	return keyPem, nil
}
