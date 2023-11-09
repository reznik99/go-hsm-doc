package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/miekg/pkcs11"
	keywrap "github.com/nickball/go-aes-key-wrap"
	"github.com/pterm/pterm"
)

type P11 struct {
	ctx      *pkcs11.Ctx
	sessions map[uint]pkcs11.SessionHandle
}

func NewP11(modulePath string) (*P11, error) {
	module := &P11{
		sessions: map[uint]pkcs11.SessionHandle{},
	}

	module.ctx = pkcs11.New(modulePath)
	if module.ctx == nil {
		return nil, fmt.Errorf("error loading module")
	}
	err := module.ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("error initializing module: %s", err)
	}

	return module, nil
}

func (p *P11) GetSlots() (map[uint]pkcs11.TokenInfo, error) {
	output := map[uint]pkcs11.TokenInfo{}

	slots, err := p.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("error reading Slots: %s", err)
	}

	for _, slotID := range slots {
		ti, err := p.ctx.GetTokenInfo(slotID)
		if err != nil {
			logger.Warn("Error getting slot info", logger.Args("", err))
			continue
		}
		if ti.Label == "" {
			continue
		}
		output[slotID] = ti
	}

	return output, nil
}

func (p *P11) FindObjects(slotID uint, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	sh, ok := p.sessions[slotID]
	if !ok {
		return nil, fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	err := p.ctx.FindObjectsInit(sh, []*pkcs11.Attribute{})
	if err != nil {
		return nil, fmt.Errorf("find objects init error: %w", err)
	}
	defer p.ctx.FindObjectsFinal(sh)

	objects, _, err := p.ctx.FindObjects(sh, 1000)
	if err != nil {
		return nil, fmt.Errorf("find objects error: %w", err)
	}

	return objects, nil
}

func (p *P11) OpenSession(slotID uint) error {
	// Use existing
	_, ok := p.sessions[slotID]
	if ok {
		return nil
	}
	// Open new connection
	sh, err := p.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	p.sessions[slotID] = sh
	return nil
}

func (p *P11) CloseAllSessions() error {
	for _, sh := range p.sessions {
		err := p.ctx.CloseSession(sh)
		if err != nil {
			pterm.Warning.Printfln("Failed to close session %d: %s", sh, err)
		}
	}
	return nil
}

func (p *P11) Login(slotID uint, pin string) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}
	return p.ctx.Login(sh, pkcs11.CKU_USER, pin)
}

func (p *P11) Finalize() error {
	err := p.ctx.Finalize()
	if err != nil {
		return err
	}
	p.ctx.Destroy()
	return nil
}

// GenerateRSAKeypair generates a AES key in the HSM
func (p *P11) GenerateAESKey(sh pkcs11.SessionHandle, label string, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keylength/8),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	return p.ctx.GenerateKey(sh, mech, temp)
}

// GenerateRSAKeypair generates a DES key in the HSM
func (p *P11) GenerateDESKey(sh pkcs11.SessionHandle, label string, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	mech := []*pkcs11.Mechanism{}

	switch keylength {
	case 64: // DES
		mech = append(mech, pkcs11.NewMechanism(pkcs11.CKM_DES_KEY_GEN, nil))
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES))
	case 128: // DES2
		mech = append(mech, pkcs11.NewMechanism(pkcs11.CKM_DES2_KEY_GEN, nil))
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES2))
	case 192: // DES3
		mech = append(mech, pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil))
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES3))
	}

	return p.ctx.GenerateKey(sh, mech, temp)
}

// GenerateRSAKeypair generates an RSA Keypair in the HSM
func (p *P11) GenerateRSAKeypair(sh pkcs11.SessionHandle, label string, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keylength),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
	}
	private := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	_, priv, err := p.ctx.GenerateKeyPair(sh, mech, public, private)
	return priv, err
}

// GenerateECKeypair generates an EC Keypair in the HSM
func (p *P11) GenerateECKeypair(sh pkcs11.SessionHandle, label string, curve string, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}

	ecParams, err := CurveNameToECParams(curve)
	if err != nil {
		return pkcs11.ObjectHandle(0), err
	}
	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	private := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	_, priv, err := p.ctx.GenerateKeyPair(sh, mech, public, private)
	return priv, err
}

// ImportPublicKey imports a public key into the hsm without wrapping
func (p *P11) ImportPublicKey(sh pkcs11.SessionHandle, pub any, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	switch publicKey := pub.(type) {
	case rsa.PublicKey:
		// Allow for 128-bit integer for future-proofing
		exponent := make([]byte, 8)
		binary.BigEndian.PutUint64(exponent, uint64(publicKey.E))
		wrapkeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, publicKey.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.ctx.CreateObject(sh, wrapkeyTemplate)
	case ecdsa.PublicKey:
		return 0, fmt.Errorf("ec public key import unimplemented")
	default:
		return 0, fmt.Errorf("unrecognized key type: %T", publicKey)
	}
}

// ExportCertificate extracts, parses and prints a Certificate from the HSM
func (p *P11) ExportCertificate(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
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
func (p *P11) ExportPublicKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, algorithm uint32) ([]byte, error) {
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
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
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
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}

	// Parse EC_PARAMS
	curve, err := ECParamsToCurve(attr[0].Value)
	if err != nil {
		return nil, err
	}

	// Parse EC_POINT
	var point asn1.RawValue
	_, err = asn1.Unmarshal(attr[1].Value, &point)
	if err != nil {
		return nil, err
	}

	// Create an ECDSA public key.
	x, y := elliptic.Unmarshal(curve, point.Bytes)
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
func (p *P11) ExportSecretKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	wrapKey, err := p.ImportPublicKey(sh, priv.PublicKey, true, true)
	if err != nil {
		return nil, fmt.Errorf("wrapping key import error: %w", err)
	}
	defer p.ctx.DestroyObject(sh, wrapKey)

	// Wrap AES key with imported wrapping key
	wrapParam := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil)
	wrapMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, wrapParam)}
	wrappedKey, err := p.ctx.WrapKey(sh, wrapMech, wrapKey, oh)
	if err != nil {
		return nil, fmt.Errorf("wrapping error: %w", err)
	}

	// Unwrap key
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, wrappedKey, nil)
}

// ExportPrivateKey extracts, parses and prints an RSA/EC key using an ephemeral AES wrapping key.
func (p *P11) ExportPrivateKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {

	// Generate Ephemeral AES KEK
	wrapKeyName := fmt.Sprintf("KEK-%s", time.Now().Format(time.DateTime))
	wrapKey, err := p.GenerateAESKey(sh, wrapKeyName, 256, true, true)
	if err != nil {
		return nil, err
	}
	defer p.ctx.DestroyObject(sh, wrapKey)

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}
	wrappedKey, err := p.ctx.WrapKey(sh, mech, wrapKey, oh)
	if err != nil {
		return nil, err
	}

	// Extract AES KEK
	wrappingKey, err := p.ExportSecretKey(sh, wrapKey)
	if err != nil {
		return nil, err
	}

	// Unwrap Private Key
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	key, err := keywrap.Unwrap(block, wrappedKey)
	if err != nil {
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key,
	})
	return keyPem, nil
}
