package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
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

func (p *P11) GenerateAESKey(slotID uint, label string, keylength int, extractable bool) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keylength/8),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	_, err := p.ctx.GenerateKey(sh, mech, temp)

	return err
}

func (p *P11) GenerateDESKey(slotID uint, label string, keylength int, extractable bool) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
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

	_, err := p.ctx.GenerateKey(sh, mech, temp)

	return err
}

func (p *P11) GenerateRSAKeypair(slotID uint, label string, keylength int, extractable bool) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keylength),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
	}
	private := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	_, _, err := p.ctx.GenerateKeyPair(sh, mech, public, private)

	return err
}

func (p *P11) GenerateECKeypair(slotID uint, label string, keylength int, extractable bool) error {
	return fmt.Errorf("unimplemented method: GenerateECKeypair")
}

func (p *P11) ExportCertificate(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return err
	}

	certificateDER := attr[0].Value

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	}
	fmt.Print(string(pem.EncodeToMemory(block)))

	return nil
}

// ExportPublicKey extracts, parses and prints Public Key or Certificate from the HSM
func (p *P11) ExportPublicKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, algorithm uint) error {
	switch algorithm {
	case pkcs11.CKK_RSA:
		return p.ExportPublicKeyRSA(sh, oh)
	case pkcs11.CKK_EC:
		return p.ExportPublicKeyEC(sh, oh)
	}
	return nil
}

// ExportPublicKeyRSA extracts, parses and prints an RSA Public Key from the HSM
func (p *P11) ExportPublicKeyRSA(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return err
	}

	// Create an RSA public key.
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(attr[0].Value),
		E: int(new(big.Int).SetBytes(attr[1].Value).Int64()),
	}

	// Marshal the RSA public key into PKIX PEM format.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		return err
	}

	// Generate a PEM block for the RSA public key.
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Print the PKIX PEM string to the console.
	fmt.Print(string(pem.EncodeToMemory(pubKeyPEM)))

	return nil
}

// ExportPublicKeyEC extracts, parses and prints an EC Public Key from the HSM
func (p *P11) ExportPublicKeyEC(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	attr, err := p.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return err
	}

	curve, err := ECParamsToCurve(attr[0].Value)
	if err != nil {
		return err
	}

	// Create an ECDSA public key.
	x, y := elliptic.Unmarshal(curve, attr[1].Value)
	ecPublicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Marshal the RSA public key into PKIX PEM format.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ecPublicKey)
	if err != nil {
		return err
	}

	// Generate a PEM block for the RSA public key.
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Print the PKIX PEM string to the console.
	fmt.Print(string(pem.EncodeToMemory(pubKeyPEM)))

	return nil
}

// ExportSecretKey TODO
func (p *P11) ExportSecretKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, algorithm uint) error {
	switch algorithm {
	case pkcs11.CKK_AES:
		return fmt.Errorf("secret key export unimplemented")
	case pkcs11.CKK_DES:
		return fmt.Errorf("secret key export unimplemented")
	case pkcs11.CKK_DES2:
		return fmt.Errorf("secret key export unimplemented")
	case pkcs11.CKK_DES3:
		return fmt.Errorf("secret key export unimplemented")
	}
	return nil
}

// ExportPrivateKey TODO
func (p *P11) ExportPrivateKey(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, algorithm uint) error {
	switch algorithm {
	case pkcs11.CKK_RSA:
		return fmt.Errorf("private key export unimplemented")
	case pkcs11.CKK_EC:
		return fmt.Errorf("private key export unimplemented")
	}
	return nil
}
