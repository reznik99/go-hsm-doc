package hsm

import (
	"crypto/rand"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
)

// GenerateAESKey generates an AES key in the HSM.
func (p *P11) GenerateAESKey(sh pkcs11.SessionHandle, label string, objectID []byte, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	if objectID == nil {
		objectID = make([]byte, 16)
		if _, err := rand.Read(objectID); err != nil {
			return 0, fmt.Errorf("generate object ID: %w", err)
		}
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
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
	return p.Ctx.GenerateKey(sh, mech, temp)
}

// GenerateDESKey generates a DES-family key in the HSM.
func (p *P11) GenerateDESKey(sh pkcs11.SessionHandle, label string, objectID []byte, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	if objectID == nil {
		objectID = make([]byte, 16)
		if _, err := rand.Read(objectID); err != nil {
			return 0, fmt.Errorf("generate object ID: %w", err)
		}
	}

	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
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

	return p.Ctx.GenerateKey(sh, mech, temp)
}

// GenerateRSAKeypair generates an RSA key pair in the HSM.
func (p *P11) GenerateRSAKeypair(sh pkcs11.SessionHandle, label string, objectID []byte, keylength int, extractable, ephemeral bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if objectID == nil {
		objectID = make([]byte, 16)
		if _, err := rand.Read(objectID); err != nil {
			return 0, 0, fmt.Errorf("generate object ID: %w", err)
		}
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
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
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
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
	return p.Ctx.GenerateKeyPair(sh, mech, public, private)
}

// GenerateECKeypair generates an EC key pair in the HSM.
func (p *P11) GenerateECKeypair(sh pkcs11.SessionHandle, label string, objectID []byte, curve string, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	if objectID == nil {
		objectID = make([]byte, 16)
		if _, err := rand.Read(objectID); err != nil {
			return 0, fmt.Errorf("generate object ID: %w", err)
		}
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}

	ecParams, err := pkcs11util.CurveNameToECParams(curve)
	if err != nil {
		return pkcs11.ObjectHandle(0), err
	}
	public := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	private := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, objectID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}
	_, priv, err := p.Ctx.GenerateKeyPair(sh, mech, public, private)
	return priv, err
}
