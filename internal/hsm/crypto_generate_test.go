package hsm

import (
	"bytes"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/hsm/mocks"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
	"github.com/stretchr/testify/mock"
)

func TestGenerateAESKeyTemplate(t *testing.T) {
	var mech []*pkcs11.Mechanism
	var tmpl []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GenerateKey(testSession, mock.Anything, mock.Anything).
		Run(func(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, temp []*pkcs11.Attribute) { mech = m; tmpl = temp }).
		Return(pkcs11.ObjectHandle(1), nil)
	p11 := &P11{Ctx: ctx}

	// objectID nil -> the driver auto-generates a 16-byte CKA_ID.
	if _, err := p11.GenerateAESKey(testSession, "label", nil, 256, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mech) != 1 || mech[0].Mechanism != pkcs11.CKM_AES_KEY_GEN {
		t.Error("mechanism is not CKM_AES_KEY_GEN")
	}
	if !bytes.Equal(attrValue(t, tmpl, pkcs11.CKA_VALUE_LEN), pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 256/8).Value) {
		t.Error("CKA_VALUE_LEN should be 32 bytes (256 bits)")
	}
	if len(attrValue(t, tmpl, pkcs11.CKA_ID)) != 16 {
		t.Error("expected a 16-byte auto-generated CKA_ID")
	}
	if !bytes.Equal(attrValue(t, tmpl, pkcs11.CKA_EXTRACTABLE), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true).Value) {
		t.Error("CKA_EXTRACTABLE should be true")
	}
}

func TestGenerateAESKeyRejectsInvalidLength(t *testing.T) {
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t)}
	if _, err := p11.GenerateAESKey(testSession, "label", nil, 135, false, false); err == nil {
		t.Fatal("expected an error for an invalid AES key length")
	}
}

func TestGenerateDESKeyRejectsInvalidLength(t *testing.T) {
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t)}
	if _, err := p11.GenerateDESKey(testSession, "label", nil, 256, false, false); err == nil {
		t.Fatal("expected an error for an invalid DES key length")
	}
}

func TestGenerateRSAKeypairTemplates(t *testing.T) {
	var mech []*pkcs11.Mechanism
	var pub, priv []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GenerateKeyPair(testSession, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) {
			mech, pub, priv = m, public, private
		}).Return(pkcs11.ObjectHandle(1), pkcs11.ObjectHandle(2), nil)
	p11 := &P11{Ctx: ctx}

	if _, _, err := p11.GenerateRSAKeypair(testSession, "label", []byte{0x01}, 2048, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mech) != 1 || mech[0].Mechanism != pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN {
		t.Error("mechanism is not CKM_RSA_PKCS_KEY_PAIR_GEN")
	}
	if !bytes.Equal(attrValue(t, pub, pkcs11.CKA_MODULUS_BITS), pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048).Value) {
		t.Error("CKA_MODULUS_BITS should be 2048")
	}
	if !bytes.Equal(attrValue(t, pub, pkcs11.CKA_ID), []byte{0x01}) || !bytes.Equal(attrValue(t, priv, pkcs11.CKA_ID), []byte{0x01}) {
		t.Error("public and private keys should share CKA_ID 0x01")
	}
	if !bytes.Equal(attrValue(t, priv, pkcs11.CKA_EXTRACTABLE), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false).Value) {
		t.Error("private CKA_EXTRACTABLE should be false")
	}
}

func TestGenerateECKeypairTemplate(t *testing.T) {
	var mech []*pkcs11.Mechanism
	var pub []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GenerateKeyPair(testSession, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, public, _ []*pkcs11.Attribute) {
			mech, pub = m, public
		}).Return(pkcs11.ObjectHandle(1), pkcs11.ObjectHandle(2), nil)
	p11 := &P11{Ctx: ctx}

	if _, err := p11.GenerateECKeypair(testSession, "label", []byte{0x02}, "P-256", false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mech) != 1 || mech[0].Mechanism != pkcs11.CKM_EC_KEY_PAIR_GEN {
		t.Error("mechanism is not CKM_EC_KEY_PAIR_GEN")
	}
	wantParams, err := pkcs11util.CurveNameToECParams("P-256")
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if !bytes.Equal(attrValue(t, pub, pkcs11.CKA_EC_PARAMS), wantParams) {
		t.Error("CKA_EC_PARAMS mismatch for P-256")
	}
}
