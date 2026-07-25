package hsm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/hsm/mocks"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
	"github.com/stretchr/testify/mock"
)

const testHandle = pkcs11.ObjectHandle(5)

func parsePEMPublic(t *testing.T, pemBytes []byte) any {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("output is not PEM: %q", pemBytes)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return pub
}

func TestExportCertificateWrapsDERinPEM(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0x02, 0x03}
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetAttributeValue(testSession, testHandle, mock.Anything).
		Return([]*pkcs11.Attribute{{Type: pkcs11.CKA_VALUE, Value: der}}, nil)
	p11 := &P11{Ctx: ctx}

	out, err := p11.ExportCertificate(testSession, testHandle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	block, _ := pem.Decode(out)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) {
		t.Errorf("output = %q, want a CERTIFICATE PEM wrapping the DER", out)
	}
}

func TestExportPublicKeyRSARoundTrip(t *testing.T) {
	key := generateTestRSA(t)
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetAttributeValue(testSession, testHandle, mock.Anything).Return([]*pkcs11.Attribute{
		{Type: pkcs11.CKA_MODULUS, Value: key.N.Bytes()},
		{Type: pkcs11.CKA_PUBLIC_EXPONENT, Value: big.NewInt(int64(key.E)).Bytes()},
	}, nil)
	p11 := &P11{Ctx: ctx}

	out, err := p11.ExportPublicKeyRSA(testSession, testHandle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pub, ok := parsePEMPublic(t, out).(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		t.Errorf("exported RSA key does not match the source")
	}
}

func TestExportPublicKeyECRoundTrip(t *testing.T) {
	key := generateTestECC(t)
	params, err := pkcs11util.CurveNameToECParams("p256")
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	point, err := pkcs11util.MarshalECPoint(&key.PublicKey)
	if err != nil {
		t.Fatalf("point: %v", err)
	}
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetAttributeValue(testSession, testHandle, mock.Anything).Return([]*pkcs11.Attribute{
		{Type: pkcs11.CKA_EC_PARAMS, Value: params},
		{Type: pkcs11.CKA_EC_POINT, Value: point},
	}, nil)
	p11 := &P11{Ctx: ctx}

	out, err := p11.ExportPublicKeyEC(testSession, testHandle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pub, ok := parsePEMPublic(t, out).(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Errorf("exported EC key does not match the source")
	}
}

func TestExportPublicKeyUnknownType(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetAttributeValue(testSession, testHandle, mock.Anything).
		Return([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DSA)}, nil)
	p11 := &P11{Ctx: ctx}

	if _, err := p11.ExportPublicKey(testSession, testHandle); err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}
