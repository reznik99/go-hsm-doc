package hsm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/hsm/mocks"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
	"github.com/stretchr/testify/mock"
)

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// captureCreateObject records the template passed to CreateObject.
func captureCreateObject(ctx *mocks.MockCryptoki, dst *[]*pkcs11.Attribute) {
	ctx.EXPECT().CreateObject(testSession, mock.Anything).
		Run(func(_ pkcs11.SessionHandle, temp []*pkcs11.Attribute) { *dst = temp }).
		Return(pkcs11.ObjectHandle(1), nil)
}

func TestImportPublicKeyRSATemplate(t *testing.T) {
	key := generateTestRSA(t)
	var captured []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	captureCreateObject(ctx, &captured)
	p11 := &P11{Ctx: ctx}

	if _, err := p11.ImportPublicKey(testSession, &key.PublicKey, "label", []byte{0x02}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_MODULUS), key.N.Bytes()) {
		t.Error("CKA_MODULUS mismatch")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_PUBLIC_EXPONENT), big.NewInt(int64(key.E)).Bytes()) {
		t.Error("CKA_PUBLIC_EXPONENT is not minimal big-endian")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_ID), []byte{0x02}) {
		t.Error("CKA_ID mismatch")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_KEY_TYPE), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA).Value) {
		t.Error("CKA_KEY_TYPE is not RSA")
	}
}

func TestImportPublicKeyECWrapsPoint(t *testing.T) {
	key := generateTestECC(t)
	var captured []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	captureCreateObject(ctx, &captured)
	p11 := &P11{Ctx: ctx}

	if _, err := p11.ImportPublicKey(testSession, &key.PublicKey, "label", []byte{0x02}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPoint, err := pkcs11util.MarshalECPoint(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal point: %v", err)
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_EC_POINT), wantPoint) {
		t.Error("CKA_EC_POINT is not the OCTET STRING-wrapped point")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_KEY_TYPE), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC).Value) {
		t.Error("CKA_KEY_TYPE is not EC")
	}
}

func TestImportCertificateTemplate(t *testing.T) {
	cert := selfSignedCert(t)
	var captured []*pkcs11.Attribute
	ctx := mocks.NewMockCryptoki(t)
	captureCreateObject(ctx, &captured)
	p11 := &P11{Ctx: ctx}

	if _, err := p11.ImportCertificate(testSession, cert, "label", []byte{0x02}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_VALUE), cert.Raw) {
		t.Error("CKA_VALUE != cert.Raw")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_CLASS), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE).Value) {
		t.Error("CKA_CLASS is not CERTIFICATE")
	}
	if !bytes.Equal(attrValue(t, captured, pkcs11.CKA_ID), []byte{0x02}) {
		t.Error("CKA_ID mismatch")
	}
}
