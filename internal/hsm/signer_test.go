package hsm

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/hsm/mocks"
	"github.com/stretchr/testify/mock"
)

func TestSignerRSASignsDigestInfo(t *testing.T) {
	key := generateTestRSA(t)
	digest := sha256.Sum256([]byte("data"))

	var mech []*pkcs11.Mechanism
	var signed []byte
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().SignInit(testSession, mock.Anything, testHandle).
		Run(func(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, _ pkcs11.ObjectHandle) { mech = m }).Return(nil)
	ctx.EXPECT().Sign(testSession, mock.Anything).
		Run(func(_ pkcs11.SessionHandle, data []byte) { signed = data }).Return([]byte("signature"), nil)
	p11 := &P11{Ctx: ctx}

	sig, err := p11.NewSigner(testSession, testHandle, &key.PublicKey).Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sig) != "signature" {
		t.Error("token signature was not returned verbatim")
	}
	if len(mech) != 1 || mech[0].Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Error("mechanism is not CKM_RSA_PKCS")
	}
	want, err := asn1.Marshal(digestInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: hashOIDs[crypto.SHA256], Parameters: asn1.NullRawValue},
		Digest:    digest[:],
	})
	if err != nil {
		t.Fatalf("build expected DigestInfo: %v", err)
	}
	if !bytes.Equal(signed, want) {
		t.Error("signed data is not the SHA-256 DigestInfo")
	}
}

func TestSignerECDSAEncodesSignature(t *testing.T) {
	key := generateTestECC(t)
	digest := sha256.Sum256([]byte("data"))
	r := bytes.Repeat([]byte{0xAB}, 32)
	s := bytes.Repeat([]byte{0xCD}, 32)
	raw := append(append([]byte{}, r...), s...) // token returns raw r||s

	var mech []*pkcs11.Mechanism
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().SignInit(testSession, mock.Anything, testHandle).
		Run(func(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, _ pkcs11.ObjectHandle) { mech = m }).Return(nil)
	ctx.EXPECT().Sign(testSession, digest[:]).Return(raw, nil)
	p11 := &P11{Ctx: ctx}

	sig, err := p11.NewSigner(testSession, testHandle, &key.PublicKey).Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mech) != 1 || mech[0].Mechanism != pkcs11.CKM_ECDSA {
		t.Error("mechanism is not CKM_ECDSA")
	}
	var got ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &got)
	if err != nil || len(rest) != 0 {
		t.Fatalf("signature is not a valid ASN.1 SEQUENCE: %v", err)
	}
	if got.R.Cmp(new(big.Int).SetBytes(r)) != 0 || got.S.Cmp(new(big.Int).SetBytes(s)) != 0 {
		t.Error("r/s were not decoded from the raw token signature")
	}
}

func TestSignerUnsupportedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t)}
	if _, err := p11.NewSigner(testSession, testHandle, pub).Sign(rand.Reader, []byte("digest"), crypto.SHA256); err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}
