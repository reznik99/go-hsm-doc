package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestSubjectKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	id, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 20 { // RFC 5280 method 1: SHA-1 digest is 20 bytes
		t.Errorf("id length = %d, want 20", len(id))
	}

	again, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(id, again) {
		t.Error("subjectKeyID not deterministic for the same key")
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	otherID, err := subjectKeyID(&other.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(id, otherID) {
		t.Error("subjectKeyID collided for different keys")
	}

	if _, err := subjectKeyID(nil); err == nil {
		t.Error("nil key: expected error, got nil")
	}
}

func TestPublicKeyFromPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}

	if pub, err := publicKeyFromPrivateKey(rsaKey); err != nil {
		t.Errorf("rsa: unexpected error %v", err)
	} else if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("rsa: got %T, want *rsa.PublicKey", pub)
	}
	if pub, err := publicKeyFromPrivateKey(ecKey); err != nil {
		t.Errorf("ec: unexpected error %v", err)
	} else if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("ec: got %T, want *ecdsa.PublicKey", pub)
	}
	if _, err := publicKeyFromPrivateKey("not a key"); err == nil {
		t.Error("unsupported: expected error, got nil")
	}
}

func TestPublicKeySearchTemplate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}

	rsaTemplate, err := publicKeySearchTemplate(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	assertAttribute(t, rsaTemplate, pkcs11.CKA_CLASS, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY).Value)
	assertAttribute(t, rsaTemplate, pkcs11.CKA_KEY_TYPE, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA).Value)
	assertAttribute(t, rsaTemplate, pkcs11.CKA_MODULUS, rsaKey.N.Bytes())

	ecTemplate, err := publicKeySearchTemplate(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("ec: %v", err)
	}
	assertAttribute(t, ecTemplate, pkcs11.CKA_KEY_TYPE, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC).Value)

	template, err := publicKeySearchTemplate("not a key")
	if err != nil || template != nil {
		t.Errorf("unsupported: got (%v, %v), want (nil, nil)", template, err)
	}
}

func assertAttribute(t *testing.T, template []*pkcs11.Attribute, typ uint, want []byte) {
	t.Helper()
	for _, attr := range template {
		if attr.Type == typ {
			if !bytes.Equal(attr.Value, want) {
				t.Errorf("attribute %d = %x, want %x", typ, attr.Value, want)
			}
			return
		}
	}
	t.Errorf("attribute %d not found in template", typ)
}
