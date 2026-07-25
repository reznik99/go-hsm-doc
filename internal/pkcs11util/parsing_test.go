package pkcs11util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParsePEMBlock(t *testing.T) {
	valid := string(pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: []byte{1, 2, 3}}))

	if _, err := ParsePEMBlock(valid, "test"); err != nil {
		t.Errorf("valid PEM: unexpected error %v", err)
	}
	if _, err := ParsePEMBlock("not a pem block", "test"); err == nil {
		t.Error("garbage: expected error, got nil")
	}
	if _, err := ParsePEMBlock(valid+"trailing bytes", "test"); err == nil {
		t.Error("trailing bytes: expected error, got nil")
	}
}

func TestParsePrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal sec1: %v", err)
	}

	cases := []struct {
		name string
		der  []byte
	}{
		{"pkcs8-rsa", pkcs8},
		{"pkcs1-rsa", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"sec1-ec", sec1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(c.der); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	if _, err := ParsePrivateKey([]byte{1, 2, 3}); err == nil {
		t.Error("garbage: expected error, got nil")
	}
}

func TestDetectKeyAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}

	cases := []struct {
		name    string
		key     any
		want    string
		wantErr bool
	}{
		{"rsa-public", &rsaKey.PublicKey, "RSA", false},
		{"rsa-private", rsaKey, "RSA", false},
		{"ec-public", &ecKey.PublicKey, "EC", false},
		{"ec-private", ecKey, "EC", false},
		{"unsupported", "not a key", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DetectKeyAlgorithm(c.key)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil || got != c.want {
				t.Errorf("got (%q, %v), want (%q, nil)", got, err, c.want)
			}
		})
	}
}
