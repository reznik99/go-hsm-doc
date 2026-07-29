package pkcs11util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

func TestDecodePEMOrDER(t *testing.T) {
	der := []byte{1, 2, 3}
	valid := pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: der})
	cases := []struct {
		name     string
		value    []byte
		wantDER  []byte
		wantType string
		wantErr  bool
	}{
		{"pem", valid, der, "TEST", false},
		{"der", der, der, "", false},
		{"trailing-whitespace", append(bytes.Clone(valid), '\n'), der, "TEST", false},
		{"trailing-data", append(bytes.Clone(valid), "trailing data"...), nil, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotDER, gotType, err := DecodePEMOrDER(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			if !bytes.Equal(gotDER, c.wantDER) || gotType != c.wantType {
				t.Errorf("got (%v, %q), want (%v, %q)", gotDER, gotType, c.wantDER, c.wantType)
			}
		})
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
		name    string
		data    []byte
		wantErr bool
	}{
		{"go-pkcs8-rsa", pkcs8, false},
		{"go-pkcs1-rsa", x509.MarshalPKCS1PrivateKey(rsaKey), false},
		{"go-sec1-ec", sec1, false},
		{"openssl-pkcs8-rsa", decodeTestPEM(t, opensslRSAPKCS8), false},
		{"openssl-pkcs1-rsa", decodeTestPEM(t, opensslRSAPKCS1), false},
		{"openssl-sec1-ec", decodeTestPEM(t, opensslECSEC1), false},
		{"openssl-pkcs8-rsa-pem", []byte(opensslRSAPKCS8), false},
		{"openssl-pkcs1-rsa-pem", []byte(opensslRSAPKCS1), false},
		{"openssl-sec1-ec-pem", []byte(opensslECSEC1), false},
		{"garbage", []byte{1, 2, 3}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ParsePrivateKey(c.data, nil)
			if (err != nil) != c.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}

	t.Run("plain-pem-with-unused-passphrase", func(t *testing.T) {
		if _, _, err := ParsePrivateKey([]byte(opensslRSAPKCS8), []byte("unused")); err != nil {
			t.Fatalf("parse plain PEM: %v", err)
		}
	})
}

func TestIsEncryptedPKCS8(t *testing.T) {
	cases := []struct {
		name string
		der  []byte
		want bool
	}{
		{"encrypted", decodeTestPEM(t, opensslEncryptedRSAPKCS8), true},
		{"plain", decodeTestPEM(t, opensslRSAPKCS8), false},
		{"garbage", []byte{1, 2, 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isEncryptedPKCS8(c.der); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	privateKey, err := x509.ParsePKCS8PrivateKey(decodeTestPEM(t, opensslRSAPKCS8))
	if err != nil {
		t.Fatalf("parse fixture private key: %v", err)
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(&privateKey.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}

	cases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"pkix-der", pkixDER, false},
		{"pkix-pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER}), false},
		{"openssh", []byte(opensshRSAPublic), false},
		{"garbage", []byte("not a public key"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ParsePublicKey(c.data)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			if !c.wantErr {
				if _, ok := key.(*rsa.PublicKey); !ok {
					t.Errorf("key type = %T, want *rsa.PublicKey", key)
				}
			}
		})
	}
}

func TestParseOpenSSHPrivateKey(t *testing.T) {
	publicKey, err := ParsePublicKey([]byte(opensshRSAPublic))
	if err != nil {
		t.Fatalf("parse fixture public key: %v", err)
	}
	wantModulus := publicKey.(*rsa.PublicKey).N

	cases := []struct {
		name               string
		data               []byte
		passphrase         []byte
		wantErr            bool
		passphraseRequired bool
	}{
		{"plain", []byte(opensshRSAPrivate), nil, false, false},
		{"encrypted-no-passphrase", []byte(opensshEncryptedRSAPrivate), nil, true, true},
		{"encrypted", []byte(opensshEncryptedRSAPrivate), []byte("test-passphrase"), false, false},
		{"wrong-passphrase", []byte(opensshEncryptedRSAPrivate), []byte("wrong"), true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, der, err := ParsePrivateKey(c.data, c.passphrase)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			if errors.Is(err, ErrPassphraseRequired) != c.passphraseRequired {
				t.Fatalf("passphrase required = %v, want %v", errors.Is(err, ErrPassphraseRequired), c.passphraseRequired)
			}
			if c.wantErr {
				return
			}
			if key.(*rsa.PrivateKey).N.Cmp(wantModulus) != 0 {
				t.Error("private key does not match OpenSSH public key")
			}
			if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
				t.Errorf("normalized PKCS#8 key: %v", err)
			}
		})
	}
}

func TestPKCS8EncryptRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}

	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal RSA PKCS#8: %v", err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal EC PKCS#8: %v", err)
	}

	cases := []struct {
		name       string
		plain      []byte
		encrypted  []byte
		passphrase string
	}{
		{"go-rsa", rsaPKCS8, nil, "correct horse battery staple"},
		{"go-ec", ecPKCS8, nil, "correct horse battery staple"},
		{"openssl-rsa", decodeTestPEM(t, opensslRSAPKCS8), decodeTestPEM(t, opensslEncryptedRSAPKCS8), "test-passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encrypted := c.encrypted
			if encrypted == nil {
				var err error
				encrypted, err = EncryptPKCS8(c.plain, c.passphrase)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
			}
			if _, err := x509.ParsePKCS8PrivateKey(encrypted); err == nil {
				t.Error("encrypted output still parses as plaintext PKCS#8")
			}
			if _, _, err := ParsePrivateKey(encrypted, nil); !errors.Is(err, ErrPassphraseRequired) {
				t.Fatalf("missing passphrase error = %v, want ErrPassphraseRequired", err)
			}
			_, normalized, err := ParsePrivateKey(encrypted, []byte(c.passphrase))
			if err != nil {
				t.Fatalf("parse encrypted key: %v", err)
			}
			if !bytes.Equal(normalized, c.plain) {
				t.Error("parsed key did not normalize to the original PKCS#8 key")
			}

			decrypted, err := DecryptPKCS8(encrypted, c.passphrase)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, c.plain) {
				t.Error("round-trip did not recover the original key")
			}

			if _, err := DecryptPKCS8(encrypted, "wrong passphrase"); err == nil {
				t.Error("wrong passphrase: expected error, got nil")
			}
		})
	}

	t.Run("openssl-pem", func(t *testing.T) {
		if _, _, err := ParsePrivateKey([]byte(opensslEncryptedRSAPKCS8), nil); !errors.Is(err, ErrPassphraseRequired) {
			t.Fatalf("missing passphrase error = %v, want ErrPassphraseRequired", err)
		}
		if _, _, err := ParsePrivateKey([]byte(opensslEncryptedRSAPKCS8), []byte("test-passphrase")); err != nil {
			t.Fatalf("parse encrypted PEM: %v", err)
		}
	})
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
