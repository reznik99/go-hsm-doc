package pkcs11util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/youmark/pkcs8"
)

const (
	// 600k HMAC-SHA256 iterations is the OWASP Password Storage recommendation for PBKDF2.
	// It is a floor that should be raised over time as hardware improves.
	pkcs8PBKDF2Iterations = 600_000
	// 128 bits, the NIST SP 800-132 minimum salt length.
	pkcs8SaltSize = 16
)

func ParsePEMBlock(raw, objectType string) (*pem.Block, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode PEM %s", objectType)
	}
	return block, nil
}

func ParsePrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("private key must use PKCS#8, PKCS#1 RSA, or SEC1 EC encoding")
}

// DecryptPKCS8 turns an encrypted PKCS#8 DER blob into a plaintext PKCS#8 DER blob,
// so the rest of the import path never has to know the key arrived encrypted.
func DecryptPKCS8(der []byte, passphrase string) ([]byte, error) {
	key, err := pkcs8.ParsePKCS8PrivateKey(der, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

// EncryptPKCS8 encrypts a plaintext PKCS#8 DER blob. PBKDF2 + AES-256-CBC is chosen over
// scrypt so the output stays readable by openssl and older PKCS#8 consumers.
func EncryptPKCS8(der []byte, passphrase string) ([]byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	opts := &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       pkcs8SaltSize,
			IterationCount: pkcs8PBKDF2Iterations,
			HMACHash:       crypto.SHA256,
		},
	}
	return pkcs8.MarshalPrivateKey(key, []byte(passphrase), opts)
}

func DetectKeyAlgorithm(key any) (string, error) {
	switch key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		return "RSA", nil
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return "EC", nil
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}
