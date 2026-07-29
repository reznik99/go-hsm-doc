package pkcs11util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

const (
	// 600k HMAC-SHA256 iterations is the OWASP Password Storage recommendation for PBKDF2.
	// It is a floor that should be raised over time as hardware improves.
	pkcs8PBKDF2Iterations = 600_000
	// 128 bits, the NIST SP 800-132 minimum salt length.
	pkcs8SaltSize = 16
)

var ErrPassphraseRequired = errors.New("private key requires a passphrase")

func DecodePEMOrDER(data []byte) ([]byte, string, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return data, "", nil
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errors.New("PEM contains trailing data")
	}
	return block.Bytes, block.Type, nil
}

func isEncryptedPKCS8(der []byte) bool {
	var key struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(der, &key)
	return err == nil && len(rest) == 0 && len(key.Algorithm.Algorithm) > 0 && len(key.Data) > 0
}

func ParsePublicKey(data []byte) (any, error) {
	der, _, err := DecodePEMOrDER(data)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		return key, nil
	}

	key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key as PKIX or OpenSSH: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("OpenSSH public key contains trailing data")
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported OpenSSH public key type %q", key.Type())
	}
	return cryptoKey.CryptoPublicKey(), nil
}

// ParsePrivateKey accepts PKCS#1 RSA, SEC1 EC, and PKCS#8 in PEM or DER.
// It also accepts PEM-encoded OpenSSH RSA or ECDSA keys and legacy encrypted RSA or EC PEM.
// The returned DER always uses unencrypted PKCS#8 encoding.
func ParsePrivateKey(data, passphrase []byte) (any, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil && len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("PEM contains trailing data")
	}

	var key any
	var err error
	if block != nil {
		key, err = parsePEMPrivateKey(data, block, passphrase)
	} else {
		key, err = parseDERPrivateKey(data, passphrase)
	}
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

func parsePEMPrivateKey(data []byte, block *pem.Block, passphrase []byte) (any, error) {
	if block.Type != "OPENSSH PRIVATE KEY" && block.Headers["Proc-Type"] != "4,ENCRYPTED" {
		return parseDERPrivateKey(block.Bytes, passphrase)
	}
	if passphrase != nil {
		return ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	}

	key, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, ErrPassphraseRequired
	}
	return key, err
}

func parseDERPrivateKey(der, passphrase []byte) (any, error) {
	if isEncryptedPKCS8(der) {
		if passphrase == nil {
			return nil, ErrPassphraseRequired
		}
		return pkcs8.ParsePKCS8PrivateKey(der, passphrase)
	}
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
