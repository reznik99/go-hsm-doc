package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func parsePEMBlock(raw, objectType string) (*pem.Block, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode PEM %s", objectType)
	}
	return block, nil
}

func parsePrivateKey(der []byte) (any, error) {
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

func detectKeyAlgorithm(key any) (string, error) {
	switch key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		return "RSA", nil
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return "EC", nil
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}
