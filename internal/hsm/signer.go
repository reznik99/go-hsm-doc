package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

// Signer implements crypto.Signer for a private key that never leaves the token —
// the signature is produced by C_Sign. The session must be logged in for the key.
type Signer struct {
	ctx        Cryptoki
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	public     crypto.PublicKey
}

// NewSigner wraps an on-token private key (with its already-parsed public key) as a
// crypto.Signer, suitable for x509.CreateCertificateRequest and friends.
func (p *P11) NewSigner(sh pkcs11.SessionHandle, privateKey pkcs11.ObjectHandle, public crypto.PublicKey) *Signer {
	return &Signer{ctx: p.Ctx, session: sh, privateKey: privateKey, public: public}
}

func (s *Signer) Public() crypto.PublicKey { return s.public }

// digestInfo is the PKCS#1 v1.5 DigestInfo that CKM_RSA_PKCS signs.
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// ecdsaSignature is the ASN.1 SEQUENCE { r, s } that crypto.Signer returns for ECDSA.
type ecdsaSignature struct {
	R, S *big.Int
}

// hashOIDs maps a hash to its ASN.1 OID, for the PKCS#1 v1.5 DigestInfo.
var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
	crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
	crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
}

func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.public.(type) {
	case *rsa.PublicKey:
		return s.signRSA(digest, opts.HashFunc())
	case *ecdsa.PublicKey:
		return s.signECDSA(digest)
	default:
		return nil, fmt.Errorf("unsupported key type %T", s.public)
	}
}

func (s *Signer) signRSA(digest []byte, hash crypto.Hash) ([]byte, error) {
	oid, ok := hashOIDs[hash]
	if !ok {
		return nil, fmt.Errorf("unsupported hash %v for RSA signing", hash)
	}
	// PKCS#1 v1.5 signs the DER DigestInfo; CKM_RSA_PKCS does the padding + RSA.
	encoded, err := asn1.Marshal(digestInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue},
		Digest:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("encode DigestInfo: %w", err)
	}
	return s.sign([]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, encoded)
}

func (s *Signer) signECDSA(digest []byte) ([]byte, error) {
	// CKM_ECDSA signs the digest directly and returns raw r||s.
	raw, err := s.sign([]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, digest)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d", len(raw))
	}
	half := len(raw) / 2
	// crypto.Signer expects the ASN.1 SEQUENCE { r, s } encoding.
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}

func (s *Signer) sign(mechanism []*pkcs11.Mechanism, data []byte) ([]byte, error) {
	if err := s.ctx.SignInit(s.session, mechanism, s.privateKey); err != nil {
		return nil, fmt.Errorf("sign init: %w", err)
	}
	signature, err := s.ctx.Sign(s.session, data)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return signature, nil
}
