package internal

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"fmt"

	"github.com/miekg/pkcs11"
)

// ImportPublicKey imports a public key into the hsm without wrapping
func (p *P11) ImportPublicKey(sh pkcs11.SessionHandle, pub any, keyLabel string, extractable, ephemeral bool) (pkcs11.ObjectHandle, error) {
	switch publicKey := pub.(type) {
	case rsa.PublicKey:
		// Allow for 128-bit integer for future-proofing
		exponent := make([]byte, 8)
		binary.BigEndian.PutUint64(exponent, uint64(publicKey.E))
		wrapkeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, publicKey.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		}
		return p.Ctx.CreateObject(sh, wrapkeyTemplate)
	case ecdsa.PublicKey:
		return 0, fmt.Errorf("ec public key import unimplemented")
	default:
		return 0, fmt.Errorf("unrecognized key type: %T", publicKey)
	}
}
