package main

import "github.com/miekg/pkcs11"

func ClassToString(class []byte) string {
	switch class[0] {
	case pkcs11.CKK_RSA:
		return "RSA"
	case pkcs11.CKK_DSA:
		return "DSA"
	case pkcs11.CKK_DH:
		return "DH"
	case pkcs11.CKK_EC:
		return "EC"
	case pkcs11.CKK_AES:
		return "AES"
	case pkcs11.CKK_DES:
		return "DES"
	case pkcs11.CKK_DES2:
		return "DES2"
	case pkcs11.CKK_DES3:
		return "DES3"
	default:
		return "N/A"
	}
}
