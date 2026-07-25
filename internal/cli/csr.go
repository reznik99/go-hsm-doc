package cli

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/pkcs11util"
)

// generateCSR builds a PKCS#10 CSR for the selected private key — signed on the token
// so the key never leaves it — and prints the PEM (matching how export works).
func (a *App) generateCSR(slotID uint, sh pkcs11.SessionHandle, privateKey pkcs11.ObjectHandle) error {
	public, err := a.publicKeyFor(slotID, sh, privateKey)
	if err != nil {
		return err
	}

	subject, email, err := a.promptSubject()
	if err != nil {
		return err
	}

	template := &x509.CertificateRequest{Subject: subject}
	if email != "" {
		template.EmailAddresses = []string{email}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, a.mod.NewSigner(sh, privateKey, public))
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	fmt.Printf("%s\n", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	return nil
}

// publicKeyFor finds and parses the public key that shares the private key's CKA_ID.
func (a *App) publicKeyFor(slotID uint, sh pkcs11.SessionHandle, privateKey pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	attrs, err := a.mod.Ctx.GetAttributeValue(sh, privateKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, err
	}
	id := attrs[0].Value
	if len(id) == 0 {
		return nil, errors.New("private key has no CKA_ID; cannot find its public key")
	}
	keyType, err := pkcs11util.AttributeToUint(attrs[1])
	if err != nil {
		return nil, err
	}

	publicKeys, err := a.mod.FindObjects(slotID, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return nil, err
	}
	if len(publicKeys) == 0 {
		return nil, errors.New("no public key with a matching CKA_ID in this slot")
	}

	pemBytes, err := a.mod.ExportPublicKey(sh, publicKeys[0], keyType)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode exported public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func (a *App) promptSubject() (pkix.Name, string, error) {
	commonName, err := a.interactiveText.Show("Common Name (CN)")
	if err != nil {
		return pkix.Name{}, "", err
	}
	if commonName == "" {
		return pkix.Name{}, "", errors.New("common name is required")
	}

	organization, err := a.interactiveText.Show("Organization (O, optional)")
	if err != nil {
		return pkix.Name{}, "", err
	}
	organizationalUnit, err := a.interactiveText.Show("Organizational Unit (OU, optional)")
	if err != nil {
		return pkix.Name{}, "", err
	}
	country, err := a.interactiveText.Show("Country (C, 2-letter, optional)")
	if err != nil {
		return pkix.Name{}, "", err
	}
	email, err := a.interactiveText.Show("Email (optional, added as SAN)")
	if err != nil {
		return pkix.Name{}, "", err
	}

	subject := pkix.Name{CommonName: commonName}
	if organization != "" {
		subject.Organization = []string{organization}
	}
	if organizationalUnit != "" {
		subject.OrganizationalUnit = []string{organizationalUnit}
	}
	if country != "" {
		subject.Country = []string{country}
	}
	return subject, email, nil
}
