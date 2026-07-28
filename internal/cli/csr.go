package cli

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/miekg/pkcs11"
)

var countryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)

// generateCSR builds a PKCS#10 CSR for the selected private key — signed on the token
// so the key never leaves it — and prints the PEM (matching how export works).
func (a *App) generateCSR(slotID uint, sh pkcs11.SessionHandle, privateKey pkcs11.ObjectHandle) error {
	public, err := a.publicKeyFor(slotID, sh, privateKey)
	if err != nil {
		return err
	}

	template, err := a.promptCSR()
	if err != nil {
		return err
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, a.mod.NewSigner(sh, privateKey, public))
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("parse generated CSR: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return fmt.Errorf("verify generated CSR: %w", err)
	}
	return a.writeOutput("request.csr.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// publicKeyFor finds and parses the public key that shares the private key's CKA_ID.
func (a *App) publicKeyFor(slotID uint, sh pkcs11.SessionHandle, privateKey pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	attrs, err := a.mod.Ctx.GetAttributeValue(sh, privateKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, err
	}
	id := attrs[0].Value
	if len(id) == 0 {
		return nil, errors.New("private key has no CKA_ID; cannot find its public key")
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

	pemBytes, err := a.mod.ExportPublicKey(sh, publicKeys[0])
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode exported public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func (a *App) promptCSR() (*x509.CertificateRequest, error) {
	commonName, err := a.interactiveText.Show("Common Name (CN)")
	if err != nil {
		return nil, err
	}
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return nil, errors.New("common name is required")
	}

	organization, err := a.interactiveText.Show("Organization (O, comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	organizationalUnit, err := a.interactiveText.Show("Organizational Unit (OU, comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	country, err := a.interactiveText.Show("Country codes (C, comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	countries, err := parseCountries(country)
	if err != nil {
		return nil, err
	}
	province, err := a.interactiveText.Show("State or Province (ST, comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	locality, err := a.interactiveText.Show("Locality (L, comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	streetAddress, err := a.interactiveText.Show("Street Address (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	postalCode, err := a.interactiveText.Show("Postal Code (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	serialNumber, err := a.interactiveText.Show("Subject Serial Number (optional)")
	if err != nil {
		return nil, err
	}
	dnsNames, err := a.interactiveText.Show("DNS SANs (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	ipValues, err := a.interactiveText.Show("IP SANs (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	ipAddresses, err := parseIPAddresses(ipValues)
	if err != nil {
		return nil, err
	}
	emailAddresses, err := a.interactiveText.Show("Email SANs (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	emails, err := parseEmailAddresses(emailAddresses)
	if err != nil {
		return nil, err
	}
	uriValues, err := a.interactiveText.Show("URI SANs (comma-separated, optional)")
	if err != nil {
		return nil, err
	}
	uriAddresses, err := parseURIs(uriValues)
	if err != nil {
		return nil, err
	}

	return &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       splitCommaSeparated(organization),
			OrganizationalUnit: splitCommaSeparated(organizationalUnit),
			Country:            countries,
			Province:           splitCommaSeparated(province),
			Locality:           splitCommaSeparated(locality),
			StreetAddress:      splitCommaSeparated(streetAddress),
			PostalCode:         splitCommaSeparated(postalCode),
			SerialNumber:       strings.TrimSpace(serialNumber),
		},
		DNSNames:       splitCommaSeparated(dnsNames),
		IPAddresses:    ipAddresses,
		EmailAddresses: emails,
		URIs:           uriAddresses,
	}, nil
}

func splitCommaSeparated(value string) []string {
	var values []string
	for part := range strings.SplitSeq(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

func parseCountries(value string) ([]string, error) {
	countries := splitCommaSeparated(value)
	for i, country := range countries {
		if !countryPattern.MatchString(country) {
			return nil, fmt.Errorf("country %q must contain two letters", countries[i])
		}
		countries[i] = strings.ToUpper(country)
	}
	return countries, nil
}

func parseEmailAddresses(value string) ([]string, error) {
	values := splitCommaSeparated(value)
	addresses := make([]string, 0, len(values))
	for _, value := range values {
		address, err := mail.ParseAddress(value)
		if err != nil {
			return nil, fmt.Errorf("invalid email SAN %q: %w", value, err)
		}
		addresses = append(addresses, address.Address)
	}
	return addresses, nil
}

func parseIPAddresses(value string) ([]net.IP, error) {
	values := splitCommaSeparated(value)
	addresses := make([]net.IP, 0, len(values))
	for _, value := range values {
		address := net.ParseIP(value)
		if address == nil {
			return nil, fmt.Errorf("invalid IP SAN %q", value)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func parseURIs(value string) ([]*url.URL, error) {
	values := splitCommaSeparated(value)
	addresses := make([]*url.URL, 0, len(values))
	for _, value := range values {
		address, err := url.Parse(value)
		if err != nil || !address.IsAbs() {
			return nil, fmt.Errorf("invalid URI SAN %q", value)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}
