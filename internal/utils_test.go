package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestStringToAttribute(t *testing.T) {
	cases := []struct {
		algo    string
		want    uint
		wantErr bool
	}{
		{"RSA", pkcs11.CKK_RSA, false},
		{"rsa", pkcs11.CKK_RSA, false},
		{"EC", pkcs11.CKK_EC, false},
		{"ECDSA", pkcs11.CKK_EC, false},
		{"AES", pkcs11.CKK_AES, false},
		{"DES", pkcs11.CKK_DES, false},
		{"2DES", pkcs11.CKK_DES2, false},
		{"3DES", pkcs11.CKK_DES3, false},
		{"nonsense", 0, true},
	}
	for _, c := range cases {
		t.Run(c.algo, func(t *testing.T) {
			attr, err := StringToAttribute(c.algo)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", c.algo)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if attr.Type != pkcs11.CKA_KEY_TYPE {
				t.Errorf("type = %d, want CKA_KEY_TYPE", attr.Type)
			}
		})
	}
}

func TestCurveNameToCurve(t *testing.T) {
	cases := []struct {
		name    string
		want    elliptic.Curve
		wantErr bool
	}{
		{"p224", elliptic.P224(), false},
		{"P-224", elliptic.P224(), false},
		{"p256", elliptic.P256(), false},
		{"p384", elliptic.P384(), false},
		{"p521", elliptic.P521(), false},
		{"p999", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			curve, err := CurveNameToCurve(c.name)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", c.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if curve != c.want {
				t.Errorf("curve = %v, want %v", curve, c.want)
			}
		})
	}
}

func TestOidCurveNameRoundTrip(t *testing.T) {
	for _, name := range []string{"p224", "p256", "p384", "p521"} {
		t.Run(name, func(t *testing.T) {
			oid, err := CurveNameToOid(name)
			if err != nil {
				t.Fatalf("CurveNameToOid: %v", err)
			}
			got, err := OidToCurveName(oid)
			if err != nil {
				t.Fatalf("OidToCurveName: %v", err)
			}
			if got != name {
				t.Errorf("round trip = %q, want %q", got, name)
			}
		})
	}
}

// TestECParamsRoundTrip guards the ASN.1 OID encoding that CKA_EC_PARAMS relies on.
func TestECParamsRoundTrip(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{
		"p224": elliptic.P224(),
		"p256": elliptic.P256(),
		"p384": elliptic.P384(),
		"p521": elliptic.P521(),
	} {
		t.Run(name, func(t *testing.T) {
			params, err := CurveNameToECParams(name)
			if err != nil {
				t.Fatalf("CurveNameToECParams: %v", err)
			}
			got, err := ECParamsToCurve(params)
			if err != nil {
				t.Fatalf("ECParamsToCurve: %v", err)
			}
			if got != curve {
				t.Errorf("round trip curve = %v, want %v", got, curve)
			}
		})
	}
}

func TestAttributeToString(t *testing.T) {
	cases := []struct {
		name string
		attr *pkcs11.Attribute
		want string
	}{
		{"class-public", pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY), "PUBLIC_KEY"},
		{"class-secret", pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), "SECRET_KEY"},
		{"keytype-rsa", pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA), "RSA"},
		{"keytype-ec", pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC), "EC"},
		{"label", pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mykey"), `"mykey"`},
		{"unhandled", pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{0x01}), "N/A"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := AttributeToString(c.attr); got != c.want {
				t.Errorf("AttributeToString = %q, want %q", got, c.want)
			}
		})
	}
}

// TestECPointRoundTrip covers the OCTET STRING wrap/unwrap symmetry between import and export.
func TestECPointRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			ecPoint, err := MarshalECPoint(&key.PublicKey)
			if err != nil {
				t.Fatalf("MarshalECPoint: %v", err)
			}

			x, y, err := ParseECPoint(curve, ecPoint)
			if err != nil {
				t.Fatalf("ParseECPoint: %v", err)
			}
			if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
				t.Errorf("coordinates did not round trip")
			}
		})
	}
}

// TestParseECPointRawFallback ensures a raw (non-OCTET-STRING-wrapped) point still parses, as some HSMs return it.
func TestParseECPointRawFallback(t *testing.T) {
	curve := elliptic.P256()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := elliptic.Marshal(curve, key.X, key.Y) //nolint:staticcheck // exercising the raw-point path

	x, y, err := ParseECPoint(curve, raw)
	if err != nil {
		t.Fatalf("ParseECPoint (raw): %v", err)
	}
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		t.Errorf("coordinates did not match for raw point")
	}
}

func TestParseECPointInvalid(t *testing.T) {
	if _, _, err := ParseECPoint(elliptic.P256(), []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error for garbage EC point, got nil")
	}
}
