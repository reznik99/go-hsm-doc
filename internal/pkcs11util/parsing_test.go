package pkcs11util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Test-only fixtures generated with OpenSSL 3.5.7. The encrypted key uses "test-passphrase".
const (
	//nolint:gosec // Public test-only private key generated for interoperability tests.
	opensslRSAPKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChTyZVtHQKGenv
6D7GnLHSOiUpDndw0p5P6duR5/tv7gGaKSA/rfR8wJaAaZTP105LEgmIZ09hCjjN
qCJrj17wVFoj8TWhyvCCM06T88VJfd1hDt0xbug511niFSpRXz1PW2f+cH1rkBFN
ROQu8eSCGjYdMREnj2aHEWtUcEmjzX0eMsYj7F/hSx3qc6by998tspnxEmEhLm1F
qFv+liK7L6KoSiQ4Y4t2+yZFitL24tpU8H5DmLTsEDV97KUD+4DupDyZRcGyFdiI
Qdb5Ogdb7UMuCpLjQqG7b0Ysvl81YTqdHZarlQf4estQJArZCqFuFq0po2ZdrYc5
jQ5z6MUPAgMBAAECggEAF85ekfd3yKXaaJWV7inh9GywX0bLSdNLme+hf/8ElJhD
lETNhZhepKqni3wJgkL8Qwf+cCsPA/tGNtPBgK5ADKfmRberep1AsXZw+lTXoOj6
awCOlGUR0Ld/hGYrQKcVnUiYKGzhlaZFZ2nrYyI/3xOPOO+s4HHBZ92iQWvw8kN9
AV4taui2TwyIsvWaYzR+7MVlo+CfNxmcejUG9+Xo149j7vMpnIwFwgc+ViHLo6WB
OnIulvdpW2nez8CT1W2t0l8+gjGlsPvuapO+DvjX4skNC5H90qStUiV4fmhvdhS6
BwovcL0RREeDQvQD9a4xbSn5VjQFjJwQh4BvI7PHgQKBgQDjHWHUvirN7Y5gttxq
pEKVZgZvXMmyyaaxl/iGsdiVSHqMKvTXGIC82IbXrlQo3X5QwJ02pjiHPSV8RoOY
NqI95eGhtzvhGfm3c2h/4zx16WC2b5C7lTeR5MOUnKYMFLhNYBvHsleBiNhx60p6
hsmJfjAF/AxNne6lRpT3BbafdwKBgQC10zTrOmXaKd5pyY0kW92s19zNzRPf5c0X
Q1nVYZL43rD446FNjkSSiO+Id3LA0tntUA2WkLlQi+S8WYR7Ys0AHxIyqo6lBiyp
ReqvvD1VbXE9N56l2HVb4uDFk3VWV9CFK/S4c4KAQoMF5qs4ZvLFerdDBJThQUp/
mtuKuN1dKQKBgAJ7M7JrUXRmgAO2e7n+iWuwbamRzfJSGawfCOwPzVn0LMKTRZGE
BwQJKY/5q5m2scaYFB+guUVg+aPd8VocXrFmbYyiv9i5u+yxKhcbmHGBVzknBuHF
w5GoeiqJe5buMwVFY4hO/n2/zP2RoIKuLk1+P3ARTOEcNJtBpib8vP4JAoGASyFi
lHAk9einBn9J2uQ6zNjFXCSJOdLy09H4pLsUx9D8v1sPo8RNgV8j2vfAavy1H+Ic
O0LB0A5+DXXP0Ewa+RndoyHmnznV6nwBZWway9nVGL6Kx2yR0c4Fop4zteHDP8PR
8wWHvwe8rAuMZFnlpsP2RbL28bzQ07lhTgjlL0ECgYEA0mZB60DhNHEbNBTmRLW9
wbqiGQQW9Wl5D2WPOd+AuuNakGGxY3fkZhuApStpaHMjW2T9Z7XeoSqdA+ekr4/4
Y2mRWZYVLEgyuQE4qjid4zTqv07hg6dVlZidgQKcl8ndihvN/wMXXlxurZIwjmGN
U6UiCyI8dg+RfYBXMzdZpwU=
-----END PRIVATE KEY-----`

	//nolint:gosec // Public test-only private key generated for interoperability tests.
	opensslRSAPKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoU8mVbR0Chnp7+g+xpyx0jolKQ53cNKeT+nbkef7b+4Bmikg
P630fMCWgGmUz9dOSxIJiGdPYQo4zagia49e8FRaI/E1ocrwgjNOk/PFSX3dYQ7d
MW7oOddZ4hUqUV89T1tn/nB9a5ARTUTkLvHkgho2HTERJ49mhxFrVHBJo819HjLG
I+xf4Usd6nOm8vffLbKZ8RJhIS5tRahb/pYiuy+iqEokOGOLdvsmRYrS9uLaVPB+
Q5i07BA1feylA/uA7qQ8mUXBshXYiEHW+ToHW+1DLgqS40Khu29GLL5fNWE6nR2W
q5UH+HrLUCQK2QqhbhatKaNmXa2HOY0Oc+jFDwIDAQABAoIBABfOXpH3d8il2miV
le4p4fRssF9Gy0nTS5nvoX//BJSYQ5REzYWYXqSqp4t8CYJC/EMH/nArDwP7RjbT
wYCuQAyn5kW3q3qdQLF2cPpU16Do+msAjpRlEdC3f4RmK0CnFZ1ImChs4ZWmRWdp
62MiP98TjzjvrOBxwWfdokFr8PJDfQFeLWrotk8MiLL1mmM0fuzFZaPgnzcZnHo1
Bvfl6NePY+7zKZyMBcIHPlYhy6OlgTpyLpb3aVtp3s/Ak9VtrdJfPoIxpbD77mqT
vg741+LJDQuR/dKkrVIleH5ob3YUugcKL3C9EURHg0L0A/WuMW0p+VY0BYycEIeA
byOzx4ECgYEA4x1h1L4qze2OYLbcaqRClWYGb1zJssmmsZf4hrHYlUh6jCr01xiA
vNiG165UKN1+UMCdNqY4hz0lfEaDmDaiPeXhobc74Rn5t3Nof+M8delgtm+Qu5U3
keTDlJymDBS4TWAbx7JXgYjYcetKeobJiX4wBfwMTZ3upUaU9wW2n3cCgYEAtdM0
6zpl2ineacmNJFvdrNfczc0T3+XNF0NZ1WGS+N6w+OOhTY5EkojviHdywNLZ7VAN
lpC5UIvkvFmEe2LNAB8SMqqOpQYsqUXqr7w9VW1xPTeepdh1W+LgxZN1VlfQhSv0
uHOCgEKDBearOGbyxXq3QwSU4UFKf5rbirjdXSkCgYACezOya1F0ZoADtnu5/olr
sG2pkc3yUhmsHwjsD81Z9CzCk0WRhAcECSmP+auZtrHGmBQfoLlFYPmj3fFaHF6x
Zm2Mor/YubvssSoXG5hxgVc5JwbhxcORqHoqiXuW7jMFRWOITv59v8z9kaCCri5N
fj9wEUzhHDSbQaYm/Lz+CQKBgEshYpRwJPXopwZ/SdrkOszYxVwkiTnS8tPR+KS7
FMfQ/L9bD6PETYFfI9r3wGr8tR/iHDtCwdAOfg11z9BMGvkZ3aMh5p851ep8AWVs
GsvZ1Ri+isdskdHOBaKeM7Xhwz/D0fMFh78HvKwLjGRZ5abD9kWy9vG80NO5YU4I
5S9BAoGBANJmQetA4TRxGzQU5kS1vcG6ohkEFvVpeQ9ljznfgLrjWpBhsWN35GYb
gKUraWhzI1tk/We13qEqnQPnpK+P+GNpkVmWFSxIMrkBOKo4neM06r9O4YOnVZWY
nYECnJfJ3Yobzf8DF15cbq2SMI5hjVOlIgsiPHYPkX2AVzM3WacF
-----END RSA PRIVATE KEY-----`

	//nolint:gosec // Public test-only encrypted private key with a documented passphrase.
	opensslEncryptedRSAPKCS8 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQfV4sa8GVrecG6RqH
8gf1HwICJxAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEF21z0vWNPBFJkRQ
9h8c+bsEggTQC7oSjRKBBYQ1+UD0uDjaKcjI20pYwwDwTbW6sFNf3oeiRpENh2Yy
Z4goLOqp666lcmTyqY0DBcFGwAlNxaif0nXdkqca+kXSUEibffuarhB1m38rrg8X
2zy3xktepHC6dyLc83FHNm01BdKVLCzeeZ0jdajKluC0zH9fClguJz6OWq4X5kvH
3zyLEHQ8AJYXIfDSyPU6YM9M/KzlXsdWrzMX7oFudPWOCAT/IgUz3M/ipjEpgCuf
KsVrivRN0VF1Mfoeg9gZZteUFab1MYtSLFDDC9A7ywiv0ANILjBXik0PnkZgorbz
4ciFiH4BlvUMSePQuNUv/q6LF+XIjGiD9jAlY7cGFSR2q90jj7Qy3PhQ0XUh4AJk
Z1DIdU6cxzlgfCnlpMmvAdyJprCZBVrBhTpIjL8E16tR7amWKCANepoH72twyG5w
hARcihRiVlaqG2E9rUaXg6kVDeTHdMwHIoMCnTbG0ggFde4NvddVBGF57ZRBzhyg
WJOq7nLnfbCrngSTcljvVEqrbaw86EwwXitj/VPWFpdCLCwQJVlh5larg5/vAE4F
mgyGnuRsTCAnzuphZKTazdEvrJp7k1/o/ww5QYnmegYxlHpPaZ9b+YXIOqimdvmD
68s4xC4H1N0TjzbjKr9Qywkq0F2aUeThXMjBxixol7r6ths7FEeqxE74ktVCr6ng
OCyje8EYXguRMfrQHaNXHFz5tPWOOo2C4K3jgPyTaHUp48jClfr/KlJ1m+NNgTHM
WcyCte82WQrHZP56H2YE627yR4CZVNS8E0JV5qTiWf9F47zC/2bV1zIf9+tbJiQW
YX1NT1sAjOGf7qv17JgDn8ywwNitkKpNvC757dzlTgF5VUAlE7dcCsNcJeItW2Jd
V2BBx+ay//fQnGhfy6aG5+Q4Jfok3a+mZ57Z1Uba7G5xHe/pbfJwQyTTbKLALdXF
YUsFmZa0zCbt3rvKn17XOwD4tPFHHMAI9YOZ5LVZtmxDjC2k4E+dhj40SlsG7L+K
S1qgXqdjQ9ftbT8OFlnB7JDaLb1vGbjpRzJ2bcIhBXkaZlXHuc/hI8JWWN1rVGBE
vEkoWVQr2Yx+33UF6pThSDU2THXc+v5aE3eXkVk6VKvRYk1TusmaO+ogDTB0Hs0s
qNcpB2mqOTbgU9FfcSVvySrGqMH86rV/TB1zKXTXuEuUBpR/nIxIidSDaBJoOHqz
pDSOtCLHEGRo3FG9EgubFDJTpw59Lvwka09UEA6FmaPJ4cnlylh8YeCeeAZL4TIR
JteduyKwQpoaQCj2B7KCYY9SrlqoKU+7Xy4p6bIklxYTJIxv/MA2xDV2qSKc12fa
RTXNwalxwcJj2VhnoXb3PslfvEZm/gIa84zeqpShV8gz24m8a8XogNSx7r6s/vp2
SkpPob2hq+62hW5y0HOkowQ8ZSvRyc52TgFkqU9OK23+Bx8/5sNxwu4LwG+Txkdy
Ee/Vf6PGkZvqW+YIqmJx2f2xu/E5g+vsYU+fHA3X7VFtTj+yLDPzOXBY+Rd8ns+h
zpa/WWgAZRG0Dfkv80807yH/W3snztToX39otwLwPIOnzkNlOrf9rEs0AON+KPML
EToGoucxhfMiFiyEaX4oOG/tItmQtwIHG6BUfBop2Pd5K7Mp8822ZEw=
-----END ENCRYPTED PRIVATE KEY-----`

	//nolint:gosec // Public test-only private key generated for interoperability tests.
	opensslECSEC1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAsAhr6UfH/tBLWIPOT9lYIeRk4IvwzKvItlKNWq63eboAoGCCqGSM49
AwEHoUQDQgAErMuPQpKGY0JhqJoKn0JnPMXy7gTybbt0sRoZekUPCMLLarOPk9+i
Vt1ZMBsMg8xeaDjGXf1ErgCFYEKwMhRyJw==
-----END EC PRIVATE KEY-----`
)

func decodeTestPEM(t *testing.T, value string) []byte {
	t.Helper()
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid test PEM")
	}
	return block.Bytes
}

func TestParsePEMBlock(t *testing.T) {
	valid := string(pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: []byte{1, 2, 3}}))
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", valid, false},
		{"garbage", "not a pem block", true},
		{"trailing-bytes", valid + "trailing bytes", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePEMBlock(c.value, "test")
			if (err != nil) != c.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, c.wantErr)
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
		der     []byte
		wantErr bool
	}{
		{"go-pkcs8-rsa", pkcs8, false},
		{"go-pkcs1-rsa", x509.MarshalPKCS1PrivateKey(rsaKey), false},
		{"go-sec1-ec", sec1, false},
		{"openssl-pkcs8-rsa", decodeTestPEM(t, opensslRSAPKCS8), false},
		{"openssl-pkcs1-rsa", decodeTestPEM(t, opensslRSAPKCS1), false},
		{"openssl-sec1-ec", decodeTestPEM(t, opensslECSEC1), false},
		{"garbage", []byte{1, 2, 3}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePrivateKey(c.der)
			if (err != nil) != c.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, c.wantErr)
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
