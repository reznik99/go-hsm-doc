package cli

import (
	"slices"
	"testing"
)

func TestSplitCommaSeparated(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{"empty", "", nil},
		{"one", "example.com", []string{"example.com"}},
		{"many", " example.com, api.example.com ,,", []string{"example.com", "api.example.com"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := splitCommaSeparated(c.value); !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseCountries(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"valid", "au, NZ", []string{"AU", "NZ"}, false},
		{"too-short", "A", nil, true},
		{"not-letters", "A1", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseCountries(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseEmailAddresses(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"multiple", "admin@example.com, security@example.com", []string{"admin@example.com", "security@example.com"}, false},
		{"display-name", "Admin <admin@example.com>", []string{"admin@example.com"}, false},
		{"invalid", "not-an-email", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseEmailAddresses(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseIPAddresses(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"ipv4-and-ipv6", "192.0.2.1, 2001:db8::1", []string{"192.0.2.1", "2001:db8::1"}, false},
		{"invalid", "example.com", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addresses, err := parseIPAddresses(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			got := make([]string, len(addresses))
			for i, address := range addresses {
				got[i] = address.String()
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseURIs(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"absolute", "spiffe://example/service, urn:example:device", []string{"spiffe://example/service", "urn:example:device"}, false},
		{"relative", "/relative/path", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addresses, err := parseURIs(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, c.wantErr)
			}
			got := make([]string, len(addresses))
			for i, address := range addresses {
				got[i] = address.String()
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
