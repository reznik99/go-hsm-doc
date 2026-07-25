package cli

import (
	"maps"
	"slices"
	"testing"

	"github.com/miekg/pkcs11"
)

func equalGenerationOptions(a, b []keyGenerationOption) bool {
	return slices.EqualFunc(a, b, func(x, y keyGenerationOption) bool {
		return x.algorithm == y.algorithm && slices.Equal(x.parameters, y.parameters)
	})
}

func TestEligibleKeyGenerationOptions(t *testing.T) {
	tests := []struct {
		name       string
		mechanisms map[uint]pkcs11.MechanismInfo
		want       []keyGenerationOption
	}{
		{
			name: "filters sizes and curves to the supported range",
			mechanisms: map[uint]pkcs11.MechanismInfo{
				pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: {MinKeySize: 2048, MaxKeySize: 4096, Flags: pkcs11.CKF_GENERATE_KEY_PAIR},
				pkcs11.CKM_EC_KEY_PAIR_GEN:       {MinKeySize: 256, MaxKeySize: 384, Flags: pkcs11.CKF_GENERATE_KEY_PAIR | pkcs11.CKF_EC_NAMEDCURVE},
				pkcs11.CKM_AES_KEY_GEN:           {MinKeySize: 24, MaxKeySize: 32, Flags: pkcs11.CKF_GENERATE},
				pkcs11.CKM_DES2_KEY_GEN:          {Flags: pkcs11.CKF_GENERATE},
				pkcs11.CKM_DES3_KEY_GEN:          {Flags: pkcs11.CKF_GENERATE},
			},
			want: []keyGenerationOption{
				{algorithm: "RSA", parameters: []string{"2048", "4096"}},
				{algorithm: "EC", parameters: []string{"P256", "P384"}},
				{algorithm: "AES", parameters: []string{"192", "256"}},
				{algorithm: "3DES", parameters: []string{"128", "192"}},
			},
		},
		{
			name: "omits mechanisms without a generate flag",
			mechanisms: map[uint]pkcs11.MechanismInfo{
				pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: {Flags: pkcs11.CKF_SIGN},              // not a generate flag -> dropped
				pkcs11.CKM_EC_KEY_PAIR_GEN:       {Flags: pkcs11.CKF_GENERATE_KEY_PAIR}, // missing CKF_EC_NAMEDCURVE -> dropped
				pkcs11.CKM_AES_KEY_GEN:           {Flags: pkcs11.CKF_GENERATE},
				pkcs11.CKM_DES_KEY_GEN:           {Flags: pkcs11.CKF_GENERATE},
			},
			want: []keyGenerationOption{
				{algorithm: "AES", parameters: []string{"128", "192", "256"}},
				{algorithm: "DES", parameters: []string{"64"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := eligibleKeyGenerationOptions(slotCapabilities{mechanisms: test.mechanisms})
			if !equalGenerationOptions(got, test.want) {
				t.Fatalf("options = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestSupportedImportObjectTypes(t *testing.T) {
	rsaWrapping := map[uint]pkcs11.MechanismInfo{
		pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: {Flags: pkcs11.CKF_GENERATE_KEY_PAIR},
		pkcs11.CKM_RSA_PKCS_OAEP:         {Flags: pkcs11.CKF_UNWRAP},
	}
	allImportMechanisms := maps.Clone(rsaWrapping)
	allImportMechanisms[pkcs11.CKM_AES_KEY_WRAP_PAD] = pkcs11.MechanismInfo{Flags: pkcs11.CKF_UNWRAP}

	tests := []struct {
		name       string
		mechanisms map[uint]pkcs11.MechanismInfo
		want       []string
	}{
		{
			name: "create object only",
			want: []string{"Certificate", "PublicKey"},
		},
		{
			name:       "secret key unwrap",
			mechanisms: rsaWrapping,
			want:       []string{"Certificate", "PublicKey", "SecretKey"},
		},
		{
			name:       "private and secret key unwrap",
			mechanisms: allImportMechanisms,
			want:       []string{"Certificate", "PublicKey", "PrivateKey", "SecretKey"},
		},
		{
			name: "RSA 2048 wrapper unavailable",
			mechanisms: map[uint]pkcs11.MechanismInfo{
				pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: {MinKeySize: 3072, MaxKeySize: 4096, Flags: pkcs11.CKF_GENERATE_KEY_PAIR},
				pkcs11.CKM_RSA_PKCS_OAEP:         {Flags: pkcs11.CKF_UNWRAP},
				pkcs11.CKM_AES_KEY_WRAP_PAD:      {Flags: pkcs11.CKF_UNWRAP},
			},
			want: []string{"Certificate", "PublicKey"},
		},
		{
			name: "wrong mechanism flags",
			mechanisms: map[uint]pkcs11.MechanismInfo{
				pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: {Flags: pkcs11.CKF_GENERATE_KEY_PAIR},
				pkcs11.CKM_RSA_PKCS_OAEP:         {Flags: pkcs11.CKF_WRAP},
				pkcs11.CKM_AES_KEY_WRAP_PAD:      {Flags: pkcs11.CKF_UNWRAP},
			},
			want: []string{"Certificate", "PublicKey"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := supportedImportObjectTypes(slotCapabilities{mechanisms: test.mechanisms})
			if !slices.Equal(got, test.want) {
				t.Fatalf("object types = %v, want %v", got, test.want)
			}
		})
	}
}
