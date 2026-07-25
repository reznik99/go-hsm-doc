package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestIsElevatedAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"non-pkcs11", errors.New("boom"), false},
		{"not-logged-in", pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN), true},
		{"action-prohibited", pkcs11.Error(pkcs11.CKR_ACTION_PROHIBITED), true},
		{"wrapped-read-only", fmt.Errorf("write: %w", pkcs11.Error(pkcs11.CKR_SESSION_READ_ONLY)), true},
		{"other-pkcs11", pkcs11.Error(pkcs11.CKR_DEVICE_ERROR), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isElevatedAuthError(c.err); got != c.want {
				t.Errorf("isElevatedAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
