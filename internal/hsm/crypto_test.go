package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/reznik99/go-hsm-doc/internal/hsm/mocks"
	"github.com/stretchr/testify/mock"
)

const testSession = pkcs11.SessionHandle(7)

var errToken = errors.New("token failure")

// attrValue returns the value of the first attribute of the given type, failing the test if absent.
func attrValue(t *testing.T, template []*pkcs11.Attribute, typ uint) []byte {
	t.Helper()
	for _, a := range template {
		if a.Type == typ {
			return a.Value
		}
	}
	t.Fatalf("attribute 0x%X not found in template", typ)
	return nil
}

func generateTestRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return key
}

func generateTestECC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	return key
}

func TestFindObjectsPaginates(t *testing.T) {
	template := []*pkcs11.Attribute{}
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().FindObjectsInit(testSession, template).Return(nil)
	ctx.EXPECT().FindObjects(testSession, 100).Return([]pkcs11.ObjectHandle{1, 2}, false, nil).Once()
	ctx.EXPECT().FindObjects(testSession, 100).Return([]pkcs11.ObjectHandle{3}, false, nil).Once()
	ctx.EXPECT().FindObjects(testSession, 100).Return(nil, false, nil).Once() // empty batch -> stop
	ctx.EXPECT().FindObjectsFinal(testSession).Return(nil)

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{0: testSession}}
	got, err := p11.FindObjects(0, template)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(got, []pkcs11.ObjectHandle{1, 2, 3}) {
		t.Errorf("objects = %v, want [1 2 3]", got)
	}
}

func TestFindObjectsNoSession(t *testing.T) {
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t), Sessions: map[uint]pkcs11.SessionHandle{}}
	if _, err := p11.FindObjects(0, nil); err == nil {
		t.Fatal("expected error when slot has no open session, got nil")
	}
}

func TestOpenSessionReturnsCached(t *testing.T) {
	// No expectations, so any call to the token fails the test.
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t), Sessions: map[uint]pkcs11.SessionHandle{3: 42}}
	sh, err := p11.OpenSession(3)
	if err != nil || sh != 42 {
		t.Fatalf("OpenSession = (%d, %v), want (42, nil)", sh, err)
	}
}

func TestOpenSessionOpensAndCaches(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().
		OpenSession(uint(3), uint(pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)).
		Return(pkcs11.SessionHandle(99), nil)

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{}}
	sh, err := p11.OpenSession(3)
	if err != nil || sh != 99 {
		t.Fatalf("OpenSession = (%d, %v), want (99, nil)", sh, err)
	}
	if p11.Sessions[3] != 99 {
		t.Errorf("session not cached: %v", p11.Sessions)
	}
}

func TestGetSlotsIncludesUnlabeledAndJoinsErrors(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetSlotList(true).Return([]uint{0, 1, 2}, nil)
	ctx.EXPECT().GetTokenInfo(uint(0)).Return(pkcs11.TokenInfo{Label: "token-0"}, nil)
	ctx.EXPECT().GetTokenInfo(uint(1)).Return(pkcs11.TokenInfo{Label: ""}, nil)
	ctx.EXPECT().GetTokenInfo(uint(2)).Return(pkcs11.TokenInfo{}, errToken)

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{}}
	slots, err := p11.GetSlots(true)
	if err == nil {
		t.Error("expected joined error from the failing slot, got nil")
	}
	if len(slots) != 2 || slots[0].ID != 0 || slots[0].Token.Label != "token-0" || slots[1].ID != 1 || slots[1].Token.Label != "" {
		t.Errorf("slots = %v, want labeled slot 0 and unlabeled slot 1", slots)
	}
}

func TestGetSlotsIncludesSlotsWithoutTokens(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetSlotList(false).Return([]uint{0, 1}, nil)
	ctx.EXPECT().GetTokenInfo(uint(0)).Return(pkcs11.TokenInfo{Label: "token-0"}, nil)
	ctx.EXPECT().GetTokenInfo(uint(1)).Return(pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_TOKEN_NOT_PRESENT))

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{}}
	slots, err := p11.GetSlots(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(slots) != 2 || slots[0].ID != 0 || slots[0].Token.Label != "token-0" || slots[1].ID != 1 || slots[1].Token.Label != "" {
		t.Errorf("slots = %v, want token slot 0 and empty slot 1", slots)
	}
}

func TestCloseAllSessionsClosesAllAndClears(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().CloseSession(pkcs11.SessionHandle(10)).Return(nil)
	ctx.EXPECT().CloseSession(pkcs11.SessionHandle(11)).Return(errToken)

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{0: 10, 1: 11}}
	if err := p11.CloseAllSessions(); err == nil {
		t.Error("expected joined error from the failing close, got nil")
	}
	if len(p11.Sessions) != 0 {
		t.Errorf("sessions not cleared: %v", p11.Sessions)
	}
}

func TestGetMechanismsSkipsFailedInfo(t *testing.T) {
	rsa := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
	aes := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().GetMechanismList(uint(0)).Return([]*pkcs11.Mechanism{rsa, aes}, nil)
	ctx.EXPECT().GetMechanismInfo(uint(0), mock.MatchedBy(func(m []*pkcs11.Mechanism) bool {
		return len(m) == 1 && m[0].Mechanism == pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
	})).Return(pkcs11.MechanismInfo{MinKeySize: 2048, MaxKeySize: 4096}, nil)
	ctx.EXPECT().GetMechanismInfo(uint(0), mock.MatchedBy(func(m []*pkcs11.Mechanism) bool {
		return len(m) == 1 && m[0].Mechanism == pkcs11.CKM_AES_KEY_GEN
	})).Return(pkcs11.MechanismInfo{}, errToken)

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{}}
	mechs, err := p11.GetMechanisms(0)
	if err == nil {
		t.Error("expected joined error from the failing GetMechanismInfo, got nil")
	}
	if _, ok := mechs[pkcs11.CKM_AES_KEY_GEN]; ok {
		t.Error("failed mechanism should be omitted from the map")
	}
	if info := mechs[pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN]; info.MinKeySize != 2048 {
		t.Errorf("RSA mechanism info = %+v, want MinKeySize 2048", info)
	}
}

func TestLoginAlreadyLoggedInIsSuccess(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().Login(testSession, uint(pkcs11.CKU_USER), "pin").
		Return(pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN))

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{0: testSession}}
	if err := p11.Login(0, pkcs11.CKU_USER, "pin"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginReLogsInOnOtherUserType(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().Login(testSession, uint(pkcs11.CKU_SO), "key").
		Return(pkcs11.Error(pkcs11.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)).Once()
	ctx.EXPECT().Logout(testSession).Return(nil).Once()
	ctx.EXPECT().Login(testSession, uint(pkcs11.CKU_SO), "key").Return(nil).Once()

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{0: testSession}}
	if err := p11.Login(0, pkcs11.CKU_SO, "key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginNoSession(t *testing.T) {
	p11 := &P11{Ctx: mocks.NewMockCryptoki(t), Sessions: map[uint]pkcs11.SessionHandle{}}
	if err := p11.Login(0, pkcs11.CKU_USER, "pin"); err == nil {
		t.Fatal("expected error when slot has no open session, got nil")
	}
}

func TestLoginPassesThroughOtherErrors(t *testing.T) {
	ctx := mocks.NewMockCryptoki(t)
	ctx.EXPECT().Login(testSession, uint(pkcs11.CKU_USER), "wrong").
		Return(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))

	p11 := &P11{Ctx: ctx, Sessions: map[uint]pkcs11.SessionHandle{0: testSession}}
	if err := p11.Login(0, pkcs11.CKU_USER, "wrong"); err == nil {
		t.Fatal("expected the PIN error to propagate, got nil")
	}
}
