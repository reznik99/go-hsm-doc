package hsm

import "github.com/miekg/pkcs11"

// Cryptoki is the subset of *pkcs11.Ctx this package uses. Depending on the
// interface (rather than the concrete *pkcs11.Ctx) lets tests inject a mock
// token. A real *pkcs11.Ctx satisfies it.
type Cryptoki interface {
	Initialize(opts ...pkcs11.InitializeOption) error
	Destroy()
	Finalize() error
	GetInfo() (pkcs11.Info, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error)
	GetMechanismInfo(slotID uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error)
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
	CloseSession(sh pkcs11.SessionHandle) error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	GenerateKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	GenerateKeyPair(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	WrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, wrappingkey, key pkcs11.ObjectHandle) ([]byte, error)
	UnwrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, unwrappingkey pkcs11.ObjectHandle, wrappedkey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
}
