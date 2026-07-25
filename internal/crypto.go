package internal

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

type P11 struct {
	Ctx      *pkcs11.Ctx
	Sessions map[uint]pkcs11.SessionHandle
}

func NewP11(modulePath string) (*P11, error) {
	module := &P11{
		Sessions: map[uint]pkcs11.SessionHandle{},
	}

	module.Ctx = pkcs11.New(modulePath)
	if module.Ctx == nil {
		return nil, errors.New("error loading module")
	}
	err := module.Ctx.Initialize()
	if err != nil {
		module.Ctx.Destroy()
		return nil, fmt.Errorf("error initializing module: %w", err)
	}

	return module, nil
}

func (p *P11) GetSlots() (map[uint]pkcs11.TokenInfo, error) {
	output := map[uint]pkcs11.TokenInfo{}
	var getSlotErr error

	slots, err := p.Ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("error reading Slots: %w", err)
	}

	for _, slotID := range slots {
		ti, err := p.Ctx.GetTokenInfo(slotID)
		if err != nil {
			getSlotErr = errors.Join(getSlotErr, fmt.Errorf("get token info for slot %d: %w", slotID, err))
			continue
		}
		if ti.Label == "" {
			continue
		}
		output[slotID] = ti
	}

	return output, getSlotErr
}

func (p *P11) FindObjects(slotID uint, template []*pkcs11.Attribute) (objects []pkcs11.ObjectHandle, err error) {
	sh, ok := p.Sessions[slotID]
	if !ok {
		return nil, fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	err = p.Ctx.FindObjectsInit(sh, template)
	if err != nil {
		return nil, fmt.Errorf("find objects init error: %w", err)
	}
	defer func() {
		err = errors.Join(err, p.Ctx.FindObjectsFinal(sh))
	}()

	for {
		found, _, err := p.Ctx.FindObjects(sh, 100)
		if err != nil {
			return nil, fmt.Errorf("find objects error: %w", err)
		}
		if len(found) == 0 {
			break
		}
		objects = append(objects, found...)
	}

	return objects, nil
}

func (p *P11) OpenSession(slotID uint) (pkcs11.SessionHandle, error) {
	// Use existing
	sh, ok := p.Sessions[slotID]
	if ok {
		return sh, nil
	}
	// Open new connection
	sh, err := p.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return sh, err
	}
	p.Sessions[slotID] = sh
	return sh, nil
}

func (p *P11) CloseAllSessions() error {
	var closeErr error
	for slotID, sh := range p.Sessions {
		err := p.Ctx.CloseSession(sh)
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close session for slot %d: %w", slotID, err))
		}
	}
	clear(p.Sessions)
	return closeErr
}

func (p *P11) destroyObjects(sh pkcs11.SessionHandle, handles ...pkcs11.ObjectHandle) error {
	var destroyErr error
	for _, handle := range handles {
		if err := p.Ctx.DestroyObject(sh, handle); err != nil {
			destroyErr = errors.Join(destroyErr, fmt.Errorf("destroy object %d: %w", handle, err))
		}
	}
	return destroyErr
}

// Login authenticates the slot's session as the given user type: pkcs11.CKU_USER
// with the PIN, or pkcs11.CKU_SO with the SO / management key. If a different user
// type is already logged in, it logs out and retries (a session holds only one).
func (p *P11) Login(slotID, userType uint, secret string) error {
	sh, ok := p.Sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}
	err := p.Ctx.Login(sh, userType, secret)
	switch {
	case err == nil, errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)):
		return nil
	case errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)):
		if lerr := p.Ctx.Logout(sh); lerr != nil {
			return fmt.Errorf("logout before re-login: %w", lerr)
		}
		return p.Ctx.Login(sh, userType, secret)
	default:
		return err
	}
}

func (p *P11) Finalize() error {
	err := p.Ctx.Finalize()
	p.Ctx.Destroy()
	return err
}
