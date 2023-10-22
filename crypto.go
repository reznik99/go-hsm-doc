package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

type P11 struct {
	ctx      *pkcs11.Ctx
	sessions map[uint]pkcs11.SessionHandle
}

func NewP11(modulePath string) (*P11, error) {
	module := &P11{
		sessions: map[uint]pkcs11.SessionHandle{},
	}

	module.ctx = pkcs11.New(modulePath)
	if module.ctx == nil {
		return nil, fmt.Errorf("error loading module")
	}
	err := module.ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("error initializing module: %s", err)
	}

	return module, nil
}

func (p *P11) GetSlots() (map[uint]pkcs11.TokenInfo, error) {
	output := map[uint]pkcs11.TokenInfo{}

	slots, err := p.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("error reading Slots: %s", err)
	}

	for _, slotID := range slots {
		ti, err := p.ctx.GetTokenInfo(slotID)
		if err != nil {
			logger.Warn("Error getting slot info", logger.Args("", err))
			continue
		}
		if ti.Label == "" {
			continue
		}
		output[slotID] = ti
	}

	return output, nil
}

func (p *P11) FindObjects(slotID uint, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	sh, ok := p.sessions[slotID]
	if !ok {
		return nil, fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	err := p.ctx.FindObjectsInit(sh, []*pkcs11.Attribute{})
	if err != nil {
		return nil, fmt.Errorf("find objects init error: %w", err)
	}
	defer p.ctx.FindObjectsFinal(sh)

	objects, _, err := p.ctx.FindObjects(sh, 1000)
	if err != nil {
		return nil, fmt.Errorf("find objects error: %w", err)
	}

	return objects, nil
}

func (p *P11) OpenSession(slotID uint) error {
	sh, err := p.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	p.sessions[slotID] = sh
	return nil
}

func (p *P11) CloseSession(slotID uint) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return nil
	}
	return p.ctx.CloseSession(sh)
}

func (p *P11) Login(slotID uint, pin string) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}
	return p.ctx.Login(sh, pkcs11.CKU_USER, pin)
}

func (p *P11) Finalize() error {
	err := p.ctx.Finalize()
	if err != nil {
		return err
	}
	p.ctx.Destroy()
	return nil
}

func (p *P11) GenerateAESKey(slotID uint, label string, keylength int, extractable bool) error {
	sh, ok := p.sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keylength/8),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}

	_, err := p.ctx.GenerateKey(sh, mech, temp)

	return err
}
