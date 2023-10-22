package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

type P11 struct {
	ctx *pkcs11.Ctx
	sh  pkcs11.SessionHandle
}

func NewP11(modulePath string) (*P11, error) {
	module := &P11{}

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

func (p *P11) FindObjects(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	err := p.ctx.FindObjectsInit(p.sh, []*pkcs11.Attribute{})
	if err != nil {
		return nil, fmt.Errorf("find objects init error: %w", err)
	}
	defer p.ctx.FindObjectsFinal(p.sh)

	objects, _, err := p.ctx.FindObjects(p.sh, 1000)
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
	p.sh = sh
	return nil
}

func (p *P11) CloseSession(slotID uint) error {
	return p.ctx.CloseSession(p.sh)
}

func (p *P11) Login(pin string) error {
	return p.ctx.Login(p.sh, pkcs11.CKU_USER, pin)
}

func (p *P11) Finalize() error {
	err := p.ctx.Finalize()
	if err != nil {
		return err
	}
	p.ctx.Destroy()
	return nil
}
