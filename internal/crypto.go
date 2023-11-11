package internal

import (
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/pterm/pterm"
)

type P11 struct {
	Ctx      *pkcs11.Ctx
	Sessions map[uint]pkcs11.SessionHandle
	logger   pterm.Logger
}

func NewP11(modulePath string, logger pterm.Logger) (*P11, error) {
	module := &P11{
		Sessions: map[uint]pkcs11.SessionHandle{},
		logger:   logger,
	}

	module.Ctx = pkcs11.New(modulePath)
	if module.Ctx == nil {
		return nil, fmt.Errorf("error loading module")
	}
	err := module.Ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("error initializing module: %s", err)
	}

	return module, nil
}

func (p *P11) GetSlots() (map[uint]pkcs11.TokenInfo, error) {
	output := map[uint]pkcs11.TokenInfo{}

	slots, err := p.Ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("error reading Slots: %s", err)
	}

	for _, slotID := range slots {
		ti, err := p.Ctx.GetTokenInfo(slotID)
		if err != nil {
			p.logger.Warn("Error getting slot info", p.logger.Args("", err))
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
	sh, ok := p.Sessions[slotID]
	if !ok {
		return nil, fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}

	err := p.Ctx.FindObjectsInit(sh, []*pkcs11.Attribute{})
	if err != nil {
		return nil, fmt.Errorf("find objects init error: %w", err)
	}
	defer p.Ctx.FindObjectsFinal(sh)

	objects, _, err := p.Ctx.FindObjects(sh, 1000)
	if err != nil {
		return nil, fmt.Errorf("find objects error: %w", err)
	}

	return objects, nil
}

func (p *P11) OpenSession(slotID uint) error {
	// Use existing
	_, ok := p.Sessions[slotID]
	if ok {
		return nil
	}
	// Open new connection
	sh, err := p.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	p.Sessions[slotID] = sh
	return nil
}

func (p *P11) CloseAllSessions() error {
	for _, sh := range p.Sessions {
		err := p.Ctx.CloseSession(sh)
		if err != nil {
			pterm.Warning.Printfln("Failed to close session %d: %s", sh, err)
		}
	}
	return nil
}

func (p *P11) Login(slotID uint, pin string) error {
	sh, ok := p.Sessions[slotID]
	if !ok {
		return fmt.Errorf("session doesn't exist for slot: %d", slotID)
	}
	return p.Ctx.Login(sh, pkcs11.CKU_USER, pin)
}

func (p *P11) Finalize() error {
	err := p.Ctx.Finalize()
	if err != nil {
		return err
	}
	p.Ctx.Destroy()
	return nil
}
