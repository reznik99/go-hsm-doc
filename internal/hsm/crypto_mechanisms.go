package hsm

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

func (p *P11) GetMechanisms(slotID uint) (map[uint]pkcs11.MechanismInfo, error) {
	mechanisms, err := p.Ctx.GetMechanismList(slotID)
	if err != nil {
		return nil, fmt.Errorf("get mechanisms for slot %d: %w", slotID, err)
	}

	output := make(map[uint]pkcs11.MechanismInfo, len(mechanisms))
	var mechanismErr error
	for _, mechanism := range mechanisms {
		info, err := p.Ctx.GetMechanismInfo(slotID, []*pkcs11.Mechanism{mechanism})
		if err != nil {
			mechanismErr = errors.Join(mechanismErr, fmt.Errorf("get mechanism 0x%X for slot %d: %w", mechanism.Mechanism, slotID, err))
			continue
		}
		output[mechanism.Mechanism] = info
	}

	return output, mechanismErr
}
