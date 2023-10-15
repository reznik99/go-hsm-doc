package main

import "github.com/miekg/pkcs11"

type P11 struct {
	ctx pkcs11.Ctx
}

func NewP11(modulePath string) (P11, error) {
	module := P11{}

	// module.ctx = pkcs11.New(modulePath)
	// if module.ctx == nil {
	// 	fatal("Error loading module: %s", err)
	// }
	// err = module.ctx.Initialize()
	// if err != nil {
	// 	fatal("Error initializing module: %s", err)
	// }

	return module, nil
}

func (p P11) Finalize() {
	// p.ctx.Finalize()
	// return p.ctx.Destroy()
}

func (p P11) Close() {
	// return p.ctx.CloseAllConnections()
}

func (p P11) Login(pin string) {
	// return p.ctx.Login(pin)
}
