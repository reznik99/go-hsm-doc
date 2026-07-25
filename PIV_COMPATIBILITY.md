# PIV / Smartcard — remaining work

Working TODO. Core PIV support (capability gating, management-key auth, CKA_ID slot
picker, label-skip) is done and hardware-verified on a YubiKey 5. Delete this file
once the items below are done.

## 4. Export / import constraints

- **Drop the "Extractable" prompt on PIV, force `false`.** `generateKey`/`importKey` already
  get `isPIV` from `promptObjectID` — mirror the label handling: skip the confirm and pass
  `extractable = false`. (`internal/cli/handler.go`)
- **Hide "Export" for non-extractable private/secret keys.** `ExportPrivateKey`/`ExportSecretKey`
  wrap with an ephemeral KEK, which needs `CKA_EXTRACTABLE=true` and fails on PIV. Gate it
  *capability-driven*: read the object's `CKA_EXTRACTABLE`; if private/secret and not
  extractable, drop "Export" (or error clearly). Public-key + cert export stay.
  (`internal/cli/handler.go`, `internal/hsm/crypto_export.go`)
- **Cert import onto a populated slot.** On PIV a cert's `CKA_ID` must match an existing key.
  `resolveImportObjectID` already resolves it; add a guard/message when no matching key exists.

## 5. UX & error hints

- **PIN errors** in `login()`: map `CKR_PIN_INCORRECT` → "wrong PIN (PIV blocks after 3 tries)"
  and `CKR_PIN_LOCKED` → "blocked — unblock with `ykman piv access unblock-pin`". A small
  `pinHint(err) string` keyed on `pkcs11.Error` (like `isElevatedAuthError`).
- **9C is PIN-per-op:** read `CKA_ALWAYS_AUTHENTICATE` when printing a key and annotate
  "PIN required per operation". (`getAttributeValue`/`printObjectInfo`)

## 6. Mock-based tests

Everything left untested calls the token, so it needs a seam.

- Add a `Cryptoki` interface in `internal/hsm` over the `*pkcs11.Ctx` methods used; `*pkcs11.Ctx`
  satisfies it, so `NewP11` is unchanged. Add `.mockery.yaml`, generate `MockCryptoki`.
- Fold in the deferred `Ctx` tidy: add `P11` wrappers (`GetInfo`/`GetSlotInfo`/`GetAttributes`/
  `DestroyObject`), replace the `a.mod.Ctx.*` reach-ins in `internal/cli/`, unexport `Ctx`.
- Then test without hardware: `FindObjects` pagination, `OpenSession` cache, `Login` user-type
  switching, generate/import templates, `withElevatedAuth` retry, `resolveImportObjectID`,
  `loadCapabilities`, `detectToken`.
