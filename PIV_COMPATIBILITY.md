# PIV / Smartcard Compatibility Plan

Plan for making `go-hsm-doc` work with PIV smartcards (YubiKey PIV via `libykcs11`,
other PIV cards via `opensc-pkcs11`) in addition to the HSMs it currently targets.

## Context

- Tested so far only against an old **Luna HSM** and **SoftHSM2**.
- Both are "generic HSM" tokens: `CKA_LABEL` / `CKA_ID` are free-form, symmetric keys
  and arbitrary mechanisms are allowed, and private keys can be marked extractable.
- **PIV is fundamentally more constrained** and several of the tool's assumptions break
  on it (see below).

## Core insight: HSM vs PIV

| Aspect | Generic HSM (Luna, SoftHSM2) | PIV (YubiKey, smartcards) |
|---|---|---|
| Object label / ID | Any value you choose | Fixed per slot; `CKA_ID` selects the slot, label is auto-derived |
| Key slots | Effectively unlimited | Fixed set: `9a`, `9c`, `9d`, `9e`, `82`–`95` (retired), `F9` (attestation) |
| Write auth (gen/import) | User PIN | **Management key** via `CKU_SO`, not the user PIN |
| Mechanisms | Broad | RSA2048 + ECCP256/ECCP384 only (no symmetric, no P-224/P-521, no DES) |
| Private key extraction | Optional (`CKA_EXTRACTABLE`) | Never extractable; cannot be wrapped/exported |
| Session objects | Supported | Not supported; `CKA_TOKEN` must be true |

## Confirmed gaps in the current code

- `internal/crypto.go:120` — `Login` only ever does `CKU_USER`; no management-key (`CKU_SO`) path.
- No `CKA_ID` is set or used anywhere — on PIV this is what selects the slot.
- `internal/crypto_generate.go` — always sets `CKA_TOKEN`/`CKA_EXTRACTABLE`; offers symmetric keys.
- `handler.go:23-33` — menu offers `AES/3DES/DES` and `P224/P256/P384/P521`, most unsupported on PIV.
- Export flows (`ExportPrivateKey`/`ExportSecretKey`) rely on wrapping extractable keys — impossible on PIV.
- Login prompt says `"Slot/Partition PIN"` (Luna terminology).

## Design principle

Keep behavior **capability-driven, not "if Yubico"**. Detect the vendor/model only for
things that cannot be discovered otherwise (PIV fixed-slot model, management-key auth).
Gate algorithms and extractability off the actual `C_GetMechanismList` and token flags,
so other smartcards and future tokens benefit without a special case each.

## Task list (suggested order: 0 → 1 → 3 → 2 → 4 → 5 → 6)

### 0. Foundation — detect the token and carry a profile
Everything else depends on this.
- At load (`NewP11`), query `C_GetInfo` + `C_GetTokenInfo` + `C_GetMechanismList`.
- Build a `TokenProfile` struct: `IsPIV`, `SupportedMechs`, `FreeFormLabels`,
  `SupportsSymmetric`, `SupportsExtractable`, `FixedSlots`, `NeedsManagementKey`.
- Detect PIV/YubiKey via `CK_TOKEN_INFO.ManufacturerID` (`"Yubico"`), `.Model`
  (`"YubiKey YK5"`), `CK_INFO.LibraryDescription` (`"ykcs11"` / `"OpenSC"`) —
  combined with the mechanism list, not string-match alone.
- Thread the profile into `handler.go` so menus adapt.

### 1. Authentication — management key for writes (biggest blocker)
- PIV generate/import require `CKU_SO` login with the **management key**, not the user PIN.
- Add SO/management-key login, prompted only when `profile.NeedsManagementKey`.
- Fix prompt wording: say "PIV PIN" when `IsPIV` instead of "Slot/Partition PIN".
- Note for users: `ykman piv access change-management-key --generate --protect` lets the
  PIN authorize management ops, avoiding a separate management key.

### 2. Object identity — `CKA_ID` and slot mapping
- When `IsPIV`: replace the free-form label prompt with a **slot picker**
  (`9a`/`9c`/`9d`/`9e`/retired), set the matching `CKA_ID`, ignore/skip the label.
- General win: set `CKA_ID` even on HSMs so keys and their certs can be correlated.

### 3. Mechanism/algorithm gating
- Filter the algorithm/curve menus by `profile.SupportedMechs`.
- Hides `AES/3DES/DES`, `P-224`, `P-521` on PIV (unsupported) — and helps every token.

### 4. Export/import constraints
- Hide/disable "Export private key" when `!profile.SupportsExtractable` (PIV can't wrap keys);
  only public key + cert export make sense.
- On PIV, force `CKA_EXTRACTABLE=false` and `CKA_TOKEN=true`; drop those prompts.
- Certificate import on PIV must target a slot that already holds the matching key — validate/guide.

### 5. UX & error handling
- Map PIV errors to hints: `CKR_USER_NOT_LOGGED_IN` / `CKR_ACTION_PROHIBITED` on write →
  "PIV needs the management key"; `CKR_PIN_LOCKED` → PUK guidance.
- Surface `CKA_ALWAYS_AUTHENTICATE` slot (`9c`) as "PIN required per operation".

### 6. Testing
- Unit-test `TokenProfile` detection with canned `CK_TOKEN_INFO` / mechanism-list fixtures (no device).
- Introduce the `Cryptoki` interface + mockery here to test profile-driven branching without hardware.
- Keep SoftHSM2/Luna as the "generic HSM" regression path; add YubiKey PIV + other smartcard as
  the "constrained" path.

## Reference

- YubiKey PIV module: `/usr/lib64/libykcs11.so.2` (ykcs11). PIV PIN is separate from the
  OpenPGP (PGP) and FIDO2 (passkey) applets — default PIV PIN `123456`.
- PIV slots: `9a` auth, `9c` signature (PIN per op), `9d` key management, `9e` card auth (no PIN),
  `82`–`95` retired key management (20), `F9` attestation (factory, do not touch).
