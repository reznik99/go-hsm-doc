# GO-HSM-DOC

[![CI](https://github.com/reznik99/go-hsm-doc/actions/workflows/ci.yml/badge.svg)](https://github.com/reznik99/go-hsm-doc/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/badge/coverage-16.6%25-red)
![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![PKCS#11](https://img.shields.io/badge/PKCS%2311-HSM%20%C2%B7%20PIV%20smartcard-2E7D32)

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <p align="center">
    A simple CLI tool to view, inspect and debug PKCS#11-compliant HSMs and PIV smartcards.
  </p>

  ![CLI Screenshot][cli]  

</div>

### Functionality
1. Get HSM and Token info
2. List Slots and Keys within a Slot
3. Delete Certificates, Public, Private and Symmetric keys
4. Export Certificates, Public, Private and Symmetric keys
5. Import Certificates, Public, Private and Symmetric keys
6. Generate RSA, EC, AES, 3DES, DES keys (menu adapts to what the token actually supports)

## Getting Started

### Requirements

- [Go](https://go.dev/dl/) 1.25+ (to build)
- A PKCS#11 module (`.so` / `.dll`) for your token — e.g. SoftHSM2, YubiKey `ykcs11`, or OpenSC

### Build & run

```sh
make build      # produces ./build/main
./build/main
```

On start the tool asks for the path to your Cryptoki library, then drops you into an
interactive menu. Common module paths:

| Token | Module (typical path) |
|---|---|
| SoftHSM2 | `/usr/lib64/libsofthsm2.so` |
| YubiKey PIV | `/usr/lib64/libykcs11.so.2` |
| PIV smartcard (OpenSC) | `/usr/lib64/opensc-pkcs11.so` |

> Tip: `pkcs11-tool --module <path> -I -L` is a quick way to confirm a module loads your token.

### Supported tokens

| Token | Type | Notes |
|---|---|---|
| SoftHSM2 | Software HSM | Free-form labels/IDs, all mechanisms |
| Thales Luna | Hardware HSM | Free-form labels/IDs |
| YubiKey PIV | Smartcard (`ykcs11`) | Writes need the management key; `CKA_ID` selects the PIV slot |
| Generic PIV | Smartcard (`opensc-pkcs11`) | Same PIV constraints via OpenSC |

For PIV specifics (slot ↔ `CKA_ID` mapping, management-key auth), the tool has a built-in
slot picker; PIV keys are non-extractable, so only public keys and certificates can be exported.

## Examples

1. Print HSM and Token information

   ![CLI Screenshot][hsm_info]

2. List Slots inside HSM

   ![CLI Screenshot][slot_list]

3. List Tokens inside HSM

   ![CLI Screenshot][token_list]

4. Find Tokens/Keys

   ![CLI Screenshot][find_token]

5. Delete Tokens/Keys

   ![CLI Screenshot][delete_token]

6. Export Tokens/Keys

   ![CLI Screenshot][export_token]

7. Generate Tokens/Keys

   ![CLI Screenshot][generate_keys]

## Development

```sh
make test    # unit tests (race) + coverage report at build/coverage.html
make lint    # golangci-lint
make build   # build ./build/main
```

Package layout:

- `internal/cli` — the interactive UI and command handlers
- `internal/hsm` — the PKCS#11 session wrapper (the token driver)
- `internal/pkcs11util` — pure encoding/parsing helpers (attributes, curves, key parsing)

<!-- LICENSE -->
## License  

Distributed under the MIT License. See `LICENSE` for more information.  

<!-- CONTACT -->
## Contact  

Francesco Gorini - goras.francesco@gmail.com - https://francescogorini.com  

Project Link: [https://github.com/reznik99/go-hsm-doc](https://github.com/reznik99/go-hsm-doc)  

<p align="right">(<a href="#top">back to top</a>)</p>  


<!-- LINKS -->
[cli]: res/cli.png
[hsm_info]: res/hsm-info.png
[slot_list]: res/list-slots.png
[token_list]: res/list-tokens.png
[find_token]: res/find-token.png
[delete_token]: res/delete-token.png
[export_token]: res/export-token.png
[generate_keys]: res/generate-keys.png
