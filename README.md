# gen6-validator

Legality validator for Pokemon X/Y/OR/AS online features (GTS, Wonder Trade, battles). The game sends its Pokemon here and only
proceeds if the answer is signed with the key it was told to trust.

Independent implementation: ASP.NET Core minimal API + [PKHeX.Core](https://github.com/kwsch/PKHeX) for the legality analysis.

## Protocol
- `POST /validator/v1/public_key` (alias `/public_kee`): answer = certificate id (u16 LE) + base64 DER SubjectPublicKeyInfo (ASCII).
- `POST /validator/v1/validate` (alias `/validdtt`): body = service token + NUL, certificate id (u16 LE), payload type (u16 BE),
  count (u16 BE, max 12), then the entries.
  - type 1: entries are `0xA0` opaque bytes + `0xE8` encrypted PK6; types 2-5: just the `0xE8` PK6; types 6-9: either, told apart by length.
  - answer: `02` for an unknown certificate id; `01` alone for an unreadable request; otherwise verdict (`00` all legal / `01`), count (u16 BE),
    one u32 BE per Pokemon (0 legal, 1 not), and when all are legal an RSA-2048 PKCS#1 v1.5 / SHA-256 signature over the entries
    exactly as received (prefix then Pokemon, in order).
- Saves cache the public key per certificate id. After changing the key, change `GEN6V_CERTIFICATE_ID`; saves holding the old id get `02` and refetch.

## Configuration (environment)
| Variable | Default | |
|---|---|---|
| `GEN6V_PRIVATE_KEY_PATH` | required | RSA-2048 private key, PEM |
| `GEN6V_CERTIFICATE_ID` | 1 | |
| `GEN6V_BIND` / `GEN6V_PORT` | 127.0.0.1 / 9107 | |
| `GEN6V_ACCEPT_ANYTHING` | false | `true` skips PKHeX (still signs) |

## Build, test
```
dotnet build -c Release
dotnet run -c Release --project tests/Checks                       # wire-format checks
GEN6V_PRIVATE_KEY_PATH=key.pem dotnet run -c Release &             # then:
dotnet run -c Release --project tests/Checks -- http://127.0.0.1:9107   # end to end, with a PKHeX-generated legal Pokemon
```
Generate a key: `openssl genrsa -out key.pem 2048`. Needs the .NET 10 SDK.

Not tested on a console.

## License
GNU AGPL v3 (see `LICENSE`). [PKHeX.Core](https://github.com/kwsch/PKHeX) is GPL-3.0-or-later; the AGPL is compatible with it (GPLv3 section 13),
and the combined program is distributed under the AGPL. If you run a modified version for other people, the AGPL asks you to offer them the source.

## Pointing the games at it
The games take the validator's address from a patch (in X/Y and OR/AS it is a URL in `code.bin`) or from DNS. Serve it over HTTPS with a
certificate the console accepts (see `deploy/`), answering `/validator/v1/public_key` and `/validator/v1/validate`.

