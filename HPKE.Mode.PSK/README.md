# HPKE.Mode.PSK

This project is an educational .NET 10 console demonstration of HPKE v1 **PSK mode** (`mode = 0x01`) from RFC 9180.

It shows the full sender/receiver flow:
- Sender: `SetupPSKS` + `Seal`
- Receiver: `SetupPSKR` + `Open`

## Ciphersuite

This demo uses one fixed RFC 9180 ciphersuite:
- KEM: `DHKEM(X25519, HKDF-SHA256)` (`kem_id = 0x0020`)
- KDF: `HKDF-SHA256` (`kdf_id = 0x0001`)
- AEAD: `AES-256-GCM` (`aead_id = 0x0002`)
- Parameters: `Nk = 32`, `Nn = 12`, `Nt = 16`

RFC: https://datatracker.ietf.org/doc/html/rfc9180

## PSK mode specifics

In PSK mode (`mode = 0x01`), both `psk` and `psk_id` are required and must be non-empty.
This project explicitly validates those constraints following RFC 9180 Section 5.1 (`VerifyPSKInputs`).

## Build and run

From the solution root:

```bash
dotnet restore
dotnet build
dotnet run --project HPKE.Mode.PSK
```

## Dependencies

- [.NET 10 SDK](https://dotnet.microsoft.com/)
- [`NSec.Cryptography` 25.4.0](https://www.nuget.org/packages/NSec.Cryptography)

## Security notice (important)

**DEMO ONLY. NOT PRODUCTION-READY.**

This demo intentionally prints private keys, PSK values, DH outputs, and derived key material to make RFC 9180 steps visible.
Printing secret material is insecure and must never be done in production systems.

## AI usage disclosure

Some parts of this project may be AI-assisted.
All cryptographic code and documentation must be independently reviewed, tested, and audited by qualified experts before any real-world use.
