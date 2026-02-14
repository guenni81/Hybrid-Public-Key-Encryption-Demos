# HPKE Auth+PSK Mode Demo in C# (.NET 10) using NSec

## Description
This project extends the HPKE demos with HPKE v1 **Authenticated + PSK mode** (`mode = 0x03`) as defined by RFC 9180. It uses:

- DHKEM(X25519, HKDF-SHA256)
- HKDF-SHA256
- AES-256-GCM

Compared with other demo modes:

- Base (`mode = 0x00`): no sender authentication, no PSK
- Auth (`mode = 0x02`): sender authentication, no PSK
- Auth+PSK (`mode = 0x03`): sender authentication **and** PSK contribution in key schedule

The implementation is educational and intentionally prints private and secret material for traceability.

## RFC Reference
- RFC 9180 (HPKE v1): https://datatracker.ietf.org/doc/html/rfc9180

## Ciphersuite and Parameters
- `kem_id = 0x0020` (DHKEM(X25519, HKDF-SHA256))
- `kdf_id = 0x0001` (HKDF-SHA256)
- `aead_id = 0x0002` (AES-256-GCM)
- `Nk = 32`, `Nn = 12`, `Nt = 16`

## Build & Run
```bash
dotnet restore
dotnet build
dotnet run --project HPKE.Mode.Auth_PSK/HPKE.Mode.Auth_PSK.csproj
```

## Dependencies
- .NET 10 SDK
- NSec.Cryptography (pinned package version)

## Security Warning
**DEMO ONLY**:

- This demo prints private keys, DH outputs, shared secrets, PSK data, and key schedule outputs.
- This is intentionally insecure and must never be used in production.
- Production systems must avoid secret logging, use hardened key management, and be independently reviewed.

## AI Usage Disclosure
AI-assisted generation may have been used for parts of this code and documentation. You must independently verify RFC conformance and perform a professional security audit before any real-world use.
