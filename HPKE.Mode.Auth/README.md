# HPKE Auth Mode Demo in C# (.NET 10) using NSec

## Description
Hybrid Public Key Encryption (HPKE) combines asymmetric key agreement, key derivation, and AEAD encryption into one interoperable construction. This demo implements HPKE v1 (RFC 9180) **Auth mode** (`mode = 0x02`) using:

- DHKEM(X25519, HKDF-SHA256)
- HKDF-SHA256
- AES-256-GCM

This project is a **minimal educational example** that prints private keys and internal secrets to the console to make each cryptographic step visible.

## RFC Reference
- HPKE v1 (RFC 9180): https://datatracker.ietf.org/doc/html/rfc9180

## What the Demo Shows
- Receiver static key generation (`skR`, `pkR`)
- Sender static authentication key generation (`skS`, `pkS`)
- Sender ephemeral key generation (`skE`, `enc`)
- Auth mode DHKEM with two DH operations (`dh1 || dh2`)
- RFC 9180 labeled HKDF (`LabeledExtract`, `LabeledExpand`)
- Auth mode key schedule (`mode = 0x02`, empty `psk` and `psk_id`)
- AES-256-GCM encryption/decryption
- Sealed format: `sealed = enc || ciphertext_with_tag`

## ⚠️ Security Notice
- NOT production-ready
- DO NOT log private keys in real systems
- DO NOT log shared secrets in real systems
- This visibility is demo-only

## Build & Run
```bash
dotnet restore
dotnet build
dotnet run --project HPKE.Mode.Auth/HPKE.Mode.Auth.csproj
```

## Dependencies
- .NET 10
- NSec.Cryptography

## AI-Generated Code Notice
Parts of the code and/or documentation were generated or assisted by AI. Output must be independently reviewed and security-audited before any production usage.
