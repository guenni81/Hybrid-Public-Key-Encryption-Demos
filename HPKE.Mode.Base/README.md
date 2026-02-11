# HPKE Base Mode Demo in C# (.NET 10) using NSec

## Description
Hybrid Public Key Encryption (HPKE) is a standard that combines public-key cryptography, key derivation, and symmetric encryption into a single, interoperable design. This demo implements HPKE v1 (RFC 9180) **Base mode** using:

- DHKEM(X25519, HKDF-SHA256)
- HKDF-SHA256
- AES-256-GCM

This project is a **minimal educational example** intended for learning and demonstration. It prints private keys and shared secrets to the console so you can observe the internal flow.

## RFC Reference
- HPKE v1 (RFC 9180): https://datatracker.ietf.org/doc/html/rfc9180

## What the Demo Shows
- Static recipient key generation
- Ephemeral sender key generation
- Diffie-Hellman shared secret computation
- HPKE labeled HKDF key schedule
- AEAD encryption and decryption
- Console trace of internal values and derived secrets

## ⚠️ Security Notice
- NOT production-ready
- DO NOT log private keys
- DO NOT log shared secrets
- Demo-only visibility of secrets

## Build & Run
```bash
dotnet restore
dotnet build
dotnet run
```

## Dependencies
- .NET 10
- NSec.Cryptography

## AI-Generated Code Notice
Parts of the code and/or documentation were generated or assisted by AI. The output was reviewed and validated manually, but users must independently verify correctness and security. AI-generated cryptographic code must be audited before real-world use.
