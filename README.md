# Hybrid Public Key Encryption (HPKE) Demos

This solution contains educational .NET 10 console demos for **HPKE v1 (RFC 9180)**.
Each project demonstrates one HPKE mode with clear, step-by-step flow and explicit security disclaimers.

## Included Projects

| Project | HPKE Mode | Description |
|---|---|---|
| `HPKE.Mode.Base` | Base | Sender uses an ephemeral key and recipient public key. |
| `HPKE.Mode.PSK` | PSK | Base mode + pre-shared key input into key schedule. |
| `HPKE.Mode.Auth` | Auth | Sender authenticates with a static sender key in addition to ephemeral key. |
| `HPKE.Mode.Auth_PSK` | Auth+PSK | Combines sender authentication and pre-shared key. |

## Common Technical Baseline

All projects in this solution follow the same baseline:

- .NET SDK-style console projects (`Microsoft.NET.Sdk`)
- Target framework: `net10.0`
- Nullable enabled
- Implicit usings enabled
- Crypto library: `NSec.Cryptography`
- Educational/demo-first implementation style

## Solution Structure

- `Hybrid-Public-Key-Encryption.Demos.slnx`
- `HPKE.Mode.Base/`
- `HPKE.Mode.PSK/`
- `HPKE.Mode.Auth/`
- `HPKE.Mode.Auth_PSK/`

Each demo project includes:

- `<ProjectName>.csproj`
- `Program.cs`
- `README.md`
- `ARCHITECTURE.md`
- `SECURITY.md`

## Build and Run

From the solution root:

```bash
dotnet restore
dotnet build
```

Run a specific demo:

```bash
dotnet run --project HPKE.Mode.Base
dotnet run --project HPKE.Mode.PSK
dotnet run --project HPKE.Mode.Auth
dotnet run --project HPKE.Mode.Auth_PSK
```

## Security Notice

These projects are **demo-only** and **not production-ready**.
They are designed for learning HPKE internals and may intentionally expose sensitive material in console output for educational purposes.
Do not use this code directly in production systems.

## References

- RFC 9180 (HPKE v1): https://datatracker.ietf.org/doc/html/rfc9180
