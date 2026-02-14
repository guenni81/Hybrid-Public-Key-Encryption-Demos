# SECURITY - HPKE.Mode.PSK

## Supported versions

This repository project is an educational demonstration.
There are no production support guarantees, SLAs, or compatibility guarantees.

## Security policy

**Demo-only implementation. Not production-ready.**

This project intentionally prints secret material (private keys, PSK, DH outputs, derived secrets) to illustrate RFC 9180 internals.
That behavior is insecure for real deployments.

## Vulnerability reporting

Please report suspected vulnerabilities through your organization's responsible disclosure process.
If no formal process exists, open a private security report channel and include:
- affected file(s)
- reproduction steps
- potential impact
- suggested mitigation (if known)

## Cryptography warning

Cryptographic implementations are subtle and easy to get wrong.
This demo has not been claimed as audited.
No side-channel resistance guarantees are provided.
Do not assume misuse resistance, production hardening, or formal verification.

## AI disclosure

AI tools may have been used to assist with code or documentation.
All outputs must be independently reviewed, tested, and audited by qualified experts before real-world use.
