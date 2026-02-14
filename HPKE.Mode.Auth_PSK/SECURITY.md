# Security Policy

## Supported Versions
This repository provides educational cryptography demos only. No production support guarantees are provided.

## Reporting a Vulnerability
If you identify a vulnerability, please report it to maintainers using a responsible disclosure process and include:

- impact summary
- reproduction steps
- proof-of-concept details
- affected commit/version

(Placeholder process: open a private security report channel when available, or an issue if private reporting is unavailable.)

## Educational-Only Disclaimer
**This project is not production-ready.**

It intentionally prints private keys, PSK values, DH outputs, shared secrets, and derived AEAD material to explain HPKE internals. This behavior is insecure by design and must never be used in real systems.

## Cryptographic Warning
Cryptographic implementations are highly sensitive to subtle errors. This demo:

- has no formal audit claim
- is not presented as side-channel resistant
- does not guarantee misuse resistance

Use audited, production-grade libraries and qualified cryptography engineering review for real deployments.

## AI Disclosure
AI assistance may have been used in code or documentation creation. Independent human review, standards conformance validation, and security assessment are required.
