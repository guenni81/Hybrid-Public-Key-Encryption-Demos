# Architecture Overview

## Overview
This repository is an educational demonstration of HPKE v1 Base Mode (RFC 9180) implemented in C# on .NET 10 using NSec.Cryptography. It is intentionally instrumented to print private keys, shared secrets, and derived values so learners can inspect each stage.

This project is **not** production-ready cryptographic software.

## Standards Reference
- RFC 9180 (Hybrid Public Key Encryption): https://datatracker.ietf.org/doc/html/rfc9180

## Selected HPKE Ciphersuite
This demo uses the RFC 9180 ciphersuite:

- KEM: DHKEM(X25519, HKDF-SHA256), `kem_id = 0x0020`
- KDF: HKDF-SHA256, `kdf_id = 0x0001`
- AEAD: AES-256-GCM, `aead_id = 0x0002`

## High-Level Data Flow
```mermaid
sequenceDiagram
    autonumber
    participant S as Sender
    participant R as Recipient

    Note over R: Generate static key pair (skR, pkR)
    R->>S: pkR

    Note over S: Generate ephemeral key pair (skE, pkE)
    Note over S: enc = Serialize(pkE)

    S->>S: DH_sender = DH(skE, pkR)
    S->>S: shared_secret = ExtractAndExpand(DH_sender, enc||pkR)

    S->>R: enc

    R->>R: pkE = Deserialize(enc)
    R->>R: DH_receiver = DH(skR, pkE)
    R->>R: shared_secret = ExtractAndExpand(DH_receiver, enc||pkR)

    Note over S,R: Base mode key schedule (same inputs)
    S->>S: (key, nonce) = KeySchedule(shared_secret, info, psk="", psk_id="")
    R->>R: (key, nonce) = KeySchedule(shared_secret, info, psk="", psk_id="")

    S->>S: ciphertext_with_tag = AEAD.Seal(key, nonce, aad, plaintext)
    S->>R: sealed = enc || ciphertext_with_tag

    R->>R: plaintext = AEAD.Open(key, nonce, aad, ciphertext_with_tag)
```

## Key Schedule
For this ciphersuite, the AEAD output sizes are:

- `Nk = 32` bytes (AES-256-GCM key)
- `Nn = 12` bytes (AES-GCM nonce)

```mermaid
flowchart TD
    A[suite_id = concat HPKE kem_id kdf_id aead_id] --> B[Base mode with empty psk and empty psk_id]
    B --> C[psk_id_hash = LabeledExtract empty psk_id_hash psk_id]
    A --> C

    D[info application context] --> E[info_hash = LabeledExtract empty info_hash info]
    A --> E

    C --> F[key_schedule_context = concat mode psk_id_hash info_hash]
    E --> F

    G[shared_secret from KEM ExtractAndExpand] --> H[secret = LabeledExtract shared_secret secret psk]
    A --> H

    H --> I[key = LabeledExpand secret key key_schedule_context Nk 32]
    H --> J[nonce = LabeledExpand secret nonce key_schedule_context Nn 12]
    F --> I
    F --> J
    A --> I
    A --> J
```

## Message Format
The transmitted sealed message is:

- `sealed = enc || ciphertext_with_tag`

Where:

- `enc` is the sender ephemeral public key encoding (`pkE`)
- `ciphertext_with_tag` is AES-256-GCM output (ciphertext + authentication tag)
- The AEAD nonce is **derived** from the HPKE key schedule and is not transmitted on the wire

In this demo, derived nonce values may be printed for debugging/learning visibility.

## Security Considerations
- The demo prints private keys and secret material; this is intentionally insecure for learning.
- The implementation has no formal audit and should not be treated as hardened cryptographic code.
- Risks include side-channel leakage, API misuse, and accidental secret exposure through logs/output.
- This repository is not intended for production deployment.

## AI Usage Disclosure
AI tools may have been used to generate or refine parts of the code and documentation in this repository. Users are responsible for independently verifying correctness, standards conformance, and security properties. Cryptographic implementations require expert review before any real-world use.

## Appendix (Optional)
Optional (requires rendering): PlantUML equivalents of the diagrams above.

### Sequence Diagram (PlantUML)
```plantuml
@startuml
autonumber
participant Sender as S
participant Recipient as R

note over R
Generate static key pair (skR, pkR)
end note
R -> S: pkR

note over S
Generate ephemeral key pair (skE, pkE)
enc = Serialize(pkE)
end note

S -> S: DH_sender = DH(skE, pkR)
S -> S: shared_secret = ExtractAndExpand(DH_sender, enc||pkR)
S -> R: enc

R -> R: pkE = Deserialize(enc)
R -> R: DH_receiver = DH(skR, pkE)
R -> R: shared_secret = ExtractAndExpand(DH_receiver, enc||pkR)

note over S,R
Base mode key schedule (same inputs)
end note
S -> S: (key, nonce) = KeySchedule(shared_secret, info, psk="", psk_id="")
R -> R: (key, nonce) = KeySchedule(shared_secret, info, psk="", psk_id="")

S -> S: ciphertext_with_tag = AEAD.Seal(key, nonce, aad, plaintext)
S -> R: sealed = enc || ciphertext_with_tag
R -> R: plaintext = AEAD.Open(key, nonce, aad, ciphertext_with_tag)
@enduml
```

### Key Schedule Flow (PlantUML)
```plantuml
@startuml
start

:suite_id = "HPKE" || kem_id || kdf_id || aead_id;
:psk = ""; psk_id = "" (Base mode);
:psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id);
:info_hash = LabeledExtract("", "info_hash", info);
:key_schedule_context = mode || psk_id_hash || info_hash;
:secret = LabeledExtract(shared_secret, "secret", psk);
:key = LabeledExpand(secret, "key", key_schedule_context, Nk=32);
:nonce = LabeledExpand(secret, "nonce", key_schedule_context, Nn=12);

stop
@enduml
```
