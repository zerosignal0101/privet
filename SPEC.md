# Privet Specifications

Status: code-derived specification set for the current Rust workspace.

The documents in [`SPECIFICATIONS/`](SPECIFICATIONS/) are the authoritative technical specifications for the functionality implemented in this repository. They describe the current code, its invariants, and its known limitations. They do not preserve features merely because an older Privet design mentioned them.

## Specification index

| Document | Subject | Primary implementation |
| --- | --- | --- |
| [00-system-architecture.md](SPECIFICATIONS/00-system-architecture.md) | scope, process model, trust boundaries, crate responsibilities | workspace and `privet-core` |
| [01-wire-protocol.md](SPECIFICATIONS/01-wire-protocol.md) | protobuf messages, framing, paths, segmentation, compatibility | `privet-protocol` |
| [02-cryptography-identity.md](SPECIFICATIONS/02-cryptography-identity.md) | Ed25519 identity, certificates, BLAKE3, SPAKE2 primitive, key persistence | `privet-crypto` |
| [03-security-pairing-trust.md](SPECIFICATIONS/03-security-pairing-trust.md) | TLS-to-identity binding, first pairing, trust pinning, revocation | `privet-security` |
| [04-peer-discovery.md](SPECIFICATIONS/04-peer-discovery.md) | mDNS, UDP discovery, peer lifecycle, candidate addresses | `privet-discovery` |
| [05-transport.md](SPECIFICATIONS/05-transport.md) | QUIC, TLS-over-TCP, fallback, logical streams, frame I/O | `privet-transport` |
| [06-transfer-engine.md](SPECIFICATIONS/06-transfer-engine.md) | preparation, manifests, chunk transfer, integrity, pause/cancel/resume | `privet-transfer` |
| [07-storage.md](SPECIFICATIONS/07-storage.md) | SQLite schema, trust/history/address persistence, sidecars and recovery | `privet-storage` |
| [08-core-orchestration.md](SPECIFICATIONS/08-core-orchestration.md) | end-to-end connection, pairing, send/receive, reconnect, event mapping | `privet-core` |
| [09-daemon-ipc.md](SPECIFICATIONS/09-daemon-ipc.md) | daemon lifecycle, local IPC contract, DTOs, event replay, client behavior | `privet-daemon`, `privet-ipc` |
| [10-verification-conformance.md](SPECIFICATIONS/10-verification-conformance.md) | test coverage, conformance requirements, known gaps | workspace tests |

## Reading order

Read `00` first. Client developers normally need `09`, plus the event and lifecycle portions of `08`. Engine contributors should read `01` through `08` in order. Any change to a protobuf field, persistent schema, IPC shape, state transition, security boundary, or normative constant must update the corresponding document in the same change.

## Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** express requirements. Statements labeled **Current limitation** describe observable implementation constraints rather than intended future behavior.
