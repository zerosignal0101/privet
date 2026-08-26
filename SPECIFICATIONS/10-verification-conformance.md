# 10. Verification and Conformance

## 1. Purpose

This document defines how the current Privet implementation demonstrates conformance. It separates checked-in automated coverage from platform and release validation and records gaps without presenting planned behavior as implemented.

## 2. Conformance levels

| Level | Requirement |
|---|---|
| crate | unit/integration tests for one subsystem and invalid inputs |
| integration | real implementations from two or more subsystems |
| transport | actual loopback QUIC/TCP sockets, not only memory streams |
| platform | native filesystem, IPC, permissions, and shutdown behavior |
| release | clean build/test, security, migration/recovery, and client compatibility |

Mocks are suitable for deterministic state machines and fault injection. They do not replace real transport, SQLite, filesystem, or local-IPC tests where those implementations are the subject.

## 3. Automated coverage by crate

| Crate | Required/current focus |
|---|---|
| `privet-protocol` | varints, caps, protobuf, path/root validation |
| `privet-crypto` | identity, keystore, SPAKE2, transcript, tags |
| `privet-security` | code lifetime/attempts, pins, certificates, exporter binding, commit timing |
| `privet-discovery` | beacons, replay/rate limits, lifecycle, subnets, known addresses |
| `privet-transport` | frame boundaries, real QUIC/TCP, certificate/exporter, fallback |
| `privet-transfer` | preparation, empty dirs, integrity, ACK/RTO, backpressure, control/resume/collisions |
| `privet-storage` | migrations, CRUD, sidecars, rehash, durability, reconciliation |
| `privet-core` | construction, hello/auth, pairing, discovery, send/serve, reconnect/recovery, E2E |
| `privet-ipc` | strict JSON, framing, correlation, events, endpoint lifecycle |
| `privet-daemon` | config mapping, replay/session, dispatch, shutdown ordering |

## 4. Critical end-to-end scenarios

Before release, supported desktop platforms must pass:

1. First contact over QUIC with a matching six-digit code creates identical pins.
2. Wrong, expired, replayed, and over-attempt codes create no trust record.
3. A pinned peer reconnects without code; changed SPKI fails closed.
4. Discovery and pairing preserve different QUIC and TCP ports.
5. A file and folder containing nested empty directories transfer and verify over QUIC.
6. The same functional transfer completes over TLS/TCP fallback.
7. Loss/reordering produces selective retransmission with bounded work.
8. Interruption leaves valid sidecars; resume rehashes and requests missing/corrupt chunks.
9. Either peer can control an active transfer with truthful events/history.
10. Restart preserves identity, trust, history, and recoverable receive staging.
11. Two IPC clients correlate out-of-order responses and deduplicate replay/live overlap.
12. A stale IPC endpoint recovers while a live daemon prevents a second instance.

## 5. Security negative tests

Tests vary one protected element at a time: certificate/fingerprint, stored/presented SPKI, roles and fingerprint order, SPAKE2 messages, nonces, exporter, tags/acknowledgements, unsafe paths, chunk bytes/length/hash, segment/full-file hashes, frame lengths/varints/protobuf, sidecar counts/bitmaps, and revoked/unknown peers.

Every case fails closed, emits no success, and leaves state unchanged or explicitly recoverable.

## 6. Resource and robustness tests

Fuzz/property tests should target frames, sidecars, path normalization, bitmasks, and transitions. Stress tests should cover maximum metadata counts, bounded event/command queues, slow readers, interrupted writers, repeated discovery input, many IPC requests, and database busy handling.

Tests assert bounds, not just output: 4 MiB peer control, 1 MiB IPC JSON and received chunk, 32 global in-flight chunks, finite retries, 1,024 replay events, and bounded queues.

## 7. Platform matrix

| Area | Linux | macOS | Windows |
|---|---|---|---|
| QUIC and TLS/TCP loopback | required | required | required |
| mDNS and UDP broadcast | required | required | required |
| Unix socket mode/single instance | required | required | n/a |
| named-pipe first instance | n/a | n/a | required |
| named-pipe user-only DACL | n/a | n/a | release blocker until implemented |
| identity protection | mode `0600` | mode `0600` | user ACL/protection required |
| rename/fsync/recovery | required | required | required with native semantics |

Mobile and iOS are outside the current matrix.

## 8. Documentation conformance

Changes to messages, defaults, limits, states, SQLite schema, daemon JSON, IPC DTOs, or security transcript fields update the relevant numbered specification in the same change. `SPEC.md` is the index; duplicate normative documents point into the set rather than drift.

English comments explain invariants, security boundaries, platform differences, or non-obvious algorithms. Comments that merely translate syntax or preserve obsolete embedded/GUI architecture are removed. Public Rust items receive Rustdoc when their contract is not evident from their type/signature.

## 9. Current status and gaps

The repository has broad subsystem and cross-crate tests, including real QUIC/TCP `frame_io` tests and core transfer end-to-end tests. Remaining incomplete behaviors are:

- Windows pipe DACL and identity-file protection;
- pairing concurrency/per-minute limits and stale-trust GC enforcement;
- configurable QUIC capacity reporting;
- wired preparation progress and reliable cancel-during-preparation;
- active heartbeat/liveness loop;
- normalized persistent timestamp units;
- automatic IPC reconnect and durable event log.

Release notes and clients must not claim these until code and tests exist.

## 10. Release gate

1. Formatting and lints pass with warnings reviewed.
2. Workspace tests pass on supported operating systems.
3. Protobuf generation succeeds from a clean checkout.
4. Supported schema upgrades and crash recovery are tested.
5. Actual QUIC/TCP and native IPC tests pass.
6. Pairing secrets and payload bytes do not appear in logs.
7. Specification links and terminology validate.
8. Two physical LAN hosts pass Wi-Fi interruption/resume smoke tests.
9. Every known gap above has a documented disposition.

A missing platform security boundary makes that platform experimental, not silently production-ready.

## 11. Related specifications

- Index: [../SPEC.md](../SPEC.md)
- Architecture: [00-system-architecture.md](00-system-architecture.md)
- IPC release requirements: [09-daemon-ipc.md](09-daemon-ipc.md)

