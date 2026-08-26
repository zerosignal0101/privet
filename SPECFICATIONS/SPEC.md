# Privet Repository Specification

Status: implementation specification for protocol version 1 and storage schema version 1.

## 1. Product boundary

Privet transfers files and directory trees between exactly two devices on the same LAN. Payload bytes never traverse a relay or external service. Discovery, connection establishment, pairing, transfer, cancellation, resume, and history are local operations.

Supported product surfaces are:

- a long-running daemon that exclusively owns identity keys, listeners, discovery sockets, the SQLite database, and active transfers;
- a CLI that talks to the daemon over local authenticated IPC;
- a Flutter GUI that uses the same IPC contract.

Clients must not link to or instantiate `privet-core::Engine`. There is one engine owner per user profile: the daemon. This prevents duplicate listeners, conflicting database writers, inconsistent pairing-code state, and multiple copies of private key material. Public client SDKs may contain only IPC request/response/event types and IPC connection code.

The Rust workspace implements the engine-side layers, the `privet-ipc` client contract, and the `privet-daemon` engine owner. `privet-core` is an internal daemon orchestration API; its direct use is limited to daemon code and engine integration tests.

## 2. Explicit non-goals

- WAN transfer, NAT traversal, internet rendezvous, or relay services
- accounts, cloud state, or cloud key recovery
- multi-party or multicast transfer
- iOS support in this phase
- encryption of files after they are committed to the destination filesystem
- chat, messaging, continuous synchronization, or anonymous transfer

## 3. Workspace map

| Crate | Responsibility | Must not own |
| --- | --- | --- |
| `privet-protocol` | Protobuf messages, framing, path validation, segment layout | sockets, keys, database |
| `privet-crypto` | Ed25519 identity, SPAKE2 backend, BLAKE3, keystore abstraction | pairing policy, transport |
| `privet-security` | Pairing policy, transcript binding, trust decisions, commit protocol | concrete sockets or SQLite |
| `privet-transport` | QUIC, TLS-over-TCP, logical streams, frame I/O | file semantics or trust decisions |
| `privet-discovery` | mDNS/UDP discovery, beacon validation, peer candidates | trust authority |
| `privet-storage` | SQLite schema, address book, history, staging and sidecars | network orchestration |
| `privet-transfer` | manifests, chunk scheduling, integrity, resume, cancellation | discovery or identity keys |
| `privet-core` | daemon-side assembly and cross-crate workflows | frontend UI behavior |
| `privet-ipc` | versioned DTOs, framing, local endpoint, async client | engine or database access |
| `privet-daemon` | sole engine owner and IPC request/event backend | frontend presentation |

Dependency direction is toward the smaller layers. Frontends depend on `privet-ipc` only; the daemon depends on IPC and `privet-core`.

## 4. Identity and trust model

Each installation has one Ed25519 key pair and a self-signed X.509 certificate. The private key is persisted with owner-only filesystem permissions where the platform supports them. A device fingerprint is derived from the SubjectPublicKeyInfo with BLAKE3.

TLS authenticates and encrypts the transport but initially accepts a self-signed peer certificate. Application security then applies one of these decisions:

1. Unknown fingerprint: require first-time pairing.
2. Trusted fingerprint with identical pinned SPKI: permit a code-free connection.
3. Revoked fingerprint: reject without disclosing revocation state.
4. Trusted fingerprint with a different SPKI: fail closed and emit a key-mismatch alert.

A pairing uses the six-digit code as the balanced SPAKE2 password. Both sides bind their PAKE exchange, nonces, identities, and TLS exporter to a canonical transcript and sign it with their device identity. Trust is committed only after transcript verification. The initiator persists a pending proof and commits after receiving `PairingResultAck`; retries are idempotent.

`PairingConfig` is runtime configuration, not a collection of documentation constants. It controls code lifetime, failed-code budget, rate-limit values, SPAKE2 group validation, TLS exporter label, acknowledgement timeout/retries, and stale-identity policy. It is deserializable with defaults and rejects unknown fields and unsafe zero values. The engine uses the configured code lifetime/attempt budget, exporter label, and acknowledgement behavior. A daemon configuration loader must call `PairingConfig::validate` before starting listeners.

Secrets, pairing codes, PAKE state, exporter bytes, and transcript signatures must never be written to logs or events.

## 5. Discovery

Discovery runs only on LAN interfaces and combines mDNS with UDP beacons/probes. A beacon advertises protocol version, fingerprint, display name, platform, capabilities, and distinct QUIC/TCP listening ports. Received beacons are freshness-checked and replay-resistant.

Candidate selection prefers a recent address on a currently attached subnet. Discovery is advisory: a discovered fingerprint or address is never sufficient for authorization. Authorization always uses the certificate SPKI and trust store after TLS establishment.

Address-book records contain one peer IP plus separate `quic_port` and `tcp_port` values. Connection fallback must preserve this distinction. A verified connection may refresh success metadata; an unverified discovery packet must not be counted as a successful connection.

## 6. Transport and framing

QUIC is preferred and TLS-over-TCP is the fallback. Both use TLS 1.3 and the same device certificate. QUIC uses BBR by default and separate streams so loss on one data stream does not block control or unrelated data streams. TCP exposes one control and one data logical stream through a multiplexed TLS connection.

Control and data protobuf messages use an unsigned LEB128 length prefix. A `ChunkHeader` is followed by exactly `length` raw bytes. Senders must reject a missing, unexpected, or length-mismatched raw chunk before writing, because accepting it would desynchronize every following frame. Receivers enforce size limits before allocation.

Concrete loopback tests must cover `send_control`/`recv_control` and `send_data`/`recv_data` through both QUIC and TLS-over-TCP, in addition to memory-stream unit tests.

Fallback receives two socket addresses: one with the advertised QUIC port and one with the advertised TCP port. Passing one address for both transports is permitted only for explicit legacy `host:port` input where no separate advertisement exists.

## 7. Connection flow

1. Resolve a trusted device to an IP and its two advertised ports, or accept explicit legacy `host:port` input.
2. Try QUIC; on timeout or connection failure, try TCP at the TCP port when policy is `PreferQuic`.
3. Open/accept the control stream and exchange `Hello`/`HelloAck`.
4. Extract peer SPKI and TLS exporter.
5. Apply pinned-key authorization or run pairing.
6. Open/accept data streams only after authorization.
7. Record the verified IP with both advertised ports. Never replace the TCP port with the QUIC port merely because QUIC succeeded.

## 8. Transfer model

A transfer starts with `TransferOffer` and batched file-set metadata. `FileEntry` represents regular files and `DirEntry` represents directories independently, so empty directories and empty subtrees survive transfer. Relative paths pass the protocol path guard before filesystem access.

Files are split into chunks and segments. BLAKE3 hashes authenticate each chunk and segment. The receiver writes into a private staging tree and persists versioned sidecar metadata. Resume reconstructs a verified bitmask by re-reading and hashing staged chunks; it never trusts the sidecar bitmask without verifying bytes. Final paths are committed only after complete verification.

Cancellation is bidirectional and is carried on the control stream. Pause and resume are transfer commands, not process lifecycle operations. Completion requires receiver verification and acknowledgement. A receiver offer remains pending until daemon policy auto-accepts it or an IPC client resolves it.

Directory semantics:

- `FileSetSummary.file_count` counts files only.
- `FileSetSummary.dir_count` counts explicit `DirEntry` records.
- every source directory is emitted, including directories containing no files;
- directory creation occurs under the sanitized destination root;
- file/directory path collisions are rejected or resolved according to configured policy.

## 9. Storage

SQLite schema v1 stores pinned peers, known addresses, transfer history, and per-file history. Foreign keys preserve history when a peer is forgotten by setting the history fingerprint to null while retaining the peer display name.

The daemon is the only database writer. History rows are created as `partial` before expensive source hashing so interrupted preparation remains visible and resumable. Final statuses are `completed`, `cancelled`, `failed`, or `partial`.

Partial bytes and `.part.meta` files live under `<save_dir>/.privet/<transfer_id>/`. Recovery scans only this staging root and must not traverse or mutate arbitrary user directories.

## 10. Daemon IPC contract

The IPC transport is local-only and authenticated by operating-system endpoint permissions. It uses Unix domain sockets on Linux/macOS and named pipes on Windows. No TCP loopback control API is permitted. See `IPC_SPEC.md` for the implemented framing, DTOs, requests, responses, events, replay, and lifecycle behavior.

The versioned IPC surface should provide these operations:

| Area | Requests | Events/results |
| --- | --- | --- |
| lifecycle | status, shutdown | daemon status |
| identity | identity info | public fingerprint/name only |
| discovery | list peers, refresh | discovered, changed, lost |
| pairing | generate code, pair candidate, revoke/forget | pairing started/result, key mismatch |
| transfer | send paths, accept/reject offer, pause/resume/cancel, resend history item | offer, progress, reconnecting, completed, failed |
| history | list/filter/get | immutable snapshots |
| settings | get/update validated runtime settings | settings changed |

Every request has a protocol version and request ID. Mutating requests should accept an idempotency key. Events carry a monotonically increasing daemon-session sequence number so clients can detect gaps and refresh snapshots. IPC messages contain paths and metadata, never file payload bytes; the daemon reads and writes files under the requesting user's authority.

The daemon owns incoming-offer policy. GUI disconnection does not stop transfers. If a decision-requiring client disappears, the offer remains pending until its deadline and is then rejected; it must never silently change to auto-accept.

## 11. Configuration

Configuration is loaded once by the daemon, validated, and then used to construct `EngineConfig`. Runtime-safe settings such as destination directory, collision policy, and trusted-peer auto-accept may be updated through IPC. Listener ports, identity path, PAKE group, and TLS exporter binding require daemon restart.

Unknown configuration keys are errors. Security-sensitive numeric limits must not accept zero. Paths are resolved before daemonization and are not interpreted relative to a GUI process.

## 12. Required verification

Before release, CI must run formatting, clippy with warnings denied, and all workspace targets on Linux, macOS, and Windows. Network tests bind loopback ephemeral ports and must include:

- concrete QUIC and TCP frame-I/O round trips;
- distinct QUIC/TCP fallback ports;
- pairing success, wrong code, expiry, attempt exhaustion, retry exhaustion, and pinned-key mismatch;
- empty directories and empty subtrees;
- cancel from either side;
- interrupted transfer resume with re-hashing and tamper rejection;
- path traversal and file/directory collision rejection;
- history resend and daemon restart recovery;
- IPC authorization and two-client event replay/gap handling once IPC exists.

## 13. Client boundary

The workspace now includes `privet-ipc` and the `privetd` daemon. It does not yet include a product CLI or Flutter UI; both should be built exclusively against the IPC contract. The engine layers are not a supported embedded-client surface.
