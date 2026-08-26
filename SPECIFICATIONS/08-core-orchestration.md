# 08. Core Orchestration

## 1. Scope

`privet-core` composes identity, discovery, transport, security, transfer, and storage into one daemon-owned engine. It is an internal service layer, not a supported embedded-client API. All user clients must operate through `privet-daemon` and `privet-ipc`.

The core owns cross-crate sequencing: starting discovery after persistent state is available, authenticating every connection, recording verified endpoints, preparing history before transfer, reconnecting, and translating subsystem events.

## 2. Engine construction

Engine construction creates or opens:

- the persistent Ed25519 identity and TLS material;
- QUIC and TCP transport backends;
- the SQLite database and adapters for trust, history, addresses, pairing proof, and receive parts;
- the discovery engine;
- the transfer offer resolver and active transfer registry;
- a 256-capacity broadcast channel for `EngineEvent`;
- runtime policy state.

Construction fails if identity, TLS material, configuration, database migration, or required directories cannot be established. A partially initialized engine is not exposed.

## 3. Lifecycle

`start` performs staging reconciliation and starts discovery unless its port is explicitly zero for tests/disabled operation. It starts event forwarding and periodic work, including trusted-peer last-seen refresh and optional known-address probes. Lifecycle sweeping occurs approximately once per second at the core/event bridge where required.

`shutdown` signals discovery and background work to stop. The daemon separately stops inbound listeners and IPC acceptance, then waits for owned tasks. Shutdown is idempotent at the public service boundary.

## 4. Peer resolution

Clients identify a destination either by explicit endpoint or trusted fingerprint:

- `ByAddr` constructs separate QUIC and TCP endpoints from the supplied address/ports. A legacy single-port form uses that same numeric port for both only because the caller explicitly supplied one port.
- `ByFingerprint` requires a trusted record and selects recent durable addresses, preserving their separate ports.
- A caller-supplied `via` address overrides only the IP while retaining the selected transport ports.

Discovery results are hints. Before an operation continues, the core connects, obtains the certificate, computes its fingerprint/SPKI, and performs trust or pairing authentication.

## 5. Outbound connection authentication

For a normal connection the core:

1. connects using configured transport/fallback behavior;
2. exchanges `Hello`/`HelloAck` and validates protocol compatibility;
3. obtains the peer certificate and TLS exporter;
4. applies the trust decision;
5. fails closed on revoked identity, SPKI mismatch, or claimed/certificate fingerprint mismatch;
6. records the actual successfully connected IP and the peer's advertised QUIC/TCP ports only after verification.

Unknown peers cannot enter the normal trusted operation path. They must use explicit pairing.

## 6. Pairing orchestration

The daemon generates a local code through the core or initiates pairing to a discovered/explicit peer. Core pairing supplies both endpoint ports, role-specific certificate data, nonces, and exporter binding to `privet-security`.

The responder commits the pin before acknowledging success. The initiator stores pending proof and commits after the authenticated result acknowledgement. On success the verified peer endpoint is recorded with distinct QUIC/TCP ports.

Pending initiator proof is stored lazily in core key/value state. Pairing runtime behavior is governed by `PairingConfig`; fields that are only validated but not yet enforced are listed in [03-security-pairing-trust.md](03-security-pairing-trust.md).

## 7. Inbound serving

The core listens on QUIC and TCP simultaneously. Each accepted connection is authenticated before it can pair or transfer. The accept loop uses a short polling timeout so shutdown is observable. A `ServeHandle` owns the shutdown flag and joins listener tasks.

Inbound control traffic is dispatched to pairing or receive handling. An untrusted peer may complete pairing but cannot silently submit an accepted transfer. Trusted incoming offers are either auto-accepted by runtime policy or emitted for explicit IPC acceptance.

## 8. Send, resume, and resend

`send_with_id` permits the daemon to allocate and return a stable UUID before asynchronous work begins. The core persists send intent, prepares the file set, resolves/authenticates the peer, and invokes the transfer sender. It records success, cancellation, pause, or failure and emits corresponding events.

- `resume` reuses an incomplete transfer ID and persisted intent/staging state.
- `resend` reads a completed/failed historical intent and starts a new transfer ID.
- reconnect tries the same verified peer through known endpoints with delays of 1, 2, 4, 8, 16, and 30 seconds.

The active transfer registry carries bounded commands for cancel, pause, and continue. Its command channel capacity is eight. Registration presently occurs after preparation; see the cancellation limitation in [06-transfer-engine.md](06-transfer-engine.md).

## 9. Runtime settings

The mutable runtime snapshot contains:

| Field | Effect |
|---|---|
| `accept_all_trusted` | Automatically accept offers from already trusted peers |
| `collision_policy` | rename, overwrite, or skip destination collisions |
| `save_dir` | Root for received files and `.privet` staging |

Changing `save_dir` creates/validates the directory before publishing the new snapshot. Identity, listen ports, database path, and pairing security parameters are startup configuration and are not live-mutated by this interface.

## 10. Engine events

The event stream includes:

- device discovered and lost;
- pairing requested and pairing result;
- transfer preparing and optional preparation progress;
- transfer offered and progress;
- reconnecting and resumed;
- paused, completed, cancelled, and failed;
- incoming connection.

Events are observations, not a durable command result. A lagged subscriber must refresh peers/history/status through request methods. Daemon IPC adds session and sequence information for replay.

## 11. Error boundaries

The core preserves subsystem error categories and attaches operation context. It must not:

- retry pin mismatches as network failures;
- record an endpoint before certificate/pairing verification;
- declare completion before transfer verification and history commit;
- let discovery bypass trust;
- expose database handles or embedded engine ownership to clients.

Network failures may enter bounded reconnect. Security, path, integrity, configuration, and persistent-state failures fail closed.

## 12. Verification

Tests cover engine construction and identity persistence, TLS material, hello negotiation, peer resolution, discovery wiring, pairing operations/end-to-end pairing, send/serve operations, offer control, recovery scanning, resume intent, reconnection, and real QUIC/TCP transfer end-to-end behavior.

## 13. Current limitations

- Incremental preparation progress is not connected through the main send path.
- Cancel during the pre-registration preparation window is not reliable.
- Pending pairing proof uses a core key/value record rather than a first-class versioned storage table.
- Timestamp units are not yet uniform.
- A complete heartbeat loop is not orchestrated; transport failure/idle handling detects disconnects.

## 14. Related specifications

- Architecture and ownership: [00-system-architecture.md](00-system-architecture.md)
- Discovery: [04-peer-discovery.md](04-peer-discovery.md)
- Transfer: [06-transfer-engine.md](06-transfer-engine.md)
- Storage: [07-storage.md](07-storage.md)
- Daemon IPC: [09-daemon-ipc.md](09-daemon-ipc.md)

