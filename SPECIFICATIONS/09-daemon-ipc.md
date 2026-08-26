# 09. Daemon and IPC

## 1. Status and purpose

This is IPC protocol version 1, implemented by `privet-ipc` and `privet-daemon`. It is the only supported client boundary for future CLI and Flutter GUI applications.

`privetd` is the only process allowed to instantiate `privet_core::Engine`. It owns the private key, TLS certificate, QUIC/TCP/mDNS/UDP sockets, SQLite connection, receive staging tree, pairing codes, trust decisions, incoming offers, and active transfers. Clients never open these resources or embed the core.

## 2. Local endpoint and access control

IPC is local only and is never exposed on TCP.

### 2.1 Unix

The default Unix-domain socket is selected from `XDG_RUNTIME_DIR`, the platform runtime directory, a cache `run` directory, or a username-scoped temporary fallback, then suffixed with `privet/privet.sock`. The containing directory is mode `0700`; the socket is mode `0600`.

Binding first probes an existing path. A live socket produces `AddrInUse`; an unreachable stale socket is removed. Dropping the listener removes its socket path.

### 2.2 Windows

The default named pipe is `\\.\pipe\privet-user-v1`. The listener requests first-instance ownership; clients retry a busy pipe every 50 ms.

The current Rust implementation does not install an explicit user-only DACL. Production Windows packaging must add one before the daemon IPC boundary can be considered equivalent to Unix `0600` access control.

## 3. Framing

Each IPC message consists of a four-byte unsigned big-endian JSON byte length followed by exactly that many UTF-8 JSON bytes. The maximum JSON size is 1 MiB. Zero-length, oversized, truncated, or invalid JSON frames terminate the affected request/connection. File payload bytes never cross IPC; send requests contain daemon-readable local paths.

## 4. Envelopes and compatibility

```json
{
  "protocol_version": 1,
  "request_id": "2fd58d50-25fe-4f2d-ad78-c42725a3260b",
  "request": { "method": "ping" }
}
```

`request_id` is client-generated; the Rust client uses a UUID. Requests use a `method` tag with optional `params` and reject unknown fields. A server message has `type: "response"` or `type: "event"`. A response repeats the ID and contains exactly one of `payload` and `error`; responses can arrive out of order. An event contains a daemon-session `sequence` and name-tagged event body.

Unsupported protocol versions return `incompatible_protocol`. Adding optional fields can be compatible within version 1; removing or renaming fields, changing enum meaning, or changing framing requires a new version.

## 5. Requests

| Method | Parameters | Successful payload |
|---|---|---|
| `ping` | none | `pong { protocol_version }` |
| `get_status` | none | daemon status |
| `get_identity` | none | public identity |
| `list_peers` / `refresh_peers` | none | peers / ack |
| `list_trusted` | none | trusted/revoked peers |
| `generate_pairing_code` | none | code and validity |
| `pair` | peer selector, code | pairing result |
| `revoke_peer` / `forget_peer` | fingerprint and optional reason | ack |
| `send` | paths, trusted fingerprint, optional root name | queued ID |
| `resume_transfer` | transfer ID | queued same ID |
| `resend_transfer` | historical transfer ID | queued new ID |
| `accept_transfer` | transfer ID, accept boolean | ack |
| `cancel_transfer` / `pause_transfer` / `continue_transfer` | transfer ID | ack |
| `list_history` | optional peer, limit | history list |
| `get_runtime_config` / `set_runtime_config` | none / partial patch | runtime configuration |
| `subscribe_events` | optional sequence cursor | replay window |
| `shutdown` | none | ack flushed before shutdown |

A pairing peer is either `discovered { device_fingerprint }` or `endpoint { ip, quic_port, tcp_port }`. Discovered pairing selects the freshest candidate and preserves both ports. Sending accepts only a trusted fingerprint; arbitrary raw-address sending is intentionally absent.

History limits are clamped to 1–1000. Transfer-starting requests return an ID immediately while work continues asynchronously. An asynchronous failure is delivered as an event and written to history.

## 6. Response data

Implemented response variants are `pong`, `ack`, `status`, `identity`, `peers`, `trusted`, `pairing_code`, `pairing_result`, `transfer_queued`, `transfer`, `history`, `runtime_config`, and `event_replay`.

- Status includes versions, daemon session UUID, fingerprint, bound QUIC/TCP addresses, and active IDs.
- A candidate includes IP, distinct QUIC/TCP ports, and last-seen milliseconds.
- Trust includes fingerprint, name/state, SPKI hex, paired/seen/revoked timestamps, and reason.
- History includes ID, direction, optional peer/name/root, totals, status, and timestamps.
- Replay includes events, optional oldest retained sequence, and latest sequence.

`transfer` exists in the enum but current handlers primarily return `transfer_queued` plus history/events. Clients must not assume it is produced unless a method documents that result.

## 7. Events

| Event | Data |
|---|---|
| `device_discovered` / `device_lost` | fingerprint and optional name |
| `pairing_requested` / `pairing_result` | fingerprint, success, optional error |
| `transfer_preparing` | transfer ID |
| `transfer_preparing_progress` | ID, scanned/total bytes |
| `transfer_offered` | ID, file count, total bytes |
| `transfer_progress` | ID, verified/total bytes |
| `transfer_reconnecting` | ID, attempt, backoff milliseconds |
| `transfer_resumed` / `transfer_paused` | ID and optional reason |
| `transfer_completed` / `transfer_cancelled` | ID |
| `transfer_failed` | ID, error code, retryable, part kept |
| `incoming_connection` | fingerprint |
| `runtime_config_changed` | complete runtime snapshot |
| `daemon_stopping` | none |

The incoming-offer resolver is registered before `transfer_offered` is published, so immediate acceptance cannot beat registration.

## 8. Replay and recovery

The daemon creates a random session UUID, numbers events from 1, retains the latest 1,024 events, and broadcasts live events through a 512-capacity channel. A reconnecting client supplies `after_sequence` and receives retained later events plus `oldest_available` and `latest`.

A gap exists when `after_sequence + 1 < oldest_available`. A changed `session_id` or gap requires refresh of status, peers, trust, history, and runtime configuration. Live forwarding starts on accept, so a live event can overlap replay. Clients deduplicate by `(session_id, sequence)` and apply remaining events in order. Events are advisory; snapshots and SQLite-backed history are authoritative.

## 9. Client/server concurrency

Each server connection has one reader and a bounded serialized writer queue of 128 messages. Request handlers run concurrently. Shutdown acknowledgement includes a writer-flush confirmation before the stop signal.

`IpcClient` has one reader task, a writer mutex, a pending request-ID/oneshot map, a 256-capacity event broadcast, and a configurable call timeout defaulting to 30 seconds. It validates the payload/error invariant and does not reconnect automatically. Transfers continue after every client disconnects.

## 10. Error model

Errors contain stable `code` and diagnostic `message`; clients branch on code only. Core-derived codes include `pairing`, `transfer`, `transport`, `storage`, `crypto`, `discovery`, `not_paired`, `io`, and `internal`. IPC codes include `invalid_request`, `incompatible_protocol`, and `pairing_failed`. Malformed framing terminates the connection; valid request failures return correlated errors.

## 11. Daemon configuration

Strict JSON is loaded through `--config <path>` with optional `--ipc <path>` override. Unknown fields are rejected.

| Field | Default/meaning |
|---|---|
| `device_name` | `privet-device`; non-blank |
| `data_dir` | platform local data plus `privet` |
| `save_dir` | downloads, or data-dir fallback |
| `ipc_endpoint` | platform default |
| `quic_port` / `tcp_port` | `47808` independently |
| `discovery_port` | `47809` |
| `accept_all_trusted` | false |
| `collision_policy` | rename |
| `pairing` | validated `PairingConfig` |

Only `accept_all_trusted`, `collision_policy`, and `save_dir` are live mutable. A successful patch returns the complete snapshot and emits `runtime_config_changed`. Identity/database paths, ports, and pairing parameters require restart.

## 12. CLI and Flutter contract

Clients connect and ping, subscribe locally before snapshots, compare the status session UUID, request replay, refresh snapshots after a session change/gap, then apply deduplicated live events and persist their cursor. Flutter may use generated DTO bindings or a small FFI wrapper around `privet-ipc`; it must not link `privet-core`.

Paths are platform-native strings, ports are unsigned 16-bit values, sequences are unsigned 64-bit values, `_ms` fields are milliseconds, and history `_ts` fields are opaque until storage units are migrated.

## 13. Verification and limitations

Tests cover JSON round trips, partial framing, oversized rejection, multiplexed event/response delivery over a real Unix socket, stale-socket cleanup, and second-daemon rejection. Daemon tests cover configuration defaults and replay.

Release gaps include Windows named-pipe integration/DACL tests, multi-client replay stress, installed-daemon lifecycle tests, and end-to-end CLI/Flutter contracts. There is no automatic reconnect, persistent event log, privilege broker, or remote administration endpoint.

## 14. Related specifications

- Ownership: [00-system-architecture.md](00-system-architecture.md)
- Runtime core: [08-core-orchestration.md](08-core-orchestration.md)
- Test expectations: [10-verification-conformance.md](10-verification-conformance.md)

