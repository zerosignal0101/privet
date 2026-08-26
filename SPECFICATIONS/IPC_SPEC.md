# Privet IPC and Daemon Specification

Status: protocol version 1, implemented by `privet-ipc` and `privet-daemon`.

## 1. Ownership model

`privetd` is the only process allowed to instantiate `privet_core::Engine`. It owns:

- the Ed25519 private key and TLS certificate;
- QUIC, TCP, mDNS, and UDP sockets;
- the SQLite connection and transfer staging tree;
- pairing-code state, trust decisions, incoming offers, and active transfers.

CLI and GUI processes use `privet_ipc::IpcClient`. They do not open the database, bind discovery/transfer ports, load private keys, or call core operations. This remains true when a client and daemon run in the same executable package.

## 2. Local transport and access control

Linux and macOS use a Unix domain socket. The containing runtime directory is mode `0700` and the socket is mode `0600`. Binding checks whether an existing socket is live before removing a stale path, which also provides single-daemon enforcement.

Windows uses a named pipe at `\\.\pipe\privet-user-v1` and requests first-instance ownership. Production installers must launch the daemon in the interactive user's session and apply a user-only pipe DACL. The Rust transport is structured so that DACL setup can be added without changing the protocol.

IPC is never exposed on TCP. Filesystem or named-pipe permissions are the authentication boundary. Pairing codes, private keys, PAKE state, TLS exporters, and transfer payload bytes are forbidden in IPC logs.

## 3. Framing

Each message is:

1. a four-byte unsigned big-endian JSON length;
2. exactly that many UTF-8 JSON bytes.

The maximum JSON message is 1 MiB. Zero-length and oversized messages close the connection. File payload bytes never travel over IPC; send requests contain filesystem paths for the daemon to read.

## 4. Envelope and compatibility

Every client message contains:

```json
{
  "protocol_version": 1,
  "request_id": "uuid",
  "request": { "method": "ping" }
}
```

Every server message is either a response or event. Responses contain exactly one of `payload` or `error`. Responses may arrive out of order because requests execute concurrently; clients correlate them by `request_id`.

An unsupported `protocol_version` returns `incompatible_protocol`. New optional fields may be added within a protocol version. Renaming/removing fields, changing enum meaning, or altering framing requires a new version. Requests and daemon configuration reject unknown fields to catch client/configuration drift early.

## 5. Requests

| Request | Purpose | Result |
| --- | --- | --- |
| `ping` | connectivity/version check | `pong` |
| `get_status` | daemon version, bound ports, active IDs | daemon status |
| `get_identity` | public local identity | identity |
| `list_peers` / `refresh_peers` | discovery snapshot/refresh | peers / ack |
| `list_trusted` | pinned and revoked peers | trusted peers |
| `generate_pairing_code` | install daemon-owned code | code + validity |
| `pair` | pair a discovered peer or explicit dual-port endpoint | pairing result |
| `revoke_peer` / `forget_peer` | trust administration | ack |
| `send` | send paths to a trusted fingerprint | queued transfer ID |
| `resume_transfer` | resume an interrupted send with the same ID | queued transfer ID |
| `resend_transfer` | create a new send from stored history intent | queued new transfer ID |
| `accept_transfer` | resolve a pending incoming offer | ack |
| `cancel_transfer` / `pause_transfer` / `continue_transfer` | active transfer control | ack |
| `list_history` | bounded history query | history rows |
| `get_runtime_config` / `set_runtime_config` | safe live settings | runtime config |
| `subscribe_events` | recover events after a sequence | replay window |
| `shutdown` | orderly daemon stop | ack |

Pairing by discovered fingerprint selects the most recently observed candidate and preserves distinct QUIC/TCP ports. Sending accepts only a trusted device fingerprint; raw-address sending is intentionally absent from the public IPC surface because it bypasses a useful client-side trust invariant.

Transfer-starting requests return immediately. Their queued ID can be used for cancellation and event correlation while preparation or network I/O continues in the daemon.

## 6. Events and recovery

Each daemon-session event has a monotonically increasing `sequence`. The daemon keeps the latest 1,024 events in memory and broadcasts live events to every connected client. A reconnecting client calls `subscribe_events { after_sequence }` and receives:

- all retained events after the supplied sequence;
- `oldest_available`, allowing it to detect an unrecoverable gap;
- `latest`, its new replay checkpoint.

If the requested next sequence predates `oldest_available`, the client refreshes status, peers, trust, history, and runtime config before applying new live events. Sequence values reset when the daemon restarts. `get_status.session_id` is a random UUID created at daemon startup; a changed session ID invalidates the saved cursor and requires snapshot refresh.

Live delivery begins as soon as the connection is accepted, so an event can appear both in the live channel and a concurrent replay response. Clients keep a highest-applied cursor, discard any event at or below it, and apply the remaining events in sequence order. A replay gap exists when `after_sequence + 1 < oldest_available`.

Events cover discovery, pairing, incoming offers, preparation/progress, reconnect, pause/resume, completion/cancellation/failure, runtime changes, and daemon shutdown. Event delivery is advisory; SQLite history and explicit snapshot requests are authoritative.

The receiver registers an incoming-offer decision before publishing `transfer_offered`. This ordering guarantees that an immediate GUI/CLI `accept_transfer` request cannot arrive before the resolver exists.

## 7. Concurrency and lifecycle

A client connection has one read loop and one serialized write queue. Each request runs in its own daemon task, so a history query or transfer does not block event delivery or control requests. The client library has a single reader task, a request-ID/oneshot map, and a broadcast event channel.

Transfers continue when all clients disconnect. Disconnecting a GUI never cancels a transfer. An unresolved incoming offer times out and is declined according to core policy. Shutdown first emits `daemon_stopping`, stops transfer listeners, shuts down discovery/core tasks, and then stops IPC acceptance.

## 8. Error model

Errors have stable machine-readable `code` and human-readable `message`. Core error codes include `pairing`, `transfer`, `transport`, `storage`, `crypto`, `discovery`, `not_paired`, `io`, and `internal`. IPC-specific codes include `invalid_request`, `incompatible_protocol`, and `pairing_failed`.

Clients branch only on `code`; messages are diagnostic and may change. A malformed/oversized frame terminates the connection because request correlation is no longer trustworthy.

## 9. Runtime configuration

The JSON daemon configuration contains device/data/save paths, listener ports, receive policy, collision policy, and `PairingConfig`. Unknown keys are rejected. Identity path, database path, ports, and pairing cryptographic settings require restart.

The live IPC patch permits only:

- `accept_all_trusted`;
- `collision_policy` (`rename`, `skip`, `overwrite`);
- `save_dir`.

Every successful live patch returns the complete resulting runtime configuration and emits `runtime_config_changed`.

## 10. Client integration

Rust CLI code uses `IpcClient::connect`, calls `call(Request)`, and owns an event subscription from `subscribe()`. A Flutter integration should expose the same DTOs through generated bindings or a small FFI package around `privet-ipc`; it must not wrap `privet-core`.

JSON paths are platform-native strings. Port values are unsigned 16-bit integers. Event sequences are daemon-session-local unsigned 64-bit integers. Fields ending in `_ms` are milliseconds; history `*_ts` values retain the storage schema's integer timestamp representation and clients should treat them as opaque ordering values until a schema-versioned time-unit migration is introduced.

GUI startup sequence:

1. connect and `ping`;
2. subscribe locally before issuing snapshot calls;
3. call `subscribe_events` with the last seen sequence;
4. refresh snapshots if the replay window reports a gap;
5. render status, peers, trust, history, and runtime configuration;
6. process live events and persist the latest sequence for the daemon session.

## 11. Verification matrix

Required IPC tests include framed partial reads/writes, oversized rejection, request JSON compatibility, response correlation under out-of-order completion, event replay/gap detection, two simultaneous clients, stale-socket recovery, live-socket single-instance rejection, offer-event ordering, disconnect without transfer cancellation, and orderly shutdown.

Windows release validation additionally verifies the installed named-pipe DACL from a second user account. Unix validation verifies directory/socket modes and rejection from another UID.
