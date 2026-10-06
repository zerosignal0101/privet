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
| `resolve_address` | `ip`, optional `quic_port`/`tcp_port` | `resolved_address` |
| `generate_pairing_code` | none | code and validity |
| `pair` | peer selector, code | pairing result |
| `revoke_peer` / `forget_peer` | fingerprint and optional reason | ack |
| `send` | paths, trusted fingerprint, optional root name, optional `via` address | queued ID |
| `resume_transfer` | transfer ID, optional source path list | queued same ID |
| `resend_transfer` | historical transfer ID | queued new ID |
| `accept_transfer` | transfer ID, accept boolean | ack |
| `cancel_transfer` / `pause_transfer` / `continue_transfer` | transfer ID | ack |
| `list_history` | optional peer, limit | history list |
| `get_history_detail` | transfer ID | history detail with per-file absolute paths |
| `delete_history` | transfer ID | ack |
| `get_runtime_config` / `set_runtime_config` | none / partial patch | runtime configuration |
| `subscribe_events` | optional sequence cursor | replay window |
| `shutdown` | none | ack flushed before shutdown |

A pairing peer is either `discovered { device_fingerprint }` or `endpoint { ip, quic_port, tcp_port }`. Discovered pairing selects the freshest candidate and preserves both ports. Sending accepts only a trusted fingerprint; arbitrary raw-address sending stays absent. A client holding nothing but an address resolves it first (`resolve_address`) and sends only when the answer is already trusted, so the peer's identity is still pinned by the trust store rather than by where it happens to be dialled.

History limits are clamped to 1–1000. Transfer-starting requests return an ID immediately while work continues asynchronously. An asynchronous failure is delivered as an event and written to history.

## 6. Response data

Implemented response variants are `pong`, `ack`, `status`, `identity`, `peers`, `trusted`, `resolved_address`, `pairing_code`, `pairing_result`, `transfer_queued`, `transfer`, `history`, `history_detail`, `runtime_config`, and `event_replay`.

- Status includes versions, daemon session UUID, fingerprint, bound QUIC/TCP addresses, and active IDs.
- Status also includes `local_addrs`: this device's own dialable interface addresses (`{ ip, quic_port, tcp_port }`), **IPv4 only**, excluding loopback, the wildcard `0.0.0.0`, and links that are not operationally up. The bound addresses above are usually wildcards (`0.0.0.0:47808`) that no peer can dial, so clients show `local_addrs` to let a user read an address off and type it on the other device when discovery is blocked (e.g. campus AP client isolation). IPv6 is excluded deliberately: a host on Wi-Fi and cellular at once enumerates dozens of IPv6 addresses (per-link SLAAC privacy addresses plus link-locals) and the list stops being readable exactly when the user has to read one entry out. The field is additive: absent means empty.
- A candidate includes IP, distinct QUIC/TCP ports, and last-seen milliseconds.
- Trust includes fingerprint, name/state, SPKI hex, paired/seen/revoked timestamps, and reason.
- Trust also includes `addresses`: the endpoints this device has been successfully reached at (pairing, a completed send, or discovery), newest first, as `{ ip, quic_port, tcp_port, last_seen_ms }`. A trusted device that discovery cannot currently see still has these, which is how a client lets a user reuse an address instead of re-typing it. Additive: absent means empty.
- `send` accepts an optional `via`: a bare IPv4 or IPv6 literal (brackets optional) to dial *instead of* the address remembered for the fingerprint. The ports always come from the device record. The fingerprint stays mandatory, so the peer's identity is still pinned by the trust store and `via` only changes where it is reached; pairing it with an unknown fingerprint is an error, and a value carrying a port is an error rather than a silently ignored one. When `via` is given but no address has ever been remembered for the device, the ports fall back to the daemon's own listener configuration instead of failing: a peer paired on one network and dialled on another has a record for the old network, and refusing to dial because of it would make `via` useless in exactly the case it exists for.
- `resume_transfer` accepts an optional `paths` list that replaces the source list recorded in the send intent. It exists because the recorded paths are not guaranteed to still exist when the user asks to resume: a sender may have had to stage a copy of its sources (an Android `content://` document can only be reached through a file the daemon can open), and that staging copy is deleted once the transfer reaches a terminal state — cancellation included — while the history row keeps pointing at it. Without an override the resume rebuilds its file list from the recorded paths and fails on the missing file with a bare `io` error code that names neither the file nor the cause. The transfer ID, the peer target, the chunking and the receiver's partial state are unchanged: this is still the same transfer, so the receiver keeps the chunks it already verified and only the missing ones are sent. Structurally additive — an absent or empty `paths` keeps the previous behaviour exactly. A supplied list must describe the *same* file set the intent recorded, because the receiver is already holding a partial transfer under this ID and would otherwise write bytes into a layout it already believes; a differing root name, an unrecorded relative path, a missing recorded path, or a differing per-file size is refused with an error naming the file that disagrees, and the refusal happens before anything is sent so it changes nothing.
- `resolve_address` dials one address and answers **who is there**, without pairing: `{ found, device_fingerprint, device_name, trusted, quic_port, tcp_port }`. It exists because an address does not identify a device. A peer paired at home and met again on a campus or office network has no remembered address that matches, and is not discoverable there either, yet the transport handshake exchanges identities *before* any pairing code is involved — the same exchange pairing relies on to learn who it is talking to. `trusted` therefore means "the device that answered is already in this trust store", which is what lets a client send by address without asking for a code it has already exchanged. When `quic_port`/`tcp_port` are omitted the daemon dials its own listener ports, which is what a peer built the same way answers on; a client passes them only when the user typed a port. `found: false` is an ordinary answer — nothing answered — not an error, and a silent address costs a bounded timeout. `trusted` is only ever true together with a `device_fingerprint`.
- History includes ID, direction, optional peer/name/root, totals, status, and timestamps.
- History detail (`get_history_detail`) adds per-file `relative_path`, `absolute_path`, `size`, and `status`. `absolute_path` is the send-side source path or the receive-side `save_dir/root/relative` landed path, and is `null` for send records that predate schema v2.
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

