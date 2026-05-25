# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build all Rust crates
cargo build

# Build specific crate
cargo build -p privet-core
cargo build -p privet-ffi
cargo build -p privet-cli
cargo build --release

# Check compilation (faster than build for validation)
cargo check -p privet-core
cargo check -p privet-ffi
cargo check --workspace

# Run all core tests
cargo test -p privet-core

# Run specific test
cargo test -p privet-core -- known_device::tests::add_and_retrieve_device

# Run integration tests
cargo test -p privet-tests

# Clippy (full workspace, unwrap/expect/panic/todo are denied)
cargo clippy --workspace --all-features

# Rust edition and toolchain
# Built with Rust 1.88.0 (see rust-toolchain.toml), edition 2024
```

## Architecture

See README.md for project overview.

### Workspace Structure

| Crate | Type | Purpose |
|---|---|---|
| `privet-core` | lib | Core engine: QUIC/TCP transport, mDNS/beacon/probe discovery, TLS security, protocol, session management, network awareness, transfer history |
| `privet-ffi` | cdylib+staticlib | C FFI bindings exposing Rust engine to Flutter via `extern "C"`. Event polling queue for Dart isolate |
| `privet-cli` | bin | CLI tool (`privet send`, `privet receive`, `privet pair`) built with clap |
| `privet-tests` | lib | Integration tests (e2e QUIC/TCP transfers, discovery) |
| `privet_app/` | - | Flutter app (Android/iOS/desktop GUI) |

### privet-core Module Map

```
src/
├── lib.rs              # Module declarations, crypto provider init (aws-lc-rs / ring)
├── config.rs           # PrivetConfig, TransportConfig, SecurityConfig, DiscoveryConfig, SecurityMode, CongestionControl
├── engine.rs           # PrivetEngine (orchestrator), PrivetEvent enum (14 variants), PairDecision, SessionMeta
├── peer.rs             # PeerId (UUID newtype), PeerInfo
├── session.rs          # SessionId, TransferSession, FileManifest, FileEntry, FileToSend, ExpansionResult
│                       # FileManifest::from_paths(), FileManifest::from_expanded(), expand_paths() (recursive dir walk)
├── error.rs            # PrivetError hierarchy (10 variants), TransportError, ProtocolError, SecurityError, DiscoveryError
├── network.rs          # NetworkInfo, subnet_from_addr(), detect_current_networks_smart(), default_prefix_len()
├── known_device.rs     # KnownDevice, NetworkEntry, KnownDeviceStore (persistent JSON: device-to-subnet IP mappings)

├── discovery/
│   ├── mod.rs          # DiscoveryManager, DiscoveryEvent (PeerDiscovered/PeerLost)
│   ├── beacon.rs       # UDP broadcast beacon (port 53531), BeaconMessage, 2s interval, self-filter
│   ├── mdns.rs         # mDNS service discovery (_privet._udp.local.) via mdns_sd crate
│   ├── probe.rs        # TCP directed probe for known devices on current subnets
│   └── scanner.rs      # CIDR range subnet scanner (TCP port sweep)

├── security/
│   ├── mod.rs
│   ├── cert.rs         # Self-signed cert generation (rcgen), SHA-256 fingerprint extraction
│   ├── identity.rs     # DeviceIdentity (load/generate cert+key, persist to identity.json)
│   ├── tls.rs          # rustls client/server config builders, mTLS with custom cert verifiers
│   ├── trust.rs        # TrustStore (trusted fingerprints hashset), pairing_code() (symmetric 6-digit)
│   └── accept.rs       # AcceptStore (auto-accept fingerprints, subset of trusted)

├── protocol/
│   ├── mod.rs
│   ├── handshake.rs    # ControlMessage enum (11 variants: Hello/HelloAck/Offer/Accept/Reject/Progress/Pause/Resume/Cancel/Complete/Verified)
│   │                   # FileInfo, FileManifestInfo, serialize/deserialize (postcard), PROTOCOL_VERSION=1
│   ├── control.rs      # QUIC control stream framing: write/read_control_frame (4-byte LE length + payload, 1MB limit)
│   └── data.rs         # StreamHeader, StreamFileEntry, Chunk serialization (postcard), SMALL_FILE_THRESHOLD=64KB

├── transfer/
│   ├── mod.rs
│   ├── sender.rs       # QUIC sender: Hello→HelloAck→Offer→Accept→parallel data streams (max 8 concurrent)→Complete→Verified
│   │                   # File batching (small files grouped ≤16), cancel flag monitoring, resume support
│   ├── receiver.rs     # QUIC receiver: Hello→HelloAck→pairing→Offer→Accept→data streams→Verified
│   │                   # open_file_atomic() (O_CREAT|O_EXCL with (i) dedup), fs_available_space()
│   │                   # build_top_dir_rename_map(), adjust_path() (folder-level dedup)
│   ├── tcp_transport.rs# TCP+TLS fallback: receive_tcp() + send_files_tcp() mirror QUIC protocol
│   │                   # Chunked data transfer, cancel frame detection, graceful TLS shutdown, drain
│   ├── resume.rs       # check_resume() — match incomplete files by name+size+mtime, byte offsets
│   └── progress.rs     # ProgressTracker — EWMA speed calculation (α=0.3, min 100ms interval)

├── transport/
│   ├── mod.rs
│   ├── endpoint.rs     # Quinn endpoint builders, reusable UDP/TCP sockets, transport config (windows, timeouts, CC)
│   ├── quic.rs         # QuicConnection wrapper (open_bi/open_uni/accept_bi/accept_uni/remote_address/local_ip)
│   └── tcp_fallback.rs # TCP framing: 6-byte header (4B length + 2B stream_id), connect_tcp(), write/read_frame

├── storage/
│   ├── mod.rs
│   ├── config_store.rs # ConfigStore — TOML serialization of PrivetConfig
│   └── records.rs      # TransferLog (JSONL append-only), TransferFileRecord, TransferRecord, TransferRecordState
```

### Data Flow

```
Flutter UI ←→ Riverpod Providers ←→ PrivetService ←→ PrivetFfiIsolate (Dart isolate, 50ms poll)
                                                        ↓  [C FFI via dart:ffi]
                                                   privet-ffi (cdylib)
                                                        ↓
                                                   PrivetEngine
                                                     ├── DiscoveryManager (mDNS + beacon + probe)
                                                     ├── Sender/Receiver (QUIC — primary transport)
                                                     ├── TCP fallback (TCP+TLS — when UDP blocked)
                                                     ├── TrustStore / AcceptStore / KnownDeviceStore
                                                     └── TransferLog (JSONL history)
```

### Discovery Strategies

1. **mDNS** — Standard multicast DNS (`_privet._udp.local.`). Works on most home networks.
2. **UDP Beacon** — Broadcast to `255.255.255.255:{beacon_port}`. Alternative when mDNS fails.
3. **TCP Probe** — Directed connection to known device IPs (stored in `known_devices.json`). Used in restricted networks where mDNS/beacon is blocked.
4. **Subnet Scanner** — CIDR range sweep of all IPs on the current subnet for open privet TCP port.

### Protocol Handshake Flow

```
Sender                           Receiver
  │                                │
  ├── Hello (version, name, fp, listen_port) ──►
  │                                │
  ◄── HelloAck (version, fp, name, listen_port) ──┘
  │                                │
  [Trust check / Pairing flow]     │
  │                                │
  ├── Offer (files, total_size) ──►
  │                                │
  ◄── Accept (resume_map) ────────┘
  │                                │
  ├── [Data streams: StreamHeader + Chunks] ──►
  │                                │
  ├── Complete ──────────────────►│
  │                                │
  ◄── Verified ──────────────────┘
  │                                │
  ◄── Cancel (any time) ─────────►│
```

### Security Model

- **Three modes**: `AllowAll` (no trust checks), `TrustRequired` (default, must trust once), `Strict` (must trust + accept each transfer)
- **mTLS**: All communications use mutual TLS with self-signed certs; TLS accepts any cert, app-layer checks fingerprint
- **Fingerprint**: SHA-256 of DER certificate, used for device identity
- **Pairing code**: 6-digit code derived from both parties' fingerprints (symmetric, deterministic)
- **Verification**: TLS certificate fingerprint is compared against protocol Hello fingerprint (MITM protection)
- **Storage**: `identity.json`, `trusted.json`, `accepted.json`, `known_devices.json` in `<cert_dir>/`

### Event System

`PrivetEvent` enum (14 variants) emitted by engine → serialized to `CEvent` → polled by Dart isolate at 50ms → converted to typed events → consumed by Riverpod providers → Flutter UI.

| Event | When |
|---|---|
| `PeerDiscovered` | New peer found via mDNS/beacon |
| `PeerLost` | Peer timed out (30s no beacon) |
| `PairRequest` | Sender needs pairing (peer not trusted) |
| `AwaitingPairing` | Receiver needs pairing decision |
| `IncomingTransfer` | Trusted peer sent an Offer |
| `AwaitingAccept` | Strict mode: user must accept/reject |
| `TransferProgress` | Every chunk received (speed + bytes) |
| `TransferComplete` | All files transferred successfully |
| `TransferFailed` | Error or cancellation |
| `KnownDeviceProbed` | Known device found via probe |
| `NetworkChanged` | Network configuration changed |

### Key Design Decisions

- **No database**: Everything is flat JSON files (identity.json, trusted.json, accepted.json, known_devices.json, transfers.jsonl)
- **Isolate-based FFI**: Rust runs in a background Dart Isolate to avoid blocking the UI thread
- **Polling, not callbacks**: Dart polls for events every 50ms via `privet_poll_event` (avoids NativeCallable crashes on Android)
- **QUIC first, TCP fallback**: Default transport is QUIC (UDP); automatically falls back to TCP+TLS when UDP is blocked. QUIC handshake has configurable timeout (default 5s) to trigger fast fallback.
- **Listen port exchange**: Hello/HelloAck messages carry `listen_port` so peers derive correct listening addresses for known device storage (avoids ephemeral port issues).
- **Folder transfer**: `expand_paths()` recursively walks directories (max depth 256, max 100k files). Empty directories produce `is_dir: true` marker entries. Receiver handles folder-level dedup (renames conflicting top-level folders).
- **Atomic file creation**: `open_file_atomic()` uses `O_CREAT|O_EXCL` to avoid TOCTOU races; appends `(1)`, `(2)` for conflicts.
- **Known devices**: Device-to-network IP mappings for directed probe discovery in restricted networks. Auto-recorded on successful transfers and pairing.
- **Clippy strictness**: `unwrap`, `expect`, `panic`, `unimplemented`, `todo` are all denied as warnings.
