# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build all Rust crates
cargo build

# Build specific crate with release optimizations
cargo build -p privet-core
cargo build -p privet-ffi
cargo build -p privet-cli
cargo build --release

# Check compilation (faster than build for validation)
cargo check -p privet-core
cargo check -p privet-ffi

# Run all Rust tests
cargo test -p privet-core

# Run specific test
cargo test -p privet-core -- known_device::tests::add_and_retrieve_device

# Clippy (full workspace, unwrap/expect/panic/todo are denied)
cargo clippy --workspace --all-features
```

## Architecture

See PRD.md for product requirements document.

### Workspace Structure

| Crate | Purpose |
|---|---|
| `privet-core` | Core engine: QUIC/TCP transport, mDNS/beacon/probe discovery, TLS security, protocol (handshake + data), session management, network awareness |
| `privet-ffi` | C FFI bindings exposing Rust engine to Flutter via `extern "C"` functions. Event polling queue for Dart |
| `privet-cli` | CLI tool (`privet send`, `privet receive`, `privet pair`) built with clap |
| `privet-tests` | Integration tests |
| `privet_app/` | Flutter app (Android/iOS/desktop GUI) |

### privet-core Module Map

```
src/
├── lib.rs              # Re-exports, init() (crypto provider setup)
├── config.rs           # PrivetConfig, TransportConfig, SecurityConfig, DiscoveryConfig
├── engine.rs           # PrivetEngine (orchestrator), PrivetEvent enum, PairDecision
├── peer.rs             # PeerId, PeerInfo
├── session.rs          # SessionId, TransferSession, TransferProgress, FileManifest
├── error.rs            # PrivetError hierarchy
├── network.rs          # Network detection, subnet calculation
├── known_device.rs     # KnownDeviceStore (persistent device-to-network IP mappings)
├── discovery/
│   ├── mod.rs          # DiscoveryManager (orchestrates beacon + mDNS)
│   ├── beacon.rs       # UDP broadcast beacon (port 53531)
│   ├── mdns.rs         # mDNS service discovery (_privet._udp.local.)
│   ├── probe.rs        # TCP directed probe for known devices
│   └── scanner.rs      # Subnet scanner (CIDR range IP sweep)
├── security/
│   ├── mod.rs
│   ├── cert.rs         # Self-signed cert generation, fingerprinting
│   ├── identity.rs     # DeviceIdentity (load/generate cert + key)
│   ├── tls.rs          # TLS client/server config builders, mTLS
│   ├── trust.rs        # TrustStore (trusted fingerprints, pairing codes)
│   └── accept.rs       # AcceptStore (auto-accept fingerprints)
├── protocol/
│   ├── mod.rs
│   ├── handshake.rs    # ControlMessage enum: Hello, Offer, Accept, Reject, etc.
│   └── data.rs         # StreamHeader, Chunk serialization
├── transfer/
│   ├── mod.rs
│   ├── sender.rs       # Send files via QUIC (paths → streams)
│   ├── receiver.rs     # Receive files via QUIC (streams → files)
│   ├── tcp_transport.rs# TCP+TLS fallback sender/receiver
│   └── resume.rs       # Resume map logic (byte offsets per file)
├── transport/
│   ├── mod.rs
│   ├── endpoint.rs     # QUIC endpoint builder (client + server)
│   └── tcp_fallback.rs # TCP socket connect helper
├── storage/
│   ├── mod.rs
│   └── records.rs      # TransferLog (JSONL transfer history)
```

### Data Flow

```
Flutter UI ←→ PrivetService ←→ FFI Isolate ←→ [C FFI] ←→ PrivetEngine
                                                            ├── DiscoveryManager (mDNS + beacon)
                                                            ├── probe::probe_known_devices() (TCP)
                                                            ├── Sender/Receiver (QUIC)
                                                            └── tcp_transport (TCP+TLS fallback)
```

### Discovery Strategies

1. **mDNS** — Standard multicast DNS (`_privet._udp.local.`). Works on most home networks.
2. **UDP Beacon** — Broadcast to `255.255.255.255:53531`. Alternative when mDNS fails.
3. **TCP Probe** — Directed connection to known device IPs (stored in `known_devices.json`). Used in restricted networks where mDNS/beacon is blocked.

### Security Model

- **Three modes**: `AllowAll`, `TrustRequired` (default), `Strict`
- **mTLS**: All communications use mutual TLS with self-signed certs
- **Fingerprint**: SHA-256 of DER certificate, used for device identity
- **Pairing code**: 6-digit code derived from both parties' fingerprints (symmetric)
- **Storage**: `trusted.json`, `accepted.json`, `known_devices.json` in `<cert_dir>/`

### Event System

`PrivetEvent` enum emitted by engine → serialized to CEvent → polled by Dart isolate → converted to typed events → consumed by Riverpod providers → Flutter UI.

Key event types: PeerDiscovered, PeerLost, PairRequest, TransferProgress, IncomingTransfer, KnownDeviceProbed, NetworkChanged.

### Key Design Decisions

- **No database**: Everything is flat JSON files (identity.json, trusted.json, accepted.json, known_devices.json, transfers.jsonl)
- **Isolate-based FFI**: Rust runs in a background Dart Isolate to avoid blocking the UI thread
- **Polling, not callbacks**: Dart polls for events every 50ms via `privet_poll_event` (avoids NativeCallable crashes on Android)
- **QUIC first, TCP fallback**: Default transport is QUIC (UDP); auto-falls back to TCP+TLS when UDP is blocked
- **Clippy strictness**: `unwrap`, `expect`, `panic`, `unimplemented`, `todo` are all denied as warnings
