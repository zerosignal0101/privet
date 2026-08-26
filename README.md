# Privet

Privet is a local-network, peer-to-peer file and folder transfer engine written in Rust. It discovers peers with mDNS and UDP broadcast, uses QUIC/TLS 1.3 with a TLS-over-TCP fallback, pairs devices with a six-digit SPAKE2 code, pins device public keys, and resumes transfers with BLAKE3-verified chunks.

The workspace contains the protocol, transport, cryptography, security, discovery, storage, transfer, orchestration, local IPC client, and daemon layers. End-user clients communicate with `privetd`; they must not embed `privet-core` or open network/database resources themselves.

See [SPEC.md](SPEC.md) for engine architecture and [IPC_SPEC.md](IPC_SPEC.md) for the daemon/client contract.

Run the daemon with defaults or a JSON configuration:

```sh
cargo run -p privet-daemon --bin privetd
cargo run -p privet-daemon --bin privetd -- --config privet.example.json
```

## Workspace checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The protocol and storage crates run `prost-build`; build machines therefore need `protoc` available unless the build is changed to use a vendored compiler.
