# 05. Transport

## 1. Scope

`privet-transport` provides encrypted, framed, point-to-point connections over QUIC and TLS-over-TCP. The two backends implement common `Transport`, `Listener`, `Connection`, and `Stream` abstractions so pairing and transfer code do not depend on a concrete socket implementation.

Transport authenticates encryption endpoints cryptographically but deliberately accepts Privet's self-signed certificates. Application-level certificate pinning in `privet-security` is therefore mandatory.

## 2. Modes and endpoints

| Mode | Behavior |
|---|---|
| `Quic` | Use only the peer's QUIC endpoint |
| `Tcp` | Use only the peer's TCP endpoint |
| `PreferQuic` | Try QUIC for up to 3 seconds, then use TCP |

The fallback operation receives distinct `SocketAddr` values for QUIC and TCP. The ports may have the same default number (`47808`) but are not interchangeable. Discovery, pairing, and durable address records must preserve both.

Default configuration uses `PreferQuic`, an idle timeout of 120 seconds, eight requested data streams, BBR congestion control, and the pairing exporter label defined by the security configuration.

## 3. Common connection contract

A connection exposes:

- one bidirectional control stream;
- one or more data streams, subject to backend capacity;
- the peer certificate bytes;
- a 32-byte TLS exporter value for pairing channel binding;
- local and remote socket addresses;
- explicit close with normal, application, or error semantics.

All backends must enforce the wire framing rules in [01-wire-protocol.md](01-wire-protocol.md). A control message exceeding 4 MiB, a chunk whose raw byte count differs from its header, or a data receive request exceeding 1 MiB fails closed.

## 4. QUIC backend

The QUIC backend uses Quinn with rustls TLS 1.3:

- the first bidirectional stream carries control traffic;
- unidirectional streams carry chunk data;
- the control sender receives higher scheduling priority;
- BBR is selected by default; CUBIC is a supported configuration;
- the transport requests the configured bidirectional/unidirectional stream limits;
- the connection exports pairing keying material and exposes the peer certificate.

QUIC avoids cross-stream head-of-line blocking and permits concurrent data streams. The current public capacity report is fixed at eight streams; changing the configured stream count does not yet change that reported value.

The implementation does not specify or rely on QUIC 0-RTT. Protocol operations begin after the connection is established and certificate information is available.

## 5. TCP backend

The TCP backend runs rustls over one TCP connection. It emulates logical streams by prefixing multiplexed frames with a stream identifier:

| Stream ID | Meaning |
|---:|---|
| `0` | control frames |
| `1` | data frames |

A reader task demultiplexes validated frames into bounded channels. Writes share a mutex so complete frames cannot interleave. TCP reports a maximum of one data stream. Keepalive is configured for 30 seconds where supported.

Because every logical stream shares one ordered TCP byte stream, packet loss can block control and data behind earlier bytes. The fallback preserves functionality and encryption, not QUIC's loss behavior.

## 6. TLS and certificate verification boundary

Each device presents the self-signed certificate derived from its persistent Ed25519 identity. The TLS verifiers accept Privet self-signed certificates and supported signatures rather than a Web PKI chain. The client uses the internal server name `privet`; it is not a DNS identity assertion.

After TLS/QUIC establishment, the security layer:

1. parses the peer certificate;
2. computes and compares its fingerprint;
3. checks a trusted SPKI pin or enters pairing;
4. binds pairing to the TLS exporter.

Treating successful TLS setup alone as peer authentication is a security defect.

## 7. Framing behavior

Control frames use unsigned LEB128 length followed by protobuf bytes. Data frames use a length-delimited `ChunkHeader` followed by exactly `data_len` raw bytes. Reads are incremental and therefore tolerate fragmented socket reads. Writes must serialize one complete logical frame.

Unexpected EOF, malformed varints, protobuf decoding errors, oversized declarations, length mismatch, exporter failure, and socket errors are propagated as transport errors; they are never converted into successful empty frames.

## 8. Backpressure and closure

Both backends use bounded queues or protocol-level flow control. Senders must await capacity instead of accumulating unbounded frames. Closing a connection terminates pending stream work, and higher layers decide whether the transfer is cancellable, reconnectable, or failed.

Heartbeat constants exist for a 15-second interval and three missed heartbeats, but the current engine does not run a complete transport heartbeat/liveness protocol. Idle timeout, I/O failure, and transfer control currently drive disconnect detection.

## 9. Verification

The transport test suite covers:

- partial and oversized frame handling;
- QUIC and TCP loopback control/data parity;
- real-socket `frame_io` operation on both QUIC and TCP;
- raw chunk-length mismatch rejection;
- exporter and peer-certificate availability;
- QUIC client configuration and control priority;
- TCP keepalive configuration;
- fallback selection and error behavior.

These tests use actual loopback QUIC and TLS/TCP connections where backend behavior matters; in-memory duplex tests remain appropriate for parser edge cases.

## 10. Current limitations

- TCP has one data lane and retains transport-wide head-of-line blocking.
- QUIC's reported stream capacity is currently a constant rather than the configured value.
- BBR selection is an implementation configuration, not a throughput guarantee.
- The standalone heartbeat constants are not yet an end-to-end liveness feature.
- Self-signed TLS requires the application pinning step; third-party use of this transport API without that step would be unsafe.

## 11. Related specifications

- Framing and messages: [01-wire-protocol.md](01-wire-protocol.md)
- Identity certificates: [02-cryptography-identity.md](02-cryptography-identity.md)
- Authentication boundary: [03-security-pairing-trust.md](03-security-pairing-trust.md)
- Transfer stream use: [06-transfer-engine.md](06-transfer-engine.md)

