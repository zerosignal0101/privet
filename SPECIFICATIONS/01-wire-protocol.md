# 01 — Wire Protocol, Framing, Paths, and Segmentation

Status: implemented by `privet-protocol`; protobuf package `privet.v1`; protocol version 1.

## 1. Scope

This specification defines the peer-visible protobuf schema, byte framing helpers, path grammar, and deterministic segment layout. It does not define socket establishment, authentication policy, transfer scheduling, or filesystem commit behavior.

## 2. Compatibility contract

`PROTO_VERSION` is `1`. `Hello`, `HelloAck`, and `TransferOffer` carry a protocol version. Unknown protobuf fields are tolerated by protobuf semantics. Existing field numbers MUST NOT be reused with a different meaning. Removed fields MUST be reserved. A semantic change that prevents a version-1 peer from completing the same operation requires a version increment.

The current handshake acknowledges `min(local, remote)` and does not implement a separate major/minor version tuple. Version changes must therefore be treated conservatively.

## 3. Message families

### 3.1 Discovery

| Message | Fields and semantics |
| --- | --- |
| `Beacon` | version, full fingerprint, display name, platform, capabilities, QUIC port, TCP port, nonce, millisecond timestamp |
| `Probe` | nonce and millisecond timestamp used to solicit a unicast beacon response |
| `Goodbye` | full device fingerprint used for graceful disappearance |

These messages are discovery hints and MUST NOT authorize a peer.

### 3.2 Connection handshake

`Hello` and `HelloAck` identify the endpoint inside the encrypted channel. Both include version, full fingerprint, device name, platform, and capabilities. `HelloAck` additionally carries `ok` and `error`. The presented certificate SPKI is checked separately by the security layer; a claimed fingerprint alone is insufficient.

### 3.3 Pairing

| Message | Role |
| --- | --- |
| `PairingInit` | initiator fingerprint, identity SPKI, SPAKE2 message, 16-byte nonce |
| `PairingConfirm` | responder fingerprint, SPAKE2 message, transcript signature, nonce |
| `PairingResult` | success/error plus initiator identity SPKI and signature |
| `PairingResultAck` | responder acknowledgement containing the transcript hash |

The acknowledgement closes the asymmetric last-message window: the initiator does not persist trust until it receives the matching hash.

### 3.4 File-set metadata

`TransferOffer` carries only the transfer ID, protocol version, resume capability, and `FileSetSummary`. The summary contains `root_name`, file count, directory count, and total file bytes.

`FileSetBatch` carries repeated `FileEntry` and `DirEntry` records and an `is_last` marker. Directory entries are independent of files and MUST include empty directories when present. Receivers accumulate batches and reject final count or byte-total mismatches.

`FileEntry` contains a transfer-local file ID, sanitized relative path, size, modification time in milliseconds, hash algorithm name, and whole-file hash. `DirEntry` contains only a sanitized relative path.

### 3.5 Integrity and resume

`SegmentManifest` binds one file/segment to its hash algorithm, ordered chunk hashes, and segment hash. `ChunkBitmask` identifies disk-verified chunks in one segment; bit `i` corresponds to segment-local chunk index `i`.

`TransferAccept` carries accept/reject, reason, and resume bitmasks. Field 3 is reserved; receiver-local `save_dir` MUST NOT be sent to the peer.

### 3.6 Data and transfer control

`ChunkHeader` identifies file, segment, segment-local chunk index, absolute file offset, and raw byte length. `InlineFile` embeds data for a small file and repeats its relative path, mtime, hash type, and hash value.

`ControlMessage` wraps `Cancel`, `Pause`, `Resume`, `Heartbeat`, `TransferComplete`, or `TransferVerified`. `ChunkAck` is a separate control-envelope payload containing one or more verified indices.

## 4. Envelopes

`ControlFrame.payload` is a protobuf `oneof` containing handshake, pairing, transfer metadata, acknowledgement, or control messages. `DataFrame.payload` is either `ChunkHeader` or `InlineFile`.

Control and data bytes MUST NOT be decoded as the other envelope type. File payload bytes MUST use data streams; the control stream contains no file bodies.

## 5. Peer-frame encoding

### 5.1 Unsigned LEB128

Frame lengths and TCP logical stream identifiers use unsigned LEB128. Decoding reads at most ten bytes for a `u64`; a tenth byte with bits outside the valid `u64` range is rejected as overflow. Truncated prefixes are rejected as unexpected EOF.

### 5.2 Control frames

```text
unsigned_leb128(protobuf_length) || ControlFrame protobuf bytes
```

The protobuf body MUST be no larger than `MAX_CONTROL_FRAME_BYTES` (4 MiB). The transport receiver checks the length before allocating the body.

### 5.3 Data frames

```text
unsigned_leb128(protobuf_length) || DataFrame protobuf bytes || optional raw bytes
```

If payload is `ChunkHeader`, raw bytes are mandatory and their exact length MUST equal `ChunkHeader.length`. If payload is not `ChunkHeader`, raw bytes MUST be absent. A sender that violates either rule returns `Malformed` without writing a desynchronizing frame.

The transport receive path rejects chunk lengths larger than `DEFAULT_CHUNK_SIZE` before reading raw bytes. An `InlineFile` contains its data inside protobuf and has no trailing raw body.

### 5.4 TCP logical multiplexing

Each write to the TLS-over-TCP connection is wrapped as:

```text
unsigned_leb128(stream_id) || unsigned_leb128(payload_length) || payload
```

Only stream ID `0` (control) and `1` (data) are valid. Invalid identifiers terminate frame decoding. The TCP reader demultiplexes complete logical payloads into bounded channels.

## 6. Path grammar

### 6.1 Relative paths

`sanitize_relative_path` applies these rules:

- input MUST be non-empty and valid UTF-8;
- NUL bytes, leading `/` or `\`, parent component `..`, and drive-letter components such as `C:` are rejected;
- both slash forms are accepted on input and normalized to `/`;
- empty components and `.` are removed;
- the normalized path may contain at most 64 components and 4,096 UTF-8 bytes.

The sender sanitizes during preparation. The receiver and storage layer MUST sanitize again before creating paths or writing persistent history.

### 6.2 Root name

An empty root name means no additional landing directory. A non-empty root name MUST be one component: it may not contain a slash, backslash, NUL, `.`, `..`, or drive-letter form, and it is capped at 4,096 UTF-8 bytes.

### 6.3 Symbolic links

Directory preparation processes entries whose reported type is a regular file or directory. Other entry types, including symbolic links, are not transferred. The current walker does not expose an option to follow symlinks.

## 7. Deterministic segment layout

For a file size `S`, chunk size `C`, and maximum chunks per segment `M`:

```text
total_chunks = ceil(S / C)
segment_count = ceil(total_chunks / M)
segment_offset = first_chunk_index * C
```

Each segment records its ID, file offset, byte length, chunk count, and nominal chunk size. A zero-size file, zero chunk size, or zero segment limit yields no segments. Sender and receiver derive identical boundaries; the wire does not carry a repeated segment layout in `FileEntry`.

With defaults, chunks are 1 MiB and a segment contains at most 1,024 chunks. The last chunk and last segment may be shorter.

## 8. File-set batching invariants

The transfer layer targets 3 MiB of encoded entries per `FileSetBatch`, below the 4 MiB control-frame ceiling. A final batch is always emitted, including for an empty file set. After `is_last=true`, further batches are invalid.

On completion the accumulator MUST verify:

- observed file count equals `summary.file_count`;
- observed directory count equals `summary.dir_count`;
- sum of observed file sizes equals `summary.total_bytes`;
- every path is safe before filesystem use.

## 9. Security properties

- Protobuf framing is not an authentication layer; it is consumed only after transport establishment.
- TLS certificate acceptance is deliberately permissive at the TLS verifier so the application can implement self-signed identity pinning. Specifications `02` and `03` define the mandatory follow-up checks.
- Length checks occur before allocation where the transport has a declared bound.
- Relative paths and root names are untrusted peer input even if the peer is paired.
- Hash algorithm strings currently carry `blake3`; receivers must fail verification rather than silently treating an unknown algorithm as equivalent.

## 10. Constants

| Constant | Current value |
| --- | --- |
| `PROTO_VERSION` | `1` |
| `MAX_CONTROL_FRAME_BYTES` | `4 MiB` |
| `INLINE_FILE_THRESHOLD` | `64 KiB` |
| `DEFAULT_CHUNK_SIZE` | `1 MiB` |
| `SEGMENT_MAX_CHUNKS` | `1,024` |
| `PRIVET_DISCOVERY_PORT` | `47809/UDP` |
| `QUIC_PORT` | `47808/UDP` |
| `TCP_PORT` | `47808/TCP` |
| maximum normalized path depth | `64` |
| maximum normalized path bytes | `4,096` |

QUIC and TCP use the same numeric default port on different transport protocols. They remain independent configuration fields and may differ.

## 11. Verification

Current unit tests cover segment boundaries and total length. Framing behavior is exercised through `privet-transport`, including real QUIC and TCP control/data round trips, oversized control/chunk rejection, and raw-length mismatch rejection. Path safety is exercised heavily through transfer and storage tests.

Required compatibility checks and remaining gaps are consolidated in [10-verification-conformance.md](10-verification-conformance.md).

## 12. Cross-references

- TLS and stream mapping: [05-transport.md](05-transport.md)
- Transfer sequencing and validation: [06-transfer-engine.md](06-transfer-engine.md)
- Staging path enforcement: [07-storage.md](07-storage.md)
