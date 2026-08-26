# 06. Transfer Engine

## 1. Scope

`privet-transfer` prepares, offers, sends, receives, verifies, pauses, resumes, cancels, and completes one-to-one file and directory transfers. It preserves relative directory structure, including empty directories and empty subtrees, and verifies resumable chunks with BLAKE3.

Continuous synchronization, deletion propagation, symlink transfer, filesystem metadata cloning, multi-peer broadcast, cloud storage, and at-rest encryption are not implemented.

## 2. Configuration and limits

| Setting | Default |
|---|---:|
| inline-file threshold | 64 KiB |
| chunk size | 1 MiB |
| chunks per segment | 1024 |
| requested stream pool | 8 |
| in-flight chunks per stream | 4 |
| chunk ACK interval | 16 chunks |
| ACK base interval | 500 ms |
| retransmission timeout | 2 s |
| chunk retry maximum | 5 |
| fsync after each segment | true |
| collision policy | rename |
| default save directory | `.` |

Hard limits include one active transfer per peer, 1,048,576 file entries, 32 total in-flight chunks, six reconnect attempts, and a target encoded file-set batch size of 3 MiB.

## 3. Transfer identity and inputs

Each transfer has a UUID. A send intent records source paths and the target peer before preparation, allowing history and later resend. `resume` continues an incomplete transfer under the same ID; `resend` creates a new transfer ID from a historical send intent.

Preparation accepts files and directories. It rejects unsafe relative paths through the protocol path rules, ignores symbolic links and unsupported filesystem object types, and emits:

- `FileEntry` for each regular file;
- `DirEntry` for each directory, including empty directories;
- file size, whole-file BLAKE3 hash, and per-chunk BLAKE3 hashes;
- inline bytes for eligible small files.

The `root` field is empty for an unwrapped file set and otherwise contains one legal path component.

## 4. Preparation and offer

The sender prepares a `FileSetSummary`, emits `FileSetBatch` messages close to the 3 MiB target, and always sends a final batch. The receiver can therefore bound individual control messages while reconstructing a large manifest.

The sender registers its offer waiter before emitting the public offered event, preventing an immediate UI acceptance from racing registration. Offer resolution has a 30-second timeout. A runtime policy may automatically accept trusted peers; otherwise a client must call the daemon accept operation.

The core currently emits a general `TransferPreparing` event before synchronous preparation. A detailed `TransferPreparingProgress` event type and streaming preparation helper exist and are unit-tested, but the main send path does not yet wire incremental preparation progress through IPC.

## 5. State model

The vocabulary is:

- `Preparing`
- `Offered`
- `Scheduled`
- `Transferring`
- `SendingDone`
- `Verified { ok }`
- `Completed`
- `VerifyFailed`
- `Cancelled`
- `Paused { User | DiskFull | PermissionBlocked | ReconnectExhausted }`
- `Reconnecting`
- `Failed`

Terminal outcomes are completed, verify-failed, cancelled, and failed. The state transition guard rejects illegal regressions. Reconnection and pause are recoverable states only while the persisted staging data and source intent remain valid.

## 6. Sender protocol

After acceptance, the sender:

1. applies the receiver's chunk bitmasks for resume;
2. sends inline files directly or sends a `SegmentManifest` before related chunks;
3. distributes missing chunks across the available stream pool;
4. tracks at most 32 chunks globally and four per stream;
5. processes cumulative/selective chunk acknowledgements;
6. retransmits expired chunks after the RTO;
7. fails closed after five failed attempts;
8. sends `TransferComplete` after all required bytes are acknowledged;
9. waits for `TransferVerified` before declaring success.

A segment root is BLAKE3 over the concatenation of the ASCII hexadecimal chunk hashes in that segment. It protects manifest consistency; every received chunk is also checked directly.

## 7. Receiver protocol

The receiver accumulates file-set batches and validates paths and limits before creating destinations. A chunk may arrive before its manifest and is held only in bounded pending state until verification information is available.

For each non-inline file, the receiver writes into a staging `.part` file using positional writes, records verified chunks in the sidecar bitmask, and sends acknowledgements. On completion it:

1. verifies every required chunk is present;
2. verifies the complete file hash;
3. flushes the part file;
4. atomically renames it to the selected destination where supported;
5. fsyncs the parent directory;
6. removes its sidecar;
7. creates all declared empty directories;
8. returns `TransferVerified` with success or failure.

Inline files are still subject to path, length, and whole-file hash validation.

## 8. Resume

Sidecars identify the transfer, relative path, expected size, chunk size, expected hashes, and completion bitmask. Resume never trusts the bitmask alone: existing bytes are re-read and hashed against expected chunks before the advertised `ChunkBitmask` is built. Invalid bits are cleared and missing/corrupt chunks are requested again.

Sidecar inputs are capped at 4 MiB chunk size and 1,048,576 chunks. A mismatched transfer identity, path, size, hash count, malformed protobuf, or impossible bitmask fails closed.

Reconnection uses delays of 1, 2, 4, 8, 16, and 30 seconds. After six unsuccessful attempts the transfer pauses with `ReconnectExhausted`; explicit resume can try again.

## 9. Collision policy

| Policy | Receiver behavior |
|---|---|
| rename | choose a non-conflicting destination name |
| overwrite | replace the existing destination during finalization |
| skip | do not replace the existing destination |

Collision resolution occurs beneath the configured save directory after path validation. No peer-supplied path may escape that root.

## 10. Pause and cancellation

Either endpoint may send pause, resume, or cancel control messages. Pause stops scheduling new work but already in-flight frames can complete. Cancellation is terminal and keeps recoverable staging data when appropriate; it does not silently report completion.

The daemon returns a transfer ID immediately after queueing a send. The active command registration currently occurs after preparation, so a cancellation issued in the narrow preparation window may report that no active transfer exists. This is a known implementation gap, not guaranteed cancel-during-preparation behavior.

## 11. Progress and history integration

Progress events include transfer ID, file/byte totals, completed counts, and current state. Durable history is owned by the core/storage layers: a partial row exists before potentially long preparation, file details are committed after preparation, and terminal status is recorded at completion or failure.

Timestamps exposed by the current implementation are not consistently normalized to one unit across all records; IPC consumers must treat them as opaque ordering values until schema normalization is implemented.

## 12. Robustness requirements

- Never write a peer path before validating and joining it under the save root.
- Never mark a chunk present before its BLAKE3 hash matches.
- Never mark a transfer completed before full-file verification and peer verification acknowledgement.
- Bound pending chunks, manifests, queues, retry counts, file counts, path lengths, and frame sizes.
- Treat source mutation during preparation/send as failure; do not construct a mixed-version file silently.
- Preserve enough staging information for a safe retry when the configured outcome is resumable.

## 13. Verification

Tests cover file-set preparation and empty directories, batching, tamper cleanup, bitmasks and integrity, fail-closed verification, sender/receiver happy paths, acknowledgements, RTO and retry, backpressure, stream pools, throttled/deadlock behavior, cancellation, pause/reconnect, resume reconstruction, collision policies, manifest ordering, state/progress rules, part stores, and transport adaptation. Core end-to-end tests exercise real QUIC and TCP transfers.

## 14. Related specifications

- Transfer protobuf and path grammar: [01-wire-protocol.md](01-wire-protocol.md)
- Encrypted streams: [05-transport.md](05-transport.md)
- Staging and history: [07-storage.md](07-storage.md)
- Core lifecycle and reconnection: [08-core-orchestration.md](08-core-orchestration.md)

