# 07. Storage and Recovery

## 1. Scope

`privet-storage` is the daemon's durable state layer. It stores trust pins, known peer endpoints, transfer history and file records in SQLite, and stores resumable receive state in `.part` files plus protobuf sidecars.

The database is not a public client API. CLI and GUI clients access it only through daemon IPC. Source files being sent and completed destination files remain ordinary filesystem data.

## 2. SQLite operation

The daemon is the sole intended writer. Database initialization enables:

| PRAGMA | Value |
|---|---|
| `journal_mode` | `WAL` |
| `synchronous` | `NORMAL` |
| `busy_timeout` | 5000 ms |
| `foreign_keys` | `ON` |
| `temp_store` | `MEMORY` |

Migrations run transactionally and are tracked by `schema_version`. The current schema version is 2. A database newer than the supported version must be rejected rather than modified speculatively.

Migration v2 (`add-transfer-files-source-path`) adds the nullable `transfer_files.source_path` column for send-side history reconstruction.

## 3. Schema version 1

### 3.1 `trust_store`

Stores the stable peer fingerprint, pinned SPKI, display metadata, trust state, first/last paired timestamps, last-seen timestamp, and revocation information. State checks constrain values to the implemented trust vocabulary.

The fingerprint is the logical peer key. A replacement SPKI under an existing trusted fingerprint is never accepted as an address update; it is a security mismatch.

### 3.2 `known_device_addresses`

Stores address candidates by `(fingerprint, subnet, address)` with distinct QUIC and TCP ports, source, last-seen timestamp, success count, and failure count. Source is constrained to the implemented self-observed/referral vocabulary even though referral exchange is not part of the current product surface.

Upsert refreshes endpoint metadata without collapsing the two transport ports. Success promotes recency and clears or reduces failure state; failure increments it; selection favors recent useful addresses; configured repeated failures permit eviction.

### 3.3 `transfer_history`

Stores transfer ID, direction, peer reference, status, byte/file totals, timestamps, error detail, and serialized send intent. Direction and status are constrained. The peer foreign key uses `SET NULL` so forgetting a peer does not erase audit/history rows. A send intent is mandatory for a send-side row so resend can reconstruct the request.

### 3.4 `transfer_files`

Stores the per-file ID, relative path, size, optional hash type/value, terminal file status, and (since migration v2) the optional `source_path` under a transfer. Rows cascade when their owning transfer is deleted. `source_path` is populated at send completion from the prepared file's absolute path so history detail can reconstruct the source location; it is `NULL` for pre-v2 records and for receives.

## 4. Trust transactions

Pairing commit inserts or updates a trust record atomically after protocol proof succeeds. Revoke preserves the peer record and marks it unusable. Forget deletes active trust/address knowledge while history can remain with a null peer link. Last-seen refresh and stale-record garbage-collection candidate queries are separate operations.

The pairing layer must not expose success before this commit succeeds. An I/O error at commit is a pairing failure.

## 5. History lifecycle

For sending:

1. create a partial history row and persist source intent before preparation;
2. insert prepared file information and totals;
3. update byte/file progress as appropriate;
4. commit exactly one terminal status or a recoverable paused state;
5. use the same transfer ID for resume;
6. create a new ID for resend.

For receiving, history records the offered peer, selected destinations, progress, and verified outcome. Listing is bounded by IPC to 1–1000 records and can be filtered by peer.

`get_history_detail` surfaces one transfer's summary plus its per-file rows (`relative_path`, `source_path`, `size`, `status`). `delete_history_entry` removes a single transfer; its `transfer_files` rows cascade via the foreign key.

History timestamps currently originate from multiple code paths with inconsistent units. Until a schema migration normalizes them, clients must not interpret every numeric timestamp as the same wall-clock unit.

## 6. Receive staging layout

All incomplete receive data stays beneath the save directory:

```text
<save-directory>/.privet/<transfer-id>/<relative-path>.part
<save-directory>/.privet/<transfer-id>/<relative-path>.part.meta
```

Every relative path is validated again at the storage boundary before joining. The guard rejects absolute paths, parent traversal, drive prefixes, NUL, excessive depth, and excessive byte length.

## 7. Sidecar format

The protobuf message `privet.storage.v1.PartMeta` records enough information to validate resume independently of in-memory state:

- transfer ID;
- normalized relative path;
- total file size;
- chunk size;
- expected whole-file hash;
- expected chunk hashes/count;
- verified-chunk bitmask.

The decoder rejects malformed protobuf, mismatched identity/path/size, impossible chunk counts, chunk sizes above 4 MiB, more than 1,048,576 chunks, and inconsistent hash/bitmask lengths.

Sidecar bitmaps are claims, not proof. Resume rehashes bytes present in the `.part` file and clears any bit whose expected chunk cannot be verified.

## 8. Durability and finalization

Staging writes are positional. With the default policy, verified progress is flushed at segment boundaries. Finalization flushes the part file, applies collision policy, renames it to the destination, fsyncs the parent directory where supported, and removes the sidecar.

The rename provides atomic visibility when source and destination are on the same filesystem. Platform filesystem semantics can weaken directory-fsync or overwrite guarantees, and such errors are reported rather than treated as verified success.

## 9. Startup reconciliation

Before accepting work, the engine scans `.privet` staging state. Reconciliation:

- validates sidecars and their corresponding part files;
- deletes orphan `.part` or `.meta` files that cannot form a valid resumable pair;
- removes now-empty staging directories;
- marks partial receive history failed when no recoverable part remains.

The scan is constrained to the configured staging root. It does not search arbitrary user directories or modify completed destination files.

## 10. Concurrency and failure semantics

SQLite transactions protect multi-row invariants. The daemon/core serialize logical ownership even though SQLite is configured to tolerate concurrent readers and bounded writer waits. Filesystem changes and database transactions cannot be one atomic transaction, so startup reconciliation repairs explicitly supported crash windows.

Disk-full, permission, corrupt-sidecar, failed-fsync, failed-rename, and database errors remain visible. No such failure may be rewritten as completion.

## 11. Security

- SQLite and sidecars may contain peer identity, filenames, and transfer history; OS file permissions and full-disk encryption are the at-rest controls.
- The code does not implement application-level database or file encryption.
- Peer-controlled paths and metadata are untrusted at every storage entry point.
- Trust records are security state and must not be edited by CLI/GUI clients outside daemon IPC.

## 12. Verification

Tests cover migrations, schema constraints, trust/address/history CRUD, concurrent access, malformed sidecars, boundary path guards, bitmask revalidation, durability/finalization, orphan reconciliation, and recovery behavior. Core recovery tests verify startup integration.

## 13. Related specifications

- Trust semantics: [03-security-pairing-trust.md](03-security-pairing-trust.md)
- Path and sidecar messages: [01-wire-protocol.md](01-wire-protocol.md)
- Transfer resume behavior: [06-transfer-engine.md](06-transfer-engine.md)
- Daemon ownership: [08-core-orchestration.md](08-core-orchestration.md)
