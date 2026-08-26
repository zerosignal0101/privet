# 02 — Cryptography and Device Identity

Status: implemented by `privet-crypto`.

## 1. Scope and non-goals

This crate owns cryptographic primitives and long-term device identity representation. It does not decide whether a peer is trusted, run the full pairing lifecycle, establish sockets, or write trust records.

The implementation does not provide at-rest encryption for received files, SQLCipher, OS keychain integration, hardware-backed keys, identity export/import, or key rotation.

## 2. Primitive inventory

| Purpose | Primitive | Implementation |
| --- | --- | --- |
| Device signing identity | Ed25519 | `ed25519-dalek` and PKCS#8 |
| TLS certificate | self-signed X.509 with Ed25519 key | `rcgen` |
| Fingerprint and content hashes | BLAKE3-256 | `blake3` |
| First-contact PAKE | balanced SPAKE2, Edwards25519 group | `spake2::Ed25519Group` |
| Random nonces/codes | OS randomness | `getrandom` through `random_bytes` |
| Secret-memory wrapper | zeroizing vectors | `zeroize::Zeroizing` |

## 3. Device identity

### 3.1 Generation

`Identity::generate` creates an Ed25519 key pair, serializes the private key as PKCS#8, obtains the DER SubjectPublicKeyInfo, and creates a self-signed certificate with no DNS names. The certificate begins at current UTC time and is valid for 100 years.

The certificate is a transport container for the identity public key. Public Web PKI validation is deliberately not used. Peer authorization occurs by pairing and exact SPKI pinning.

### 3.2 Fingerprint

The device fingerprint is:

```text
lowercase_hex(BLAKE3-256(spki_der))
```

It is therefore 64 ASCII hexadecimal characters. Fingerprints identify trust rows, discovery peers, history peers, and IPC peer arguments. A fingerprint claim MUST be checked against the certificate SPKI during authentication or pairing.

### 3.3 Signing and verification

`Identity::sign` produces an Ed25519 signature. `Identity::verify` parses a peer SPKI and verifies against it. Pairing signs the fixed 32-byte transcript hash, not an ad hoc concatenation of network messages.

### 3.4 Persistence validation

Stored identity material contains PKCS#8 private-key bytes, SPKI DER, and certificate DER. On load, the implementation derives the public key from the private key and rejects the record if it does not equal the stored SPKI. The existing certificate bytes are retained; certificate-to-SPKI consistency is covered by generation tests but is not re-derived during `from_stored`.

## 4. File keystore

`FileKeyStore` serializes `StoredIdentity` with bincode.

On Unix, writes use a sibling temporary file, mode `0600`, `write_all`, `sync_all`, and rename. Load returns `None` for a missing file. Delete is idempotent.

On Windows, the same file serialization and atomic-replace flow is used, but Unix mode bits do not apply. **Current limitation:** Windows identity bytes are not protected with DPAPI and no explicit user-only ACL is installed by this crate. Packaging MUST place the daemon data directory under the current user's protected application-data directory.

On platforms other than Unix and Windows, the file keystore returns `KeyStore` errors.

The daemon supplies `<data_dir>/identity.bin`. An engine with `identity_path=None` creates an ephemeral identity and does not persist it.

## 5. BLAKE3 helpers

- `blake3(data)` returns a 32-byte digest.
- `StreamingHasher` permits incremental whole-file hashing.
- `fingerprint_hex` hashes DER SPKI bytes.
- Transfer code hex-encodes chunk, segment, and file digests.

Segment roots in the current transfer implementation are computed as BLAKE3 over the ASCII concatenation of ordered hexadecimal chunk hashes. This convention is protocol behavior and MUST remain stable for version 1.

## 6. SPAKE2 primitive

### 6.1 Roles and identities

The initiator calls `Spake2::start_a`; the responder calls `start_b`. The password is the pairing code. SPAKE2 identities are the initiator and responder device fingerprint bytes in canonical role order.

### 6.2 Completion

Finishing with the peer SPAKE2 message produces a shared key. The state is single-use; a second `finish` returns `PakeAlreadyFinished`. The shared key is held in `Zeroizing<Vec<u8>>`.

The confirmation tag is:

```text
BLAKE3("privet-pairing-confirmation" || shared_key)
```

The tag, rather than the raw shared key, is included in the signed pairing transcript.

## 7. Transcript hash

The transcript uses tagged, length-delimited fields. Each field contributes:

```text
tag || little_endian_u64(value_length) || value
```

Fields appear in this exact order:

1. protocol version;
2. context string `privet-pairing-v1`;
3. initiator fingerprint;
4. responder fingerprint;
5. initiator SPKI;
6. responder SPKI;
7. initiator SPAKE2 message;
8. responder SPAKE2 message;
9. initiator nonce;
10. responder nonce;
11. TLS exporter;
12. SPAKE2 confirmation tag.

The BLAKE3-256 transcript hash is signed by both device identities. Role canonicalization in `privet-security` ensures both sides produce identical ordering.

## 8. Security invariants

- The device private key MUST never appear in protocol messages, events, logs, SQLite, or IPC.
- The SPAKE2 shared key MUST not leave the PAKE output except for confirmation-tag derivation.
- The TLS exporter MUST be exactly the exporter of the connection on which pairing messages are exchanged.
- A declared pairing SPKI MUST equal the TLS certificate SPKI before its signature is accepted.
- Changing either identity, nonce, SPAKE2 message, exporter, protocol version, or confirmation tag changes the transcript hash.
- Certificate acceptance without the application checks in specification `03` provides encryption only, not peer identity authentication.

## 9. Constants

| Constant | Value |
| --- | --- |
| pairing context | `privet-pairing-v1` |
| default TLS exporter label | `privet-pairing-binding` |
| confirmation label | `privet-pairing-confirmation` |
| nonce length | `16 bytes` |
| exporter length | `32 bytes` |
| certificate validity | `100 years` |
| default code validity | `600 seconds` |
| default failed-code budget | `5` |

## 10. Verification

Tests cover identity uniqueness, signing, incorrect-key rejection, certificate SPKI equality, fingerprint derivation, stored-identity consistency, Unix `0600` permissions, atomic overwrite, Windows file round trip under Windows cfg, SPAKE2 same/different password behavior, single-use state, transcript role ordering, MITM transcript separation, and exporter sensitivity.

## 11. Cross-references

- Pairing lifecycle and commit timing: [03-security-pairing-trust.md](03-security-pairing-trust.md)
- TLS exporter capture: [05-transport.md](05-transport.md)
- Identity construction and daemon ownership: [08-core-orchestration.md](08-core-orchestration.md)
