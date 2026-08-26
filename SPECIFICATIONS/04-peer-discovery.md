# 04. Peer Discovery

## 1. Scope

`privet-discovery` finds Privet peers on directly reachable LANs and maintains an advisory, in-memory view of their addresses. It combines mDNS, UDP broadcast/probe traffic, and addresses previously recorded by the daemon. Discovery never establishes trust: every connection is authenticated by the security layer.

WAN discovery, DNS-based rendezvous, NAT traversal, relays, multicast transfer, and manual-IP-only operation are outside this subsystem.

## 2. Ownership and interfaces

- `DiscoveryEngine` owns the UDP socket, mDNS service, periodic tasks, and `PeerStore`.
- The core supplies local identity, advertised ports, capability strings, configuration, and trusted/known-address queries.
- Discovery emits peer observations; the core translates them into engine events and may refresh a trusted peer's last-seen time.
- The store is volatile. Durable addresses and trust records live in `privet-storage`.

An observation identifies a peer by its full fingerprint and may contain several candidate IP addresses. A candidate preserves separate QUIC and TCP ports.

## 3. Configuration

| Setting | Default | Meaning |
|---|---:|---|
| discovery UDP port | `47809` | Tagged beacon, probe, and goodbye datagrams |
| discoverability | `Always` | `Always`, time-limited `Window`, or `TrustedOnly` |
| discovery window | 600 s | Announcement duration in window mode |
| beacon interval | 60 s | Periodic advertisement |
| active probe interval | 10 s | Broadcast probe cadence |
| stale timeout | 180 s | `Live` to `Stale` |
| lost timeout | 300 s | `Stale` to `Lost` |
| configured interfaces | empty | Reserved interface-name filter; currently not applied by the engine |
| active scan | true | Enables periodic probes |
| recent known addresses | 5 | Durable addresses selected for direct probing |
| known-address concurrency | 8 | Maximum simultaneous attempts |
| known-address timeout | 1500 ms | Per-address attempt budget |
| eviction failure count | 5 | Failed durable candidates may be removed |
| automatically record observations | true | Persist useful peer addresses |
| probe known addresses | true | Try durable addresses at startup/refresh |

Internal limits are a 30-second lifecycle sweep, a 30-second beacon TTL, ten accepted datagrams per source IP per ten seconds, and a 256-entry nonce replay cache.

## 4. UDP discovery protocol

Every datagram starts with one tag byte followed by one protobuf message from the peer wire schema:

| Tag | Message | Purpose |
|---:|---|---|
| `1` | `Beacon` | Advertise identity and endpoints |
| `2` | `Probe` | Ask eligible peers to advertise |
| `3` | `Goodbye` | Remove a departing live observation |

A beacon is accepted only when the fingerprint is exactly 64 hexadecimal characters, the nonce is non-empty, and its timestamp is within 30 seconds of the receiver's clock. Rate-limited, replayed, malformed, or stale packets are discarded without changing peer state. The nonce cache prevents repeated processing; it is not an authentication mechanism.

Probe replies are sent only when the local discoverability policy allows announcement and the sender is on a local subnet. A reply targets the sender's IP at the configured discovery port, not the UDP source's ephemeral port.

Broadcast targets include directed broadcasts of enumerated IPv4 interfaces and the limited broadcast address `255.255.255.255`.

## 5. mDNS

The service type is `_privet._udp.local.`. Its service port is the QUIC port. TXT records publish:

- protocol version;
- platform;
- capabilities;
- full public-key fingerprint;
- TCP port.

The normalized instance name is at most 63 bytes. mDNS observations and UDP beacons enter the same peer store and therefore have identical lifecycle semantics.

## 6. Discoverability policy

- `Always` permits advertisements whenever the engine is running.
- `Window` permits them until the configured deadline.
- `TrustedOnly` suppresses general announcements; durable trusted-address probing remains a separate core behavior.

Discovery visibility does not bypass pairing. A visible unknown peer still requires the six-digit pairing procedure.

## 7. Peer lifecycle

The store merges observations by fingerprint and maintains address candidates keyed by IP. Re-observing an IP updates its ports, source, and freshness.

| Current state | Input | Next state |
|---|---|---|
| absent | valid beacon | `Seen` |
| absent | known-address connection succeeds | `Live` |
| `Seen` | address resolved | `Resolved` |
| `Resolved` | connection succeeds | `Live` |
| `Resolved` | connection fails | `Resolved` |
| `Live` | stale timeout | `Stale` |
| `Live` | goodbye or explicit remove | absent |
| `Stale` | beacon or known-address success | `Live` |
| `Stale` | lost timeout | `Lost` |
| `Lost` | beacon or known-address success | `Live` |
| `Lost` | explicit remove | absent |

Candidate selection prefers an address on the same subnet and then the freshest candidate. The fingerprint remains the stable identity; IP addresses and ports are routing hints only.

## 8. Durable-address integration

When enabled, the core reads recently successful addresses from SQLite and probes them directly. A successful connection promotes the peer to `Live` and updates success metadata; failures increment durable failure information and can trigger eviction at the configured threshold. This path allows a paired device to be reached even when its current discovery announcement was missed.

The recorded endpoint must keep the observed QUIC port and TCP port independently. Substituting the discovery port or copying one transport port into the other violates this specification.

## 9. Security and privacy

Discovery packets are unauthenticated and attacker-controlled. Consumers must validate every field, cap memory and work, and treat names, capabilities, ports, and addresses as untrusted. The certificate fingerprint asserted by discovery is checked against the certificate presented by the actual connection and then against the trust store.

Goodbye packets affect only volatile presence. They cannot revoke trust, delete history, or cancel a transfer.

## 10. Verification

Tests cover state transitions, peer merging, subnet preference, beacon validation and expiry, UDP receive behavior, replay/rate behavior, probes, interface information, lifecycle sweeping and stopping, direct known-address connection, injected observations, and loopback discovery. Cross-process tests may use loopback because CI multicast support is not guaranteed.

## 11. Current limitations

- Presence is process-local and is rebuilt after daemon restart.
- Discovery does not prove possession of the advertised key.
- `TrustedOnly` is not a private rendezvous protocol; it merely suppresses general announcements.
- The configured interface-name list is not currently applied; all usable enumerated interfaces contribute broadcast targets.
- Multiple interfaces and restrictive host firewalls can still make a LAN peer undiscoverable; durable address probing is the fallback, not NAT traversal.

## 12. Related specifications

- Wire messages and default ports: [01-wire-protocol.md](01-wire-protocol.md)
- Pinning and pairing: [03-security-pairing-trust.md](03-security-pairing-trust.md)
- Connection attempts: [05-transport.md](05-transport.md)
- Core discovery orchestration: [08-core-orchestration.md](08-core-orchestration.md)
