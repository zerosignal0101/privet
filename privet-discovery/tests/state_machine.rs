use privet_discovery::peer::{transition, PeerEvent, PeerState};

#[test]
fn table_driven_transitions() {
    use PeerEvent::*;
    use PeerState::*;
    let cases: Vec<(PeerState, PeerEvent, Option<PeerState>)> = vec![
        (Absent, BeaconRecv, Some(Seen)),
        (Absent, KnownAddrConnectOk, Some(Live)),
        (Seen, AddrResolved, Some(Resolved)),
        (Resolved, ConnectOk, Some(Live)),
        (Resolved, ConnectFail, Some(Resolved)),
        (Live, StaleTimeout, Some(Stale)),
        (Live, GoodbyeBeacon, Some(Absent)),
        (Live, ExplicitRemove, Some(Absent)),
        (Stale, BeaconRecv, Some(Live)),
        (Stale, KnownAddrConnectOk, Some(Live)),
        (Stale, LostTimeout, Some(Lost)),
        (Lost, BeaconRecv, Some(Live)),
        (Lost, ExplicitRemove, Some(Absent)),
        (Absent, StaleTimeout, None),
        (Seen, ConnectOk, None),
    ];
    for (from, ev, expected) in cases {
        assert_eq!(transition(from, ev.clone()), expected, "{from:?} + {ev:?}");
    }
}
