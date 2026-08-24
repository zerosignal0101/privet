use privet_crypto::pake::{PakeOutput, PakeScheme, Spake2Backend};
use zeroize::Zeroizing;

#[test]
fn same_code_derives_same_key_and_tag() {
    let scheme = Spake2Backend;
    let code = b"123456";
    let fingerprint_a = b"initiator-device-fingerprint";
    let fingerprint_b = b"responder-device-fingerprint";

    let (mut st_i, msg_i) = scheme.start_initiator(code, fingerprint_a, fingerprint_b).unwrap();
    let (mut st_r, msg_r) = scheme.start_responder(code, fingerprint_a, fingerprint_b).unwrap();

    let out_i: PakeOutput = st_i.finish(&msg_r).unwrap();
    let out_r: PakeOutput = st_r.finish(&msg_i).unwrap();

    assert_eq!(out_i.shared_key.as_slice(), out_r.shared_key.as_slice());
    assert_eq!(out_i.confirmation_tag, out_r.confirmation_tag);
    assert!(!out_i.shared_key.is_empty());
}

#[test]
fn different_code_derives_different_key_and_tag() {
    let scheme = Spake2Backend;
    let fingerprint_a = b"a";
    let fingerprint_b = b"b";
    let (mut st_i, msg_i) = scheme.start_initiator(b"111111", fingerprint_a, fingerprint_b).unwrap();
    let (mut st_r, msg_r) = scheme.start_responder(b"222222", fingerprint_a, fingerprint_b).unwrap();

    let out_i = st_i.finish(&msg_r).unwrap();
    let out_r = st_r.finish(&msg_i).unwrap();
    assert_ne!(out_i.shared_key.as_slice(), out_r.shared_key.as_slice());
    assert_ne!(out_i.confirmation_tag, out_r.confirmation_tag);
}

#[test]
fn state_is_single_use() {
    let scheme = Spake2Backend;
    let (mut st_i, msg_i) = scheme.start_initiator(b"code", b"a", b"b").unwrap();
    let (_, msg_r) = scheme.start_responder(b"code", b"a", b"b").unwrap();
    let _ = st_i.finish(&msg_r).unwrap();
    assert!(st_i.finish(&msg_i).is_err());
}

#[test]
fn injectable_trait_allows_fake_backend() {
    struct FakeBackend;
    impl PakeScheme for FakeBackend {
        fn start_initiator(
            &self,
            _p: &[u8],
            _a: &[u8],
            _b: &[u8],
        ) -> Result<(Box<dyn privet_crypto::pake::PakeState>, Vec<u8>), privet_crypto::CryptoError>
        {
            Ok((Box::new(FakeState), vec![0xDE]))
        }
        fn start_responder(
            &self,
            _p: &[u8],
            _a: &[u8],
            _b: &[u8],
        ) -> Result<(Box<dyn privet_crypto::pake::PakeState>, Vec<u8>), privet_crypto::CryptoError>
        {
            Ok((Box::new(FakeState), vec![0xAD]))
        }
    }
    struct FakeState;
    impl privet_crypto::pake::PakeState for FakeState {
        fn finish(&mut self, _peer: &[u8]) -> Result<PakeOutput, privet_crypto::CryptoError> {
            Ok(PakeOutput {
                shared_key: Zeroizing::new(vec![1, 2, 3]),
                confirmation_tag: [9u8; 32],
            })
        }
    }
    let fb = FakeBackend;
    let (mut st, _msg) = fb.start_initiator(b"x", b"a", b"b").unwrap();
    let out = st.finish(&[0xAD]).unwrap();
    assert_eq!(out.shared_key.as_slice(), &[1u8, 2, 3]);
}
