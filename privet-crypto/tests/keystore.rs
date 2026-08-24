use privet_crypto::identity::Identity;
use privet_crypto::keystore::{FileKeyStore, KeyStore};
use tempfile::tempdir;

#[test]
fn identity_roundtrips_through_stored() {
    let id = Identity::generate().unwrap();
    let stored = id.to_stored().unwrap();
    let back = Identity::from_stored(&stored).unwrap();
    assert_eq!(back.spki_der(), id.spki_der());
    assert_eq!(back.cert_der(), id.cert_der());
    assert_eq!(back.fingerprint(), id.fingerprint());
}

#[cfg(unix)]
#[test]
fn file_store_roundtrip_and_overwrite() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("identity.bin");
    let ks = FileKeyStore::new(path.clone());
    let id = Identity::generate().unwrap();
    ks.store(&id.to_stored().unwrap()).unwrap();
    let loaded = ks.load().unwrap().unwrap();
    assert_eq!(loaded.cert_der, id.cert_der());

    let id2 = Identity::generate().unwrap();
    ks.store(&id2.to_stored().unwrap()).unwrap();
    let loaded2 = ks.load().unwrap().unwrap();
    assert_eq!(loaded2.cert_der, id2.cert_der());
}

#[cfg(unix)]
#[test]
fn file_store_missing_returns_none_and_delete_idempotent() {
    let dir = tempdir().unwrap();
    let ks = FileKeyStore::new(dir.path().join("nope.bin"));
    assert!(ks.load().unwrap().is_none());
    ks.delete().unwrap();
}

#[cfg(unix)]
#[test]
fn file_store_perms_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("identity.bin");
    let ks = FileKeyStore::new(path.clone());
    let id = Identity::generate().unwrap();
    ks.store(&id.to_stored().unwrap()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(windows)]
#[test]
fn file_store_roundtrip_and_overwrite_windows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("identity.bin");
    let ks = FileKeyStore::new(path.clone());
    let id = Identity::generate().unwrap();
    ks.store(&id.to_stored().unwrap()).unwrap();
    let loaded = ks.load().unwrap().unwrap();
    assert_eq!(loaded.cert_der, id.cert_der());

    let id2 = Identity::generate().unwrap();
    ks.store(&id2.to_stored().unwrap()).unwrap();
    let loaded2 = ks.load().unwrap().unwrap();
    assert_eq!(loaded2.cert_der, id2.cert_der());
    ks.delete().unwrap();
    assert!(ks.load().unwrap().is_none());
}
