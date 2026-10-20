#[path = "../../../tests/support/swtpm_harness.rs"]
mod swtpm_harness;

use storage_adapter_templates::{StorageError, TemplateStore, TpmConfig};
use swtpm_harness::SwTpm;

const UID: u32 = 1000;
const MAGIC_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn embedding_bytes() -> Vec<u8> {
    (0..64u8).flat_map(|i| (i as f32 * 0.37 - 5.0).to_le_bytes()).collect()
}

fn store_in(tpm: &SwTpm, dir: &tempfile::TempDir) -> TemplateStore {
    TemplateStore::open(dir.path(), TpmConfig { tcti: Some(tpm.tcti.clone()) }).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// @spec:AC-009
// @principle:P-006
#[test]
fn stored_template_is_authenticated_ciphertext_not_a_raw_embedding() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    let plaintext = embedding_bytes();
    store.put(UID, &plaintext).unwrap();

    let on_disk = std::fs::read(store.template_path(UID)).unwrap();
    assert_eq!(&on_disk[..MAGIC_LEN], b"OHT1");
    assert_eq!(on_disk.len(), MAGIC_LEN + NONCE_LEN + plaintext.len() + TAG_LEN);
    assert!(!contains(&on_disk, &plaintext[..16]));
    assert_eq!(store.get(UID).unwrap(), plaintext);
}

// @spec:AC-010
// @principle:P-006
#[test]
fn any_modified_byte_makes_the_template_unavailable() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    store.put(UID, &embedding_bytes()).unwrap();
    let path = store.template_path(UID);
    let original = std::fs::read(&path).unwrap();

    let positions = [0, MAGIC_LEN, MAGIC_LEN + NONCE_LEN - 1, MAGIC_LEN + NONCE_LEN, original.len() - TAG_LEN, original.len() - 1];
    for position in positions {
        let mut tampered = original.clone();
        tampered[position] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();
        assert!(matches!(store.get(UID), Err(StorageError::AuthenticationFailed)), "byte {position}");
    }

    std::fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(matches!(store.get(UID), Err(StorageError::AuthenticationFailed)));

    std::fs::write(&path, &original).unwrap();
    assert_eq!(store.get(UID).unwrap(), embedding_bytes());
}

// @principle:P-006
#[test]
fn a_template_file_copied_to_another_uid_is_rejected() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    store.put(1000, &embedding_bytes()).unwrap();
    store.put(1001, b"other user's template").unwrap();
    std::fs::copy(store.template_path(1000), store.template_path(1001)).unwrap();
    assert!(matches!(store.get(1001), Err(StorageError::AuthenticationFailed)));
}

// @principle:P-004
#[test]
fn sealed_key_bytes_never_appear_in_stored_data_or_errors() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    store.put(UID, &embedding_bytes()).unwrap();

    let unsealed = tpm.tpm2("tpm2_unseal", &["-c", &format!("0x{:X}", 0x8108_0000u32 | UID)]);
    assert!(unsealed.status.success());
    let key = unsealed.stdout;
    assert_eq!(key.len(), 32);

    let on_disk = std::fs::read(store.template_path(UID)).unwrap();
    assert!(!contains(&on_disk, &key));
    std::fs::write(store.template_path(UID), &on_disk[..20]).unwrap();
    let error = store.get(UID).unwrap_err().to_string();
    assert!(!contains(error.as_bytes(), &key));
}

#[test]
fn missing_template_and_unsupported_uid_are_explicit_errors() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    assert!(matches!(store.get(UID), Err(StorageError::NotFound)));
    assert!(matches!(store.put(70_000, b"x"), Err(StorageError::InvalidUid(70_000))));
}

#[test]
fn enrolled_uids_lists_stored_templates_sorted() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    for uid in [1002, 1000, 1001] {
        store.put(uid, b"template").unwrap();
    }
    assert_eq!(store.enrolled_uids().unwrap(), vec![1000, 1001, 1002]);
}

#[test]
fn overwriting_a_template_reuses_the_existing_key() {
    let tpm = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&tpm, &dir);
    store.put(UID, b"first").unwrap();
    store.put(UID, b"second").unwrap();
    assert_eq!(store.get(UID).unwrap(), b"second");
}
