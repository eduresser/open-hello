mod support;

use openhello_keyd::{KeyAttribute, KeyInfo, Keyd, KeydError, Secret};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig};

const SECRET: &str = "6f1d0c5a9e3b7d2480ac1f5e6b9d3a7c21e4f08b";
const OTHER_SECRET: &str = "00112233445566778899aabbccddeeff00112233";
const DIGEST: [u8; 32] = [0x5a; 32];

fn secret(value: &str) -> Secret {
    Secret::new(value).unwrap()
}

fn keyd(rig: &Rig) -> Keyd {
    Keyd::new(rig.config.clone())
}

fn verifies(key: &KeyInfo, signature: &[u8]) -> bool {
    let verifying =
        VerifyingKey::from_sec1_bytes(&key.public_key).expect("public key is a P-256 point");
    let signature = Signature::from_slice(signature).expect("raw r||s signature");
    verifying.verify_prehash(&DIGEST, &signature).is_ok()
}

// @spec:AC-016
#[test]
fn provisioning_creates_one_non_exportable_p256_signing_key() {
    let rig = rig();
    let keyd = keyd(&rig);
    let provisioned = keyd.provision(1000, &secret(SECRET)).unwrap();
    let key = &provisioned.key;

    assert!(provisioned.created);
    assert_eq!(key.public_key.len(), 65);
    assert_eq!(key.public_key[0], 0x04);
    assert!(key.tpm.fixed_tpm && key.tpm.fixed_parent && key.tpm.sensitive_data_origin);
    assert!(key.tpm.sign && !key.tpm.decrypt && !key.tpm.restricted);
    assert!(!key.extractable && key.sensitive);

    let mut classes = rig.listed_classes("openhello-1000");
    classes.sort();
    assert_eq!(
        classes,
        ["CKO_CERTIFICATE", "CKO_PRIVATE_KEY", "CKO_PUBLIC_KEY"]
    );

    let signature = keyd.sign_digest(1000, &secret(SECRET), &DIGEST).unwrap();
    assert_eq!(signature.len(), 64);
    assert!(verifies(key, &signature));
}

// @spec:AC-016
#[test]
fn each_user_gets_a_separate_key() {
    let rig = rig();
    let keyd = keyd(&rig);
    let first = keyd.provision(1001, &secret(SECRET)).unwrap().key;
    let second = keyd.provision(1002, &secret(OTHER_SECRET)).unwrap().key;
    assert_ne!(first.handle, second.handle);
    assert_ne!(first.public_key, second.public_key);
    assert_eq!(rig.listed_classes("openhello-1002").len(), 3);
    let signature = keyd
        .sign_digest(1002, &secret(OTHER_SECRET), &DIGEST)
        .unwrap();
    assert!(verifies(&second, &signature));
    assert!(!verifies(&first, &signature));
}

// @spec:AC-017
#[test]
fn provisioning_twice_keeps_the_same_key() {
    let rig = rig();
    let keyd = keyd(&rig);
    let first = keyd.provision(1003, &secret(SECRET)).unwrap();
    let again = keyd.provision(1003, &secret(OTHER_SECRET)).unwrap();

    assert!(first.created && !again.created);
    assert_eq!(first.key, again.key);
    assert_eq!(keyd.key(1003).unwrap(), first.key);
    assert_eq!(rig.listed_classes("openhello-1003").len(), 3);
    let signature = keyd.sign_digest(1003, &secret(SECRET), &DIGEST).unwrap();
    assert!(verifies(&first.key, &signature));
    assert!(matches!(
        keyd.sign_digest(1003, &secret(OTHER_SECRET), &DIGEST),
        Err(KeydError::AuthenticationFailed)
    ));
}

// @spec:AC-018
// @principle:P-004
#[test]
fn private_key_value_is_refused_and_only_signing_is_offered() {
    let rig = rig();
    let keyd = keyd(&rig);
    keyd.provision(1004, &secret(SECRET)).unwrap();

    assert!(matches!(
        keyd.attribute(1004, KeyAttribute::Value),
        Err(KeydError::Refused)
    ));
    assert!(!keyd.attribute(1004, KeyAttribute::Extractable).unwrap());
    assert!(keyd.attribute(1004, KeyAttribute::Sensitive).unwrap());
    assert!(keyd.attribute(1004, KeyAttribute::Sign).unwrap());
    keyd.verify_protection(1004, &secret(SECRET)).unwrap();
    assert!(matches!(
        keyd.verify_protection(1004, &secret(OTHER_SECRET)),
        Err(KeydError::AuthenticationFailed)
    ));
}

// @principle:P-004
#[test]
fn outputs_and_errors_never_carry_secrets_key_blobs_or_paths() {
    let rig = rig();
    let keyd = keyd(&rig);
    let provisioned = keyd.provision(1005, &secret(SECRET)).unwrap();
    let wrong = keyd
        .sign_digest(1005, &secret(OTHER_SECRET), &DIGEST)
        .unwrap_err();
    let missing = keyd
        .sign_digest(1007, &secret(SECRET), &DIGEST)
        .unwrap_err();
    let refused = keyd.attribute(1005, KeyAttribute::Value).unwrap_err();
    let signature = keyd.sign_digest(1005, &secret(SECRET), &DIGEST).unwrap();

    let mut broken = rig.config.clone();
    broken.prefix = Some("/nonexistent/openhello-prefix".into());
    let unavailable = Keyd::new(broken).key(1005).unwrap_err();

    let store = std::fs::read(rig.config.store_dir.join("tpm2_pkcs11.sqlite3")).unwrap();
    let store_text = String::from_utf8_lossy(&store);
    assert!(
        !store_text.contains(SECRET),
        "the user secret is stored only through the token's wrapping"
    );

    let shown = format!(
        "{provisioned:?} {wrong} {wrong:?} {missing} {refused} {unavailable} {unavailable:?} {:?}",
        secret(SECRET)
    );
    let store_dir = rig.config.store_dir.display().to_string();
    for forbidden in [
        SECRET,
        OTHER_SECRET,
        store_dir.as_str(),
        "/nonexistent",
        "tpm2_ptool",
        "libtpm2_pkcs11",
    ] {
        assert!(!shown.contains(forbidden), "output leaks {forbidden}");
    }
    assert!(matches!(unavailable, KeydError::Tpm));
    assert_eq!(unavailable.to_string(), "TPM operation failed");
    assert!(!String::from_utf8_lossy(&signature).contains(SECRET));
}

#[test]
fn invalid_input_and_unprovisioned_users_are_explicit_errors() {
    let rig = rig();
    let keyd = keyd(&rig);
    assert!(matches!(
        keyd.provision(70_000, &secret(SECRET)),
        Err(KeydError::InvalidUid(70_000))
    ));
    assert!(matches!(keyd.key(70_000), Err(KeydError::InvalidUid(_))));
    assert!(matches!(Secret::new(""), Err(KeydError::InvalidSecret)));
    assert!(matches!(
        Secret::new("pin with spaces"),
        Err(KeydError::InvalidSecret)
    ));
    assert!(matches!(keyd.key(1006), Err(KeydError::NotProvisioned)));
    assert!(matches!(
        keyd.attribute(1006, KeyAttribute::Sign),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        keyd.sign_digest(1006, &secret(SECRET), &DIGEST),
        Err(KeydError::NotProvisioned)
    ));
}
