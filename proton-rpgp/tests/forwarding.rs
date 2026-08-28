use pgp::ser::Serialize;
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, Decryptor, Encryptor, ForwardingPkesk, PrivateKey, Profile,
    UnixTime,
};

const FORWARDEE_KEY: &str = include_str!("../test-data/keys/private_key_v4_forwardee.asc");
const FORWARDED_MESSAGE: &str =
    include_str!("../test-data/messages/encrypted_message_v4_forwarded.asc");
const SIGN_ONLY_KEY: &str = include_str!("../test-data/keys/private_key_v4_sign_only.asc");
const REGULAR_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");

pub const TEST_KEY_V4: &str = include_str!("../test-data/keys/private_key_v4.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_refuses_encryption_to_forwarding_key() {
    let key = PrivateKey::import_unlocked(FORWARDEE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let result = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_raw(b"abc", DataEncoding::Armored);

    assert!(
        result.is_err(),
        "Encryption to a forwarding key must be refused"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_key_serialization_preserves_kdf_params() {
    let profile = Profile::default();
    let date = UnixTime::new(1_679_044_110);

    let key = PrivateKey::import_unlocked(FORWARDEE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    assert!(key.is_forwarding_key(&profile));

    let exported = key
        .export_unlocked(DataEncoding::Armored)
        .expect("Failed to export key");

    let reimported = PrivateKey::import_unlocked(&exported, DataEncoding::Armored)
        .expect("Failed to re-import key");

    // Forwarding KDF params survived serialization.
    assert!(reimported.is_forwarding_key(&profile));

    // And the re-imported key still decrypts the forwarded ciphertext.
    let verified_data = Decryptor::default()
        .with_decryption_key(&reimported)
        .at_date(date.into())
        .allow_forwarding_decryption(true)
        .decrypt(FORWARDED_MESSAGE, DataEncoding::Armored)
        .expect("Failed to decrypt with re-imported forwarding key");

    assert_eq!(verified_data.data, b"Message for Bob");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_reformat_preserves_flag() {
    let profile = Profile::default();
    let key = PrivateKey::import_unlocked(FORWARDEE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    assert!(key.is_forwarding_key(&profile));

    let reformatted = key
        .modify()
        .add_user_id("test", "test@forwarding.it")
        .reset_signatures()
        .apply()
        .expect("Failed to reformat key");

    assert!(
        reformatted.is_forwarding_key(&profile),
        "Reformatting must preserve the forwarding flag"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_detection_negative_cases() {
    let profile = Profile::default();

    let regular = PrivateKey::import_unlocked(REGULAR_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    assert!(!regular.is_forwarding_key(&profile));

    let sign_only = PrivateKey::import_unlocked(SIGN_ONLY_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    assert!(!sign_only.is_forwarding_key(&profile));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_full() {
    let date = UnixTime::new(1_787_919_498);
    let msg = "hello";

    let forwarder = PrivateKey::import_unlocked(TEST_KEY_V4.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted = Encryptor::default()
        .with_encryption_key(forwarder.as_public_key())
        .encrypt(msg.as_bytes())
        .unwrap();

    let encrypted_bytes = encrypted.to_bytes().unwrap();

    let (forwardee_key, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee@example.com", "forwardee@example.com")
        .at_date(date)
        .generate()
        .expect("Generation should succeed");

    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked()).unwrap();

    let forwarded = pkesk.proxy_forward(&instances).unwrap();

    let mut forwarded_msg = forwarded.to_vec().unwrap();
    forwarded_msg.extend_from_slice(encrypted.as_data_packet_unchecked());

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee_key)
        .decrypt(forwarded_msg, DataEncoding::Unarmored)
        .unwrap();

    assert_eq!(decrypted.data, msg.as_bytes());

    // Old message decryption fails
    Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee_key)
        .decrypt(encrypted_bytes, DataEncoding::Unarmored)
        .expect_err("decryption should fail");
}
