use pgp::{
    packet::SignatureType,
    types::{Duration, Tag},
};
use proton_rpgp::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, KeyCertificationError, KeyGenerationType,
    KeyGenerator, Lifetime, PrivateKey, Profile, PublicKey, UnixTime,
};

/// Ensures the certification API is usable from outside the crate for both key types.
#[test]
#[allow(clippy::missing_panics_doc)]
pub fn certify_public_and_private_key_with_external_key() {
    const TEST_KEY_TO_CERTIFY: &str = include_str!("../test-data/keys/private_key_v4.asc");
    const TEST_KEY_TO_CERTIFY_EMAIL: &str = "rust-test@test.test";
    let date = UnixTime::new(1_756_196_260);
    let key = PrivateKey::import_unlocked(TEST_KEY_TO_CERTIFY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let certifier = KeyGenerator::default()
        .with_user_id("certifier", "certifier@test.com")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(date)
        .generate()
        .expect("Failed to generate certifier key");

    let certified_private: PrivateKey = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_TO_CERTIFY_EMAIL)
        .with_date(date)
        .with_profile(&Profile::default())
        .apply()
        .expect("Failed to certify private key");

    let certified_public: PublicKey = key
        .as_public_key()
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_TO_CERTIFY_EMAIL)
        .with_date(date)
        .with_profile(&Profile::default())
        .apply()
        .expect("Failed to certify public key");

    for user in [
        certified_private.as_signed_public_key(),
        certified_public.as_signed_public_key(),
    ]
    .map(|key| key.details.users.first().expect("No user-id").clone())
    {
        assert_eq!(user.signatures.len(), 2);
    }
}

const TEST_KEY_EMAIL: &str = "rust-test@test.test";

fn import_test_key() -> PrivateKey {
    PrivateKey::import_unlocked(
        include_str!("../test-data/keys/private_key_v4.asc").as_bytes(),
        DataEncoding::Armored,
    )
    .expect("Failed to import key")
}

fn generate_certifier(date: UnixTime) -> PrivateKey {
    KeyGenerator::default()
        .with_user_id("certifier", "certifier@test.com")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(date)
        .generate()
        .expect("Failed to generate certifier key")
}

#[test]
fn certification_with_external_key() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify key");

    assert!(certified_key
        .check_can_encrypt(&Profile::default(), date.into())
        .is_ok());

    let user = certified_key
        .as_signed_public_key()
        .details
        .users
        .first()
        .expect("No user-id in certified key");

    // The self-certification is kept and the external certification is added.
    assert_eq!(user.signatures.len(), 2);
    let certification = user.signatures.last().expect("No certification");
    assert_eq!(certification.typ(), Some(SignatureType::CertGeneric));
    assert_eq!(UnixTime::from(certification.created().unwrap()), date);
    assert_eq!(
        certification.issuer_fingerprint().first().copied(),
        Some(&certifier.fingerprint())
    );
    assert_eq!(
        certification.signers_userid().map(AsRef::as_ref),
        Some("certifier <certifier@test.com>".as_bytes())
    );

    certification
        .verify_third_party_certification(
            &certified_key.as_signed_public_key().primary_key,
            &certifier.as_signed_public_key().primary_key,
            Tag::UserId,
            &user.id,
        )
        .expect("Certification must verify with the certifier key");
}

#[test]
fn certification_with_external_key_on_public_key() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);
    let public_key = PublicKey::from(&key);

    let certified_key = public_key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify public key");

    // The certified public key is still a valid key that can be re-imported.
    let exported = certified_key
        .export(DataEncoding::Armored)
        .expect("Failed to export certified public key");
    let reimported = PublicKey::import(&exported, DataEncoding::Armored)
        .expect("Failed to import certified public key");

    let user = reimported
        .as_signed_public_key()
        .details
        .users
        .first()
        .expect("No user-id in certified key");

    assert_eq!(user.signatures.len(), 2);
    let certification = user.signatures.last().expect("No certification");
    assert_eq!(certification.typ(), Some(SignatureType::CertGeneric));
    certification
        .verify_third_party_certification(
            &reimported.as_signed_public_key().primary_key,
            &certifier.as_signed_public_key().primary_key,
            Tag::UserId,
            &user.id,
        )
        .expect("Certification must verify with the certifier key");
}

#[test]
fn certification_with_external_key_with_lifetime() {
    const LIFETIME: u32 = 60 * 60 * 24;

    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .with_lifetime(Lifetime::from_secs(LIFETIME))
        .apply()
        .expect("Failed to certify key");

    let user = certified_key
        .as_signed_public_key()
        .details
        .users
        .first()
        .expect("No user-id in certified key");
    let certification = user.signatures.last().expect("No certification");

    assert_eq!(
        certification
            .signature_expiration_time()
            .map(Duration::as_secs),
        Some(LIFETIME)
    );

    // The certification is valid until the lifetime elapsed.
    let expiration = UnixTime::new(date.unix_seconds() + u64::from(LIFETIME));
    certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(expiration)
        .verify()
        .expect("Certification must still verify before expiration");
    let result = certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(UnixTime::new(expiration.unix_seconds() + 1))
        .verify();
    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn certification_with_external_key_replaces_existing() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let later_date = UnixTime::new(1_756_296_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify key");
    let recertified_key = certified_key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(later_date)
        .apply()
        .expect("Failed to re-certify key");

    let user = recertified_key
        .as_signed_public_key()
        .details
        .users
        .first()
        .expect("No user-id in certified key");

    assert_eq!(user.signatures.len(), 2);
    let certification = user.signatures.last().expect("No certification");
    assert_eq!(certification.typ(), Some(SignatureType::CertGeneric));
    assert_eq!(UnixTime::from(certification.created().unwrap()), later_date);
}

#[test]
fn certification_with_external_key_wrong_email() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let result = key
        .certify_with_external(&certifier)
        .with_email("other@test.test")
        .with_date(date)
        .apply();

    assert!(matches!(
        result,
        Err(KeyCertificationError::EmailMismatch(_))
    ));
}

#[test]
fn certification_with_external_key_too_many_user_ids() {
    let date = UnixTime::new(1_756_196_260);
    let key = import_test_key()
        .modify()
        .add_user_id("test2", "test2@test.com")
        .with_date(date)
        .apply()
        .expect("Failed to modify key");
    let certifier = generate_certifier(date);

    let result = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply();

    assert!(matches!(result, Err(KeyCertificationError::TooManyUserIds)));
}

#[test]
fn verification_with_external_key() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify key");

    certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .verify()
        .expect("Certification must verify with the certifier key");

    // Verification also works on the public key alone.
    certified_key
        .as_public_key()
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .verify()
        .expect("Certification must verify with the certifier key on the public key");
}

#[test]
fn verification_with_external_key_wrong_certifier() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);
    let other_certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify key");

    let result = certified_key
        .verify_with_external(&other_certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn verification_with_external_key_expired() {
    const LIFETIME: u32 = 60 * 60 * 24;

    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .with_lifetime(Lifetime::from_secs(LIFETIME))
        .apply()
        .expect("Failed to certify key");

    let expiration = UnixTime::new(date.unix_seconds() + u64::from(LIFETIME));
    certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(expiration)
        .verify()
        .expect("Certification must still verify before expiration");

    let result = certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(UnixTime::new(expiration.unix_seconds() + 1))
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn verification_with_external_key_wrong_email() {
    let key = import_test_key();
    let date = UnixTime::new(1_756_196_260);
    let certifier = generate_certifier(date);

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .apply()
        .expect("Failed to certify key");

    let result = certified_key
        .verify_with_external(&certifier)
        .with_email("other@test.test")
        .with_date(date)
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::EmailMismatch(_))
    ));
}

#[test]
fn verification_with_external_key_too_many_user_ids() {
    let date = UnixTime::new(1_756_196_260);
    let key = import_test_key()
        .modify()
        .add_user_id("test2", "test2@test.com")
        .with_date(date)
        .apply()
        .expect("Failed to modify key");
    let certifier = generate_certifier(date);

    let result = key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(date)
        .verify();

    assert!(matches!(result, Err(KeyCertificationError::TooManyUserIds)));
}

const EXTERNAL_CERTIFIER_KEY: &str =
    include_str!("../test-data/keys/external_certifier_private_key_v4.asc");
const EXTERNAL_CERTIFIER_2_KEY: &str =
    include_str!("../test-data/keys/external_certifier_2_private_key_v4.asc");
const EXTERNALLY_CERTIFIED_KEY: &str =
    include_str!("../test-data/keys/externally_certified_public_key_v4.asc");
const EXTERNALLY_CERTIFIED_KEY_MULTIPLE: &str =
    include_str!("../test-data/keys/externally_certified_public_key_v4_multiple.asc");
const VERIFY_FIXTURE_DATE_SECS: u64 = 1_756_196_260;
const VERIFY_FIXTURE_LIFETIME: u32 = 60 * 60;

fn verify_fixture_date() -> UnixTime {
    UnixTime::new(VERIFY_FIXTURE_DATE_SECS)
}

fn import_external_certifier() -> PrivateKey {
    PrivateKey::import_unlocked(EXTERNAL_CERTIFIER_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import external certifier key")
}

fn import_external_certifier_2() -> PrivateKey {
    PrivateKey::import_unlocked(EXTERNAL_CERTIFIER_2_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import second external certifier key")
}

fn import_externally_certified_key() -> PublicKey {
    PublicKey::import(EXTERNALLY_CERTIFIED_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import externally certified key")
}

fn import_externally_certified_key_multiple() -> PublicKey {
    PublicKey::import(
        EXTERNALLY_CERTIFIED_KEY_MULTIPLE.as_bytes(),
        DataEncoding::Armored,
    )
    .expect("Failed to import externally certified key with multiple certifications")
}

#[test]
fn verify_key_basic() {
    let key = import_externally_certified_key();
    let certifier = import_external_certifier();

    key.verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("Certification must verify with the certifier key");
}

#[test]
fn verify_key_expired() {
    let key = import_externally_certified_key();
    let certifier = import_external_certifier();

    // Still valid right at the expiration boundary.
    let expiration = UnixTime::new(VERIFY_FIXTURE_DATE_SECS + u64::from(VERIFY_FIXTURE_LIFETIME));
    key.verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(expiration)
        .verify()
        .expect("Certification must still verify before expiration");

    // Expired one second after the expiration boundary.
    let result = key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(UnixTime::new(expiration.unix_seconds() + 1))
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn verify_key_not_yet_valid() {
    let key = import_externally_certified_key();
    let certifier = import_external_certifier();

    // A verification date before the certification's creation time must fail.
    let result = key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(UnixTime::new(VERIFY_FIXTURE_DATE_SECS - 1))
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn verify_key_wrong_key() {
    let key = import_externally_certified_key();
    // A certifier that never issued a certification for this key.
    let wrong_certifier = generate_certifier(verify_fixture_date());

    let result = key
        .verify_with_external(&wrong_certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::NoValidCertification(_))
    ));
}

#[test]
fn verify_key_wrong_identity() {
    let key = import_externally_certified_key();
    let certifier = import_external_certifier();

    let result = key
        .verify_with_external(&certifier)
        .with_email("not-rust-test@test.test")
        .with_date(verify_fixture_date())
        .verify();

    assert!(matches!(
        result,
        Err(KeyCertificationError::EmailMismatch(_))
    ));
}

#[test]
fn sign_verify_key_full() {
    let key = import_test_key();
    let certifier = import_external_certifier();

    let certified_key = key
        .certify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .apply()
        .expect("Failed to certify key");

    certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("Certification must verify right after signing");
}

#[test]
fn sign_verify_key_multiple() {
    // The fixture is already certified by `EXTERNAL_CERTIFIER_KEY`; certify it again with a
    // second, independent certifier and verify that both certifications remain valid.
    let key = import_externally_certified_key();
    let certifier = import_external_certifier();
    let other_certifier = import_external_certifier_2();

    let certified_key = key
        .certify_with_external(&other_certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .with_lifetime(Lifetime::from_secs(VERIFY_FIXTURE_LIFETIME))
        .apply()
        .expect("Failed to certify key with second certifier");

    certified_key
        .verify_with_external(&other_certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("New certification must verify");

    certified_key
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("Original certification must still verify");

    // The pre-built multiple-certifiers fixture matches the same expectation.
    let key_multiple = import_externally_certified_key_multiple();
    key_multiple
        .verify_with_external(&certifier)
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("First certification must verify");
    key_multiple
        .verify_with_external(&import_external_certifier_2())
        .with_email(TEST_KEY_EMAIL)
        .with_date(verify_fixture_date())
        .verify()
        .expect("Second certification must verify");
}
