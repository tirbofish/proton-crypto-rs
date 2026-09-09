use pgp::{
    composed::SignedSecretKey,
    packet::{self, KeyFlags, PubKeyInner, SignatureType, UserId},
    types::{KeyDetails, SignedUser},
};

use crate::{
    convert_user_ids, primary_key_flags, CertificationSelectionExt, CheckUnixTime,
    KeyCertificationError, KeyGenerationProfileBuilder, KeyModificationError, KeyUserId, Lifetime,
    PacketPublicSubkeyExt, PacketUserIdExt, PrivateKey, PrivateKeySelectionExt, Profile, PublicKey,
    PublicKeySelectionExt, SignatureExt, SignatureUsage, UnixTime, DEFAULT_PROFILE,
};

pub struct KeyModifier {
    /// The key to modify.
    key: SignedSecretKey,

    /// The profile to use for the key modification.
    profile: Profile,

    /// The new user-ids to add to the key.
    new_user_ids: Vec<KeyUserId>,

    /// Whether to remove the old user-ids from the key.
    clear_existing_user_ids: bool,

    /// Whether reset and create new signatures for user-ids/direct-key/subkeys.
    ///
    /// All existing signatures on these parts are removed and new signatures are created.
    reset_signatures: bool,

    /// The date of the key generation for the self-certifications and key creation time.
    modification_date: UnixTime,

    /// Override the key creation time of the primary key and subkeys.
    key_creation_time: Option<UnixTime>,
}

impl KeyModifier {
    pub fn new(key_to_modify: &PrivateKey) -> Self {
        Self::new_with_profile(key_to_modify, &DEFAULT_PROFILE)
    }

    pub fn new_with_profile(key_to_modify: &PrivateKey, profile: &Profile) -> Self {
        Self {
            key: key_to_modify.secret.clone(),
            profile: profile.clone(),
            new_user_ids: Vec::new(),
            clear_existing_user_ids: false,
            reset_signatures: false,
            modification_date: UnixTime::now().unwrap_or_default(),
            key_creation_time: None,
        }
    }

    /// Add a new user-id to the key.
    pub fn add_user_id(mut self, name: &str, email: &str) -> Self {
        self.new_user_ids.push(KeyUserId {
            name: name.to_string(),
            email: email.to_string(),
        });
        self
    }

    /// Remove all existing user-ids from the key.
    pub fn clear_existing_user_ids(mut self) -> Self {
        self.clear_existing_user_ids = true;
        self
    }

    /// Resets and regenerates signatures for user-IDs, direct-key info, and subkeys.
    ///
    /// When enabled, all existing signatures related to these components are removed,
    /// and new self-signatures are created according to the modification configuration.
    pub fn reset_signatures(mut self) -> Self {
        self.reset_signatures = true;
        self
    }

    /// Override the key creation time of the primary key and subkeys.  
    ///
    /// Automatically triggers a signature reset.
    pub fn with_key_creation_time(mut self, key_creation_time: UnixTime) -> Self {
        self.reset_signatures = true;
        self.key_creation_time = Some(key_creation_time);
        self
    }

    /// Set the date of the key modification.
    pub fn with_date(mut self, date: UnixTime) -> Self {
        self.modification_date = date;
        self
    }

    /// Apply the key modifications according to the configuration.
    pub fn apply(self) -> crate::Result<PrivateKey> {
        let sub_key_flags = self.collect_sub_key_flags()?;
        let modifier = self
            .apply_primary_key_modifications()?
            .apply_subkey_modifications(sub_key_flags)?;
        Ok(PrivateKey::new(modifier.key))
    }

    fn collect_sub_key_flags(&self) -> Result<Vec<KeyFlags>, KeyModificationError> {
        if self.reset_signatures {
            self.key
                .secret_subkeys
                .iter()
                .map(|sub_key| {
                    let self_sig = sub_key.latest_valid_self_certification(
                        self.key.primary_key(),
                        CheckUnixTime::disable(),
                        &self.profile,
                    )?;
                    Ok(self_sig.key_flags())
                })
                .collect()
        } else {
            Ok(Vec::default())
        }
    }

    fn apply_primary_key_modifications(mut self) -> Result<Self, KeyModificationError> {
        let mut rng = self.profile.rng();
        let preferred_hash = self.profile.key_hash_algorithm();

        if self.clear_existing_user_ids {
            self.key.details.users.clear();
        }

        if self.reset_signatures {
            if let Some(key_creation_time) = self.key_creation_time {
                let pub_key = PubKeyInner::new(
                    self.key.primary_key().version(),
                    self.key.primary_key().algorithm(),
                    key_creation_time.into(),
                    None,
                    self.key.primary_key().public_params().clone(),
                )
                .map_err(KeyModificationError::PrimaryKeyModification)?;
                let primary_pub_key = packet::PublicKey::from_inner(pub_key)
                    .map_err(KeyModificationError::PrimaryKeyModification)?;
                let primary_secret_key = packet::SecretKey::new(
                    primary_pub_key.clone(),
                    self.key.primary_secret_key().secret_params().clone(),
                )
                .map_err(KeyModificationError::PrimaryKeyModification)?;
                self.key.primary_key = primary_secret_key;
            }
        }

        let key_gen_config = KeyGenerationProfileBuilder::default()
            .key_version(self.key.version())
            .build();

        let (primary_user_id, non_primary_user_ids) = if self.key.details.users.is_empty() {
            convert_user_ids(&self.new_user_ids)?
        } else {
            let mut old_user_ids = if self.reset_signatures {
                std::mem::take(&mut self.key.details.users)
                    .into_iter()
                    .map(|user| user.id)
                    .collect::<Vec<_>>()
            } else {
                Vec::with_capacity(self.new_user_ids.len())
            };
            for user_id in &self.new_user_ids {
                old_user_ids.push(user_id.try_to_user_id()?);
            }

            (None, old_user_ids)
        };

        let key_details_config = key_gen_config.create_key_details_config(
            primary_user_id,
            non_primary_user_ids,
            primary_key_flags(),
        );

        let updated_signed_key_details = key_details_config
            .sign_with(
                self.key.primary_secret_key(),
                self.key.primary_key(),
                self.modification_date,
                preferred_hash,
                &mut rng,
                &self.profile,
            )
            .map_err(KeyModificationError::Signing)?;

        let mut new_users = Vec::with_capacity(
            updated_signed_key_details.users.len() + self.key.details.users.len(),
        );
        new_users.extend(updated_signed_key_details.users);
        new_users.extend(self.key.details.users);
        self.key.details.users = new_users;

        if self.reset_signatures {
            self.key.details.revocation_signatures.clear();
            self.key.details.direct_signatures.clear();
            self.key
                .details
                .direct_signatures
                .extend(updated_signed_key_details.direct_signatures);
        }

        Ok(self)
    }

    fn apply_subkey_modifications(
        mut self,
        sub_key_flags: Vec<KeyFlags>,
    ) -> Result<Self, KeyModificationError> {
        if self.reset_signatures {
            let mut rng = self.profile.rng();
            let preferred_hash = self.profile.key_hash_algorithm();

            let updated_subkeys: Vec<_> = self
                .key
                .secret_subkeys
                .iter()
                .map(|sub_key| {
                    if let Some(key_creation_time) = self.key_creation_time {
                        let pub_key = PubKeyInner::new(
                            sub_key.key.version(),
                            sub_key.key.algorithm(),
                            key_creation_time.into(),
                            None,
                            sub_key.key.public_key().public_params().clone(),
                        )
                        .map_err(KeyModificationError::SubkeyModification)?;
                        let subkey_public = packet::PublicSubkey::from_inner(pub_key)
                            .map_err(KeyModificationError::SubkeyModification)?;
                        packet::SecretSubkey::new(subkey_public, sub_key.secret_params().clone())
                            .map_err(KeyModificationError::SubkeyModification)
                    } else {
                        Ok(sub_key.key.clone())
                    }
                })
                .collect::<Result<_, _>>()?;

            let new_subkey_signatures = updated_subkeys
                .iter()
                .zip(sub_key_flags)
                .map(|(sub_key, subkey_flag)| {
                    sub_key
                        .public_key()
                        .sign_with(
                            self.key.primary_secret_key(),
                            self.key.primary_key(),
                            self.modification_date,
                            preferred_hash,
                            subkey_flag,
                            None,
                            &mut rng,
                            &self.profile,
                        )
                        .map_err(KeyModificationError::Signing)
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (sub_key, (updated_subkey, signature)) in self
                .key
                .secret_subkeys
                .iter_mut()
                .zip(updated_subkeys.into_iter().zip(new_subkey_signatures))
            {
                sub_key.key = updated_subkey;
                sub_key.signatures.clear();
                sub_key.signatures.push(signature);
            }
        }

        Ok(self)
    }
}

/// A builder to certify the single user-id of a key with an external `certifier` key.
///
/// For example: Proton CA
pub struct ExternalCertifier<'a, K> {
    /// The key whose user-id is being certified.
    key: K,

    /// The key used to issue the certification.
    certifier: &'a PrivateKey,

    /// The expected email address of the certified user-id.
    check_email: Option<String>,

    /// The date of the certification.
    date: UnixTime,

    /// The lifetime of the certification, after which it expires.
    lifetime: Option<Lifetime>,

    /// The profile to use for the certification.
    profile: Profile,
}

impl<'a, K> ExternalCertifier<'a, K> {
    pub(crate) fn new(key: K, certifier: &'a PrivateKey) -> Self {
        Self {
            key,
            certifier,
            check_email: None,
            date: UnixTime::now().unwrap_or_default(),
            lifetime: None,
            profile: DEFAULT_PROFILE.clone(),
        }
    }

    /// Enforce that the certified user-id contains the given email address.
    pub fn with_email(mut self, email: &str) -> Self {
        self.check_email = Some(email.to_string());
        self
    }

    /// Set the date of the certification.
    pub fn with_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Set the lifetime of the certification, after which it expires.
    ///
    /// If not set, the certification does not expire.
    pub fn with_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Set the profile to use for the certification.
    pub fn with_profile(mut self, profile: &Profile) -> Self {
        self.profile = profile.clone();
        self
    }
}

impl ExternalCertifier<'_, PublicKey> {
    /// Apply the certification according to the configuration.
    pub fn apply(self) -> Result<PublicKey, KeyCertificationError> {
        let certified_user_ids = certify_user_id_with_external(
            &self.key.inner.primary_key,
            self.certifier,
            &self.key.inner.details.users,
            self.check_email.as_deref(),
            self.date,
            self.lifetime,
            &self.profile,
        )?;
        let mut key = self.key;
        key.inner.details.users = certified_user_ids;
        Ok(key)
    }
}

impl ExternalCertifier<'_, PrivateKey> {
    /// Apply the certification according to the configuration.
    pub fn apply(self) -> Result<PrivateKey, KeyCertificationError> {
        let certified_user_ids = certify_user_id_with_external(
            self.key.secret.primary_key.public_key(),
            self.certifier,
            &self.key.secret.details.users,
            self.check_email.as_deref(),
            self.date,
            self.lifetime,
            &self.profile,
        )?;
        let mut secret = self.key.secret;
        secret.details.users = certified_user_ids;
        Ok(PrivateKey::new(secret))
    }
}

/// Certifies the single user-id of a key with an external `certifier` key.
///
/// If a `lifetime` in seconds is given, the certification expires that many
/// seconds after `date`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn certify_user_id_with_external(
    certified_primary_key: &packet::PublicKey,
    certifier: &PrivateKey,
    user_ids: &[SignedUser],
    check_email: Option<&str>,
    date: UnixTime,
    lifetime: Option<Lifetime>,
    profile: &Profile,
) -> Result<Vec<SignedUser>, KeyCertificationError> {
    // Enforce that the key has a single user-id that matches the email.
    if user_ids.len() > 1 {
        return Err(KeyCertificationError::TooManyUserIds);
    }
    let Some(user) = user_ids.first() else {
        return Err(KeyCertificationError::NoUserId);
    };
    check_user_id_email(&user.id, check_email)?;

    // Time checks are disabled to also allow certifying expired keys.
    user.check_validity(certified_primary_key, CheckUnixTime::disable(), profile)
        .map_err(KeyCertificationError::UserIdSelfCertification)?;

    let certifier_primary_key = certifier.secret.primary_key.public_key();
    let certification_key = certifier.secret.signing_key(
        date.into(),
        Some(certifier_primary_key.legacy_key_id()),
        SignatureUsage::Sign,
        profile,
    )?;
    let (certifier_user, _) = certifier
        .secret
        .select_user_id_with_certification(CheckUnixTime::disable(), profile)
        .map_err(KeyCertificationError::CertifierUserId)?;

    let certification = user.id.sign_third_party_with(
        &certification_key.private_key,
        certified_primary_key,
        Some(&certifier_user.id),
        date,
        profile.key_hash_algorithm(),
        lifetime,
        profile.rng(),
        profile,
    )?;

    // Replace existing generic certifications from the same certifier.
    let mut certified_user = user.clone();
    certified_user.signatures.retain(|signature| {
        signature.typ() != Some(SignatureType::CertGeneric)
            || !signature.is_issued_by(certifier_primary_key)
    });
    certified_user.signatures.push(certification);

    Ok(vec![certified_user])
}

/// Checks that the user-id contains the given email address.
fn check_user_id_email(
    user_id: &UserId,
    check_email: Option<&str>,
) -> Result<(), KeyCertificationError> {
    let Some(email) = check_email else {
        return Ok(());
    };
    let user_id_string = user_id
        .as_str()
        .ok_or(KeyCertificationError::InvalidUserId)?;
    if extract_email(user_id_string) != Some(email) {
        return Err(KeyCertificationError::EmailMismatch(email.to_owned()));
    }
    Ok(())
}

/// Extracts the email address of a user-id of the form `name (comment) <email>`.
fn extract_email(user_id: &str) -> Option<&str> {
    let (_, remainder) = user_id.split_once('<')?;
    let (email, _) = remainder.split_once('>')?;
    Some(email)
}

#[cfg(test)]
mod tests {
    use pgp::{
        packet::SignatureType,
        types::{Duration, Tag},
    };

    use crate::{
        AccessKeyInfo, DataEncoding, KeyCertificationError, KeyGenerationType, KeyGenerator,
        Lifetime, PrivateKey, PublicKey, SignatureExt, UnixTime, DEFAULT_PROFILE,
        PREFERRED_KEY_GEN_COMPRESSION_ALGORITHMS, PREFERRED_KEY_GEN_HASH_ALGORITHMS,
    };

    const TEST_PRIVATE_KEY: &str = include_str!("../../test-data/keys/locked_private_key_v6.asc");
    const TEST_PRIVATE_KEY_PASSWORD: &str = "password";
    const TEST_KEY_EMAIL: &str = "rust-test@test.test";

    #[test]
    fn key_modification_user_id_v4() {
        let key = PrivateKey::import_unlocked(
            include_str!("../../test-data/keys/private_key_v4.asc").as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify()
            .clear_existing_user_ids()
            .add_user_id("test2", "test2@test.com")
            .with_date(date)
            .apply()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 1);
        let user_id = modified_key
            .as_signed_public_key()
            .details
            .users
            .first()
            .unwrap();
        assert_eq!(user_id.id.as_str().unwrap(), "test2 <test2@test.com>");
        let user_id_signature = user_id.signatures.first().unwrap();
        assert_eq!(
            user_id_signature.preferred_hash_algs(),
            PREFERRED_KEY_GEN_HASH_ALGORITHMS
        );
        assert_eq!(
            user_id_signature.preferred_compression_algs(),
            PREFERRED_KEY_GEN_COMPRESSION_ALGORITHMS,
        );

        assert_eq!(UnixTime::from(user_id_signature.created().unwrap()), date);
    }

    #[test]
    fn key_modification_user_id_v6() {
        let key = PrivateKey::import(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify()
            .clear_existing_user_ids()
            .add_user_id("test2", "test2@test.com")
            .with_date(date)
            .apply()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 1);
        let user_id = modified_key
            .as_signed_public_key()
            .details
            .users
            .first()
            .unwrap();
        assert_eq!(user_id.id.as_str().unwrap(), "test2 <test2@test.com>");

        let user_id_signature = user_id.signatures.first().unwrap();
        assert!(user_id_signature.preferred_hash_algs().is_empty());
        assert_eq!(UnixTime::from(user_id_signature.created().unwrap()), date);
    }

    #[test]
    #[allow(clippy::indexing_slicing)]
    fn key_modification_user_id_v4_reset() {
        let key = PrivateKey::import_unlocked(
            include_str!("../../test-data/keys/private_key_v4.asc").as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify()
            .add_user_id("test2", "test2@test.com")
            .reset_signatures()
            .with_key_creation_time(date)
            .with_date(date)
            .apply()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 2);
        let users = &modified_key.as_signed_public_key().details.users;
        let new_user_id = &users[1].id;
        let old_user_id = &users[0].id;
        assert_eq!(new_user_id.as_str().unwrap(), "test2 <test2@test.com>");
        assert_eq!(
            old_user_id.as_str().unwrap(),
            "rust-test <rust-test@test.test>"
        );
    }

    fn import_test_key() -> PrivateKey {
        PrivateKey::import_unlocked(
            include_str!("../../test-data/keys/private_key_v4.asc").as_bytes(),
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
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
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
        assert!(certification.check_not_expired(expiration.into()).is_ok());
        assert!(certification
            .check_not_expired(UnixTime::new(expiration.unix_seconds() + 1).into())
            .is_err());
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
}
