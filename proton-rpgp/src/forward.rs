use std::io::BufRead;

use pgp::{
    composed::{KeyType, SignedSecretKey},
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Packet, PacketParser, PacketTrait, PublicKeyEncryptedSessionKey},
    types::{
        EcdhKdfType, EcdhPublicParams, Fingerprint, ForwardingProxyParameter, KeyDetails, KeyId,
        KeyVersion, Password, PublicParams, Timestamp,
    },
};

use crate::{
    check_subkey_for_forwarding, generate_forwarding_encryption_subkey_and_sign,
    generate_primary_key, primary_key_flags, AccessKeyInfo, FingerprintExt,
    ForwardingKeyGenerationError, ForwardingKeyValidation, ForwardingPkeskError, KeyOperationError,
    KeyUserId, PrivateKey, Profile, PublicKeySelectionExt, UnixTime,
};

/// A PKESK that has been transformed for a forwardee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedPkesk(PublicKeyEncryptedSessionKey);

impl ForwardedPkesk {
    pub fn pkesk(&self) -> &PublicKeyEncryptedSessionKey {
        &self.0
    }

    /// Encodes the PKESK as a standalone `OpenPGP` packet, header included.
    pub fn to_vec(&self) -> crate::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.0.write_len_with_header());
        self.0
            .to_writer_with_header(&mut bytes)
            .map_err(ForwardingPkeskError::Encode)?;
        Ok(bytes)
    }
}

impl From<ForwardedPkesk> for PublicKeyEncryptedSessionKey {
    fn from(value: ForwardedPkesk) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingPkesk(PublicKeyEncryptedSessionKey);

impl ForwardingPkesk {
    /// Decodes the single PKESK packet contained in `bytes`..
    pub fn from_bytes<R: BufRead>(bytes: R) -> crate::Result<Self> {
        let mut pkesks = Self::from_bytes_iter(bytes);
        let Some(pkesk) = pkesks.next() else {
            return Err(KeyOperationError::DecodeNotFound.into());
        };
        let pkesk = pkesk?;
        if pkesks.next().is_some() {
            return Err(KeyOperationError::DecodeMultipleKeys.into());
        }
        Ok(pkesk)
    }

    /// Iterates over the PKESK packets in `bytes`, yielding an error for every
    /// packet that fails to parse or is not eligible for forwarding.
    pub fn from_bytes_iter<R: BufRead>(bytes: R) -> impl Iterator<Item = crate::Result<Self>> {
        PacketParser::new(bytes).filter_map(|packet| match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => Some(Self::try_from(pkesk)),
            Ok(_) => None,
            Err(err) => Some(Err(ForwardingPkeskError::Parsing(err).into())),
        })
    }

    /// Checks that `pkesk` is eligible to be transformed in forarding.
    pub fn valid(pkesk: &PublicKeyEncryptedSessionKey) -> crate::Result<()> {
        let PublicKeyEncryptedSessionKey::V3 { pk_algo, .. } = pkesk else {
            return Err(ForwardingPkeskError::VersionMismatch(pkesk.version()).into());
        };
        if *pk_algo != PublicKeyAlgorithm::ECDH {
            return Err(ForwardingPkeskError::AlgorithmMismatch(*pk_algo).into());
        }
        Ok(())
    }

    fn key_id(&self) -> crate::Result<KeyId> {
        self.0
            .id()
            .copied()
            .map_err(|_| ForwardingPkeskError::VersionMismatch(self.0.version()).into())
    }

    /// Tries to find a matching `ForwardingInstance` to transform pkesk.
    pub fn proxy_forward<'a>(
        &self,
        params: impl IntoIterator<Item = &'a ForwardingInstance>,
    ) -> crate::Result<ForwardedPkesk> {
        let fpkesk_key_id = self.key_id()?;
        let fw_instance = params
            .into_iter()
            .find(|instance| {
                instance
                    .forwarder_fingerprint()
                    .key_id()
                    .is_some_and(|key_id| key_id == fpkesk_key_id)
            })
            .ok_or(ForwardingPkeskError::NoMatchingInstance(fpkesk_key_id))?;

        let proxy_parameter = ForwardingProxyParameter::from(*fw_instance.proxy_parameter.as_ref());
        let pkesk = self
            .0
            .forwarding_transform(&fw_instance.inner, proxy_parameter)
            .map_err(ForwardingPkeskError::ProxyTansform)?;
        Ok(ForwardedPkesk(pkesk))
    }
}

impl TryFrom<PublicKeyEncryptedSessionKey> for ForwardingPkesk {
    type Error = crate::Error;

    fn try_from(value: PublicKeyEncryptedSessionKey) -> crate::Result<Self> {
        Self::valid(&value)?;
        Ok(Self(value))
    }
}

impl From<ForwardingPkesk> for PublicKeyEncryptedSessionKey {
    fn from(value: ForwardingPkesk) -> Self {
        value.0
    }
}

pub struct ForwardingInstance {
    inner: ForwardingKeyDetails,
    proxy_parameter: ForwardingProxyParameter,
}

impl ForwardingInstance {
    pub fn new(
        forwarder_fp: Fingerprint,
        forwardee_fp: Fingerprint,
        proxy_parameter: ForwardingProxyParameter,
    ) -> crate::Result<Self> {
        Self::new_inner(forwarder_fp, forwardee_fp, proxy_parameter).map_err(Into::into)
    }

    fn new_inner(
        forwarder_fp: Fingerprint,
        forwardee_fp: Fingerprint,
        proxy_parameter: ForwardingProxyParameter,
    ) -> Result<Self, ForwardingPkeskError> {
        Ok(Self {
            inner: ForwardingKeyDetails::new(forwarder_fp, forwardee_fp)?,
            proxy_parameter,
        })
    }

    /// Fingerprint of the key the message was originally encrypted to.
    pub fn forwarder_fingerprint(&self) -> &Fingerprint {
        &self.inner.forwarder_fingerprint
    }

    /// Fingerprint of the key the message is being forwarded to.
    pub fn forwardee_fingerprint(&self) -> &Fingerprint {
        &self.inner.forwardee_fingerprint
    }

    pub fn proxy_parameter(&self) -> &ForwardingProxyParameter {
        &self.proxy_parameter
    }
}

impl PrivateKey {
    pub fn generate_forwarding_key(
        &self,
        key_generation_time: Option<UnixTime>,
        user_id: &KeyUserId,
        profile: &Profile,
    ) -> crate::Result<(PrivateKey, Vec<ForwardingInstance>)> {
        generate_forwarding_key_inner(self, key_generation_time, user_id, profile)
            .map_err(Into::into)
    }
}

fn generate_forwarding_key_inner(
    secret_key: &PrivateKey,
    key_generation_time: Option<UnixTime>,
    user_id: &KeyUserId,
    profile: &Profile,
) -> Result<(PrivateKey, Vec<ForwardingInstance>), ForwardingKeyGenerationError> {
    if secret_key.version() != 4 {
        return Err(ForwardingKeyGenerationError::VersionMismatch(
            secret_key.version(),
        ));
    }

    let generation_time = key_generation_time
        .unwrap_or(UnixTime::now().ok_or(ForwardingKeyGenerationError::UnableToGetTime)?);

    // Check the key can encrypt
    secret_key
        .as_signed_public_key()
        .encryption_key(generation_time.into(), profile)
        .map_err(ForwardingKeyValidation::KeyValidation)
        .map_err(ForwardingKeyGenerationError::KeyValidation)?;

    //

    let primary = secret_key.secret.primary_key.public_key();
    let mut rng = profile.rng();

    let mut errors = Vec::new();
    let mut forwardee_subkeys = Vec::new();
    let mut forwarding_params = Vec::new();

    let (primary_secret_key, primary_pub_key) = generate_primary_key(
        KeyType::Ed25519Legacy,
        KeyVersion::V4,
        generation_time,
        &mut rng,
    )
    .map_err(ForwardingKeyGenerationError::GenerationPrimary)?;

    for sub_key in &secret_key.secret.secret_subkeys {
        if let Err(err) =
            check_subkey_for_forwarding(sub_key, primary, generation_time.into(), profile)
        {
            errors.push(ForwardingKeyValidation::KeyValidation(err));
            continue;
        }

        let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
            hash: forwarder_hash,
            alg_sym: forwarder_alg_sym,
            ..
        }) = sub_key.public_params()
        else {
            errors.push(ForwardingKeyValidation::SubKeyNoMatchingAlgorithm(
                sub_key.algorithm(),
            ));
            continue;
        };

        let forwarder_fingerprint = sub_key.fingerprint();
        let signed_subkey = generate_forwarding_encryption_subkey_and_sign(
            &primary_secret_key,
            &primary_pub_key,
            forwarder_fingerprint.clone(),
            *forwarder_hash,
            *forwarder_alg_sym,
            generation_time,
            &mut rng,
            profile,
        )
        .map_err(ForwardingKeyGenerationError::GenerationSubkey)?;

        let proxy_parameter = sub_key
            .key
            .generate_proxy_parameter(&signed_subkey.key, &Password::empty(), &Password::empty())
            .map_err(ForwardingKeyGenerationError::ProxyParamGeneration)?;

        let forwarding_instance = ForwardingInstance::new_inner(
            forwarder_fingerprint,
            signed_subkey.fingerprint(),
            proxy_parameter,
        )?;

        forwardee_subkeys.push(signed_subkey);
        forwarding_params.push(forwarding_instance);
    }

    if forwardee_subkeys.is_empty() {
        return Err(ForwardingKeyGenerationError::SubKeyValidation(
            errors.into(),
        ));
    }

    let key_generation_options = profile.default_key_generation_profile().build();
    let user_id = user_id
        .try_to_user_id()
        .map_err(ForwardingKeyGenerationError::UserID)?;
    let primary_flags = primary_key_flags();
    let key_details_config =
        key_generation_options.create_key_details_config(Some(user_id), Vec::new(), primary_flags);

    let signed_key_details = key_details_config
        .sign_with(
            &primary_secret_key,
            &primary_pub_key,
            generation_time,
            profile.key_hash_algorithm(),
            &mut rng,
            profile,
        )
        .map_err(|err| ForwardingKeyGenerationError::GenerationPrimary(err.into()))?;

    let signed_secret_key = SignedSecretKey::new(
        primary_secret_key,
        signed_key_details,
        Vec::new(),
        forwardee_subkeys,
    );

    let private_key = PrivateKey::new(signed_secret_key);

    Ok((private_key, forwarding_params))
}

/// The parameters a forwarding proxy needs to transform a PKESK that was
#[derive(Debug)]
pub(crate) struct ForwardingKeyDetails {
    forwarder_fingerprint: Fingerprint,
    forwardee_fingerprint: Fingerprint,
    forwardee_params: PublicParams,
}

impl ForwardingKeyDetails {
    /// Both fingerprints must be v4; forwarding is not defined for other key
    /// versions.
    fn new(
        forwarder_fingerprint: Fingerprint,
        forwardee_fingerprint: Fingerprint,
    ) -> Result<Self, ForwardingPkeskError> {
        let Fingerprint::V4(forwarder_bytes) = forwarder_fingerprint else {
            return Err(ForwardingPkeskError::UnsupportedKeyVersion(
                forwarder_fingerprint.version(),
            ));
        };
        if !matches!(forwardee_fingerprint, Fingerprint::V4(_)) {
            return Err(ForwardingPkeskError::UnsupportedKeyVersion(
                forwardee_fingerprint.version(),
            ));
        }
        Ok(Self {
            forwarder_fingerprint,
            forwardee_fingerprint,
            forwardee_params: forwardee_public_params(&forwarder_bytes),
        })
    }
}

/// Stands in for the forwardee key when transforming a PKESK.
impl KeyDetails for ForwardingKeyDetails {
    fn version(&self) -> KeyVersion {
        KeyVersion::V4
    }

    fn legacy_key_id(&self) -> KeyId {
        self.forwardee_fingerprint
            .key_id()
            .unwrap_or(KeyId::new([0_u8; 8]))
    }

    fn fingerprint(&self) -> Fingerprint {
        self.forwardee_fingerprint.clone()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyAlgorithm::ECDH
    }

    fn created_at(&self) -> Timestamp {
        Timestamp::from_secs(0)
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        None
    }

    fn public_params(&self) -> &PublicParams {
        &self.forwardee_params
    }
}

fn forwardee_public_params(forwarder_fingerprint: &[u8; 20]) -> PublicParams {
    PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
        p: x25519_dalek::PublicKey::from([0_u8; 32]),
        hash: HashAlgorithm::Sha256,
        alg_sym: SymmetricKeyAlgorithm::AES128,
        ecdh_kdf_type: EcdhKdfType::Replaced {
            replacement_fingerprint: *forwarder_fingerprint,
        },
    })
}
