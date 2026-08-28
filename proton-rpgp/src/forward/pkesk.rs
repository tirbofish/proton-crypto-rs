use std::io::BufRead;

use pgp::{
    crypto::public_key::PublicKeyAlgorithm,
    packet::{Packet, PacketParser, PacketTrait, PublicKeyEncryptedSessionKey},
    types::KeyId,
};

use crate::{FingerprintExt, ForwardingInstance, ForwardingTransformError};

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
            .map_err(ForwardingTransformError::Encode)?;
        Ok(bytes)
    }
}

impl From<ForwardedPkesk> for PublicKeyEncryptedSessionKey {
    fn from(value: ForwardedPkesk) -> Self {
        value.0
    }
}

/// A PKESK that is eligible to be transformed for a forwardee.
///
/// Only v3 PKESKs with the ECDH algorithm can be forwarded, so constructing
/// this type validates those two properties up front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingPkesk(PublicKeyEncryptedSessionKey);

impl ForwardingPkesk {
    /// Decodes the single PKESK packet contained in `bytes`.
    ///
    /// Fails if `bytes` holds no PKESK or more than one.
    pub fn from_bytes<R: BufRead>(bytes: R) -> crate::Result<Self> {
        let mut pkesks = Self::from_bytes_iter(bytes);
        let Some(pkesk) = pkesks.next() else {
            return Err(ForwardingTransformError::NoPkeskFound.into());
        };
        let pkesk = pkesk?;

        match pkesks.next() {
            None => {}
            Some(Err(err)) => return Err(err),
            Some(Ok(_)) => return Err(ForwardingTransformError::MultiplePkesks.into()),
        }

        Ok(pkesk)
    }

    /// Iterates over the PKESK packets in `bytes`, yielding an error for every
    /// packet that fails to parse or is not eligible for forwarding.
    pub fn from_bytes_iter<R: BufRead>(bytes: R) -> impl Iterator<Item = crate::Result<Self>> {
        PacketParser::new(bytes).filter_map(|packet| match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => Some(Self::try_from(pkesk)),
            Ok(_) => None,
            Err(err) => Some(Err(ForwardingTransformError::Parsing(err).into())),
        })
    }

    /// Checks that `pkesk` is eligible to be transformed for forwarding.
    pub fn valid(pkesk: &PublicKeyEncryptedSessionKey) -> crate::Result<()> {
        let PublicKeyEncryptedSessionKey::V3 { pk_algo, .. } = pkesk else {
            return Err(ForwardingTransformError::VersionMismatch(pkesk.version()).into());
        };
        if *pk_algo != PublicKeyAlgorithm::ECDH {
            return Err(ForwardingTransformError::AlgorithmMismatch(*pk_algo).into());
        }
        Ok(())
    }

    fn key_id(&self) -> Result<KeyId, ForwardingTransformError> {
        self.0
            .id()
            .copied()
            .map_err(|_| ForwardingTransformError::VersionMismatch(self.0.version()))
    }

    /// Transforms this PKESK with the [`ForwardingInstance`] in `instances` that
    /// matches its recipient key id.
    pub fn proxy_forward<'a>(
        &self,
        instances: impl IntoIterator<Item = &'a ForwardingInstance>,
    ) -> crate::Result<ForwardedPkesk> {
        let pkesk_key_id = self.key_id()?;
        let instance = instances
            .into_iter()
            .find(|instance| {
                instance
                    .forwarder_fingerprint()
                    .key_id()
                    .is_some_and(|key_id| key_id == pkesk_key_id)
            })
            .ok_or(ForwardingTransformError::NoMatchingInstance(pkesk_key_id))?;

        Ok(ForwardedPkesk(instance.transform(&self.0)?))
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
