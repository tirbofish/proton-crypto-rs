# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-00-00

## [0.5.0] - 2026-07-02

### Added

- Adds the AEAD Seipdv2 API for proton-rpgp.
- `HAZARD_AEAD_PROFILE`: profile with AEAD enabled by default
- New `with_aead` and `with_aead_chunk_size` method on the Encryptor for AEAD encryption.
- `is_seipdv2_aead` on the `SessionKey` type

### Changed

- Bump `pgp` to `0.20.0`: Fixes an issue where decrypting or verifying empty messages triggerd an error.

## [0.4.0] - 2026-06-05

### Changed

- Allow streaming verification of an empty message with a detached signature.

- BREAKING: `PrivateKey::import` now throws an error if the key is not locked. Unifies the behaviour with gopenpgp-sys and improves security.

- On unlocking a locked key, validate that the primary key’s public parameters match the just-decrypted secret values. This thwarts tampering with unauthenticated public material and hardens key security.

- BREAKING: Removed the `asm` feature flag due to dangerous instability on apple arm (Apple clang 21 (CLT 26.5)). 

## [0.3.3] - 2026-04-17

### Fixed

- Fixed `VerificationResultUtility::selected_signature_bytes` to return only the selected signature bytes rather than all signatures bytes.

## [0.3.2] - 2026-04-16

### Fixed

- Compression while writing messages is now applied only when explicitly enabled through the API or user profile independant of the key preferences.

## [0.3.1] - 2026-03-23

### Added

- Add API for importing multiple private keys from a blob.

## [0.3.0] - 2026-03-13

### Changed

- Removed the `wasm` feature flag
- Enable wasm32 target build without adding any external dependencies.

## [0.2.0] - 2026-03-03

### Added

- Support for modifying keys.
- Allow to collect information about the encryption process in the encryptor.

## [0.1.0] - 2026-02-10

### Added

- Initial release of the `proton-rpgp` crate.
