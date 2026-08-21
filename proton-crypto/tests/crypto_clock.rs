//! Tests that mutate the global crypto clock.

use std::sync::{Mutex, MutexGuard, PoisonError};

use proton_crypto::{
    crypto::{
        DataEncoding, KeyGenerator, KeyGeneratorSync, PGPProvider, PGPProviderSync, UnixTimestamp,
        Verifier, VerifierSync, CLOCK_SKEW_KEY_GENERATION, CLOCK_SKEW_VERIFICATION,
    },
    crypto_clock, CryptoClockProvider, ProtonPGP,
};

pub mod common;
use common::{TEST_EXPECTED_PLAINTEXT, TEST_PGP_PUBLIC_KEY, TEST_SIGNATURE};

static CLOCK_LOCK: Mutex<()> = Mutex::new(());

fn lock_clock() -> MutexGuard<'static, ()> {
    CLOCK_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn set_clock(time: UnixTimestamp) {
    crypto_clock().set_provider(Box::new(FixedCryptoClockProvider(time)));
}

#[derive(Debug)]
struct FixedCryptoClockProvider(UnixTimestamp);

impl CryptoClockProvider for FixedCryptoClockProvider {
    fn unix_time(&self) -> UnixTimestamp {
        self.0
    }
}

#[test]
fn test_api_verify_detached_signature_clock_skew() {
    let _guard = lock_clock();
    let provider = ProtonPGP::new_sync();
    set_clock(UnixTimestamp::new(1_706_017_671 - CLOCK_SKEW_VERIFICATION));

    let public_key = provider
        .public_key_import(TEST_PGP_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .verify_detached(TEST_EXPECTED_PLAINTEXT, TEST_SIGNATURE, DataEncoding::Armor);
    assert!(verification_result.is_ok());

    set_clock(UnixTimestamp::new(
        1_706_017_671 - CLOCK_SKEW_VERIFICATION - 1,
    ));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .verify_detached(TEST_EXPECTED_PLAINTEXT, TEST_SIGNATURE, DataEncoding::Armor);
    assert!(verification_result.is_err());
}

#[test]
fn test_key_generation_clock_skew() {
    let _guard = lock_clock();
    let provider = ProtonPGP::new_sync();
    let test_time = UnixTimestamp::new(1_706_017_671);
    set_clock(test_time);

    let generated_key = provider
        .new_key_generator()
        .with_user_id("test", "test@test.test")
        .generate()
        .expect("key should be generated");
    let raw = provider
        .private_key_export_unlocked(&generated_key, DataEncoding::Bytes)
        .expect("key should be exported");

    let expected = (test_time.value() - CLOCK_SKEW_KEY_GENERATION).to_be_bytes();
    assert!(raw
        .as_ref()
        .windows(4)
        .any(|window| window == &expected[4..]));
}
