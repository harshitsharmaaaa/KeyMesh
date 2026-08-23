//! Cryptographic provider boundary.
//!
//! ## SECURITY BOUNDARY — read before implementing
//!
//! Nothing in this module is production cryptography. The [`MockCryptoProvider`]
//! is a deterministic, **insecure** placeholder for tests and local
//! development only. It must never be compiled into anything that touches real
//! keys or funds.
//!
//! Phase 2 requirements for a real provider:
//!
//! - Use well-reviewed, audited libraries (e.g. for secp256k1: `k256` or
//!   `secp256k1-sys`; for threshold schemes: established TSS libraries).
//! - Never hand-roll curve arithmetic, hashing, or nonce generation.
//! - Constant-time comparisons on all secret material.
//! - Zeroization of key material on drop.
//!
//! TODO(phase-2): introduce the reviewed implementation behind this trait and
//! gate the mock behind a feature flag (e.g. `unsafe-mock-crypto`) that is off
//! by default.

use crate::errors::KeymeshError;

/// Curve identifiers supported by the protocol surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// secp256k1 (Ethereum / Bitcoin).
    Secp256k1,
    /// ed25519 (planned Solana support).
    Ed25519,
}

/// A signature produced by a [`CryptoProvider`].
///
/// Bytes are opaque at this boundary; interpretation belongs to the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes(pub Vec<u8>);

/// A public key produced by a [`CryptoProvider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyBytes(pub Vec<u8>);

/// A private key handle owned by a [`CryptoProvider`].
///
/// Implementations MUST zeroize memory on drop. The mock does not hold any
/// secret-like material beyond test fixtures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyBytes(pub Vec<u8>);

/// The cryptographic operations the protocol needs.
///
/// Every method returns [`KeymeshError::CryptoOperationFailed`] on invalid
/// inputs rather than panicking; callers cannot be crashed into inconsistent
/// states via malformed keys or messages.
pub trait CryptoProvider {
    fn generate_keypair(&self, curve: Curve) -> Result<(PrivateKeyBytes, PublicKeyBytes), KeymeshError>;

    fn public_key(&self, private_key: &PrivateKeyBytes) -> Result<PublicKeyBytes, KeymeshError>;

    fn sign(
        &self,
        private_key: &PrivateKeyBytes,
        message: &[u8],
    ) -> Result<SignatureBytes, KeymeshError>;

    fn verify(
        &self,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<bool, KeymeshError>;
}

/// Deterministic, insecure provider for tests and local development only.
///
/// "Signatures" are length-prefixed copies of the message concatenated with a
/// fixed tag so tests can assert exact bytes. This is NOT a signature scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockCryptoProvider;

const MOCK_TAG: &[u8] = b"KEYMESH-MOCK-NOT-A-SIGNATURE";

impl CryptoProvider for MockCryptoProvider {
    fn generate_keypair(&self, _curve: Curve) -> Result<(PrivateKeyBytes, PublicKeyBytes), KeymeshError> {
        // Deterministic fixture values; no entropy is consumed on purpose so
        // tests are reproducible.
        Ok((
            PrivateKeyBytes(vec![0x11; 32]),
            PublicKeyBytes(vec![0x22; 33]),
        ))
    }

    fn public_key(&self, private_key: &PrivateKeyBytes) -> Result<PublicKeyBytes, KeymeshError> {
        if private_key.0.is_empty() {
            return Err(KeymeshError::CryptoOperationFailed(
                "empty private key".into(),
            ));
        }
        Ok(PublicKeyBytes(vec![0x22; 33]))
    }

    fn sign(&self, private_key: &PrivateKeyBytes, message: &[u8]) -> Result<SignatureBytes, KeymeshError> {
        if private_key.0.is_empty() {
            return Err(KeymeshError::CryptoOperationFailed("empty private key".into()));
        }
        let mut out = MOCK_TAG.to_vec();
        out.extend_from_slice(&(message.len() as u64).to_be_bytes());
        out.extend_from_slice(message);
        Ok(SignatureBytes(out))
    }

    fn verify(
        &self,
        public_key: &PublicKeyBytes,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> Result<bool, KeymeshError> {
        if public_key.0.is_empty() {
            return Err(KeymeshError::CryptoOperationFailed("empty public key".into()));
        }
        let expected = self.sign(&PrivateKeyBytes(vec![0x11; 32]), message)?;
        Ok(expected.0 == signature.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_signatures_roundtrip() {
        let provider = MockCryptoProvider;
        let (sk, pk) = provider.generate_keypair(Curve::Secp256k1).unwrap();
        let msg = b"hello keymesh";
        let sig = provider.sign(&sk, msg).unwrap();
        assert!(provider.verify(&pk, msg, &sig).unwrap());
        assert!(!provider.verify(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn empty_keys_are_rejected_not_panics() {
        let provider = MockCryptoProvider;
        let err = provider.sign(&PrivateKeyBytes(vec![]), b"m").unwrap_err();
        assert!(matches!(err, KeymeshError::CryptoOperationFailed(_)));
    }
}
