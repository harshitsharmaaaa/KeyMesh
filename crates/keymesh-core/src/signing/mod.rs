//! Signing service boundary.
//!
//! The protocol never touches raw private keys directly; it goes through
//! [`SigningService`]. This keeps the future threshold-signing (MPC)
//! implementation behind the same interface as the mock.
//!
//! ## Maturity: PROTOTYPE
//!
//! The only implementation is [`MockSigningService`], which delegates to the
//! insecure [`MockCryptoProvider`](crate::crypto::MockCryptoProvider). It is
//! for tests and local development ONLY.

pub mod tss;

use crate::crypto::{CryptoProvider, MockCryptoProvider, PrivateKeyBytes, SignatureBytes};
use crate::errors::KeymeshError;

/// Domain-separated message prefixes. Real deployments must use distinct,
/// versioned domains to prevent replay across message classes
/// (see docs/security/threat-model.md — "signature misuse").
pub enum SigningDomain {
    TransactionAuthorization,
    RecoveryApproval,
    DeviceRegistration,
}

impl SigningDomain {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            SigningDomain::TransactionAuthorization => b"KEYMESH/tx-auth/v1",
            SigningDomain::RecoveryApproval => b"KEYMESH/recovery/v1",
            SigningDomain::DeviceRegistration => b"KEYMESH/device-reg/v1",
        }
    }
}

/// Signs domain-separated messages on behalf of key material it controls.
pub trait SigningService {
    fn sign_message(
        &self,
        key: &PrivateKeyBytes,
        domain: SigningDomain,
        payload: &[u8],
    ) -> Result<SignatureBytes, KeymeshError>;
}

/// Insecure mock signing service (test/local development only).
#[derive(Debug, Default, Clone, Copy)]
pub struct MockSigningService {
    provider: MockCryptoProvider,
}

impl MockSigningService {
    /// Concatenates the domain tag and payload, then signs with the mock
    /// provider. Deterministic and INSECURE by construction.
    fn composite(domain: &SigningDomain, payload: &[u8]) -> Vec<u8> {
        let mut msg = domain.as_bytes().to_vec();
        msg.push(0x00);
        msg.extend_from_slice(payload);
        msg
    }
}

impl SigningService for MockSigningService {
    fn sign_message(
        &self,
        key: &PrivateKeyBytes,
        domain: SigningDomain,
        payload: &[u8],
    ) -> Result<SignatureBytes, KeymeshError> {
        self.provider.sign(key, &Self::composite(&domain, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        let service = MockSigningService::default();
        let key = PrivateKeyBytes(vec![0x11; 32]);

        let tx_sig = service
            .sign_message(&key, SigningDomain::TransactionAuthorization, b"abc")
            .unwrap();
        let rec_sig = service
            .sign_message(&key, SigningDomain::RecoveryApproval, b"abc")
            .unwrap();

        assert_ne!(
            tx_sig, rec_sig,
            "same payload under different domains must not collide"
        );
    }

    #[test]
    fn rejects_empty_keys() {
        let service = MockSigningService::default();
        let err = service
            .sign_message(
                &PrivateKeyBytes(vec![]),
                SigningDomain::RecoveryApproval,
                b"x",
            )
            .unwrap_err();
        assert!(matches!(err, KeymeshError::CryptoOperationFailed(_)));
    }

    #[test]
    fn signatures_are_deterministic_for_fixed_keys() {
        let service = MockSigningService::default();
        let key = PrivateKeyBytes(vec![0x11; 32]);
        let a = service
            .sign_message(&key, SigningDomain::DeviceRegistration, b"payload")
            .unwrap();
        let b = service
            .sign_message(&key, SigningDomain::DeviceRegistration, b"payload")
            .unwrap();
        assert_eq!(a, b);
    }
}
