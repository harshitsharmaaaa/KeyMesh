//! ParticipantIdentity — network identity separate from threshold signing share.
//! Compromising network identity does NOT expose signing share.

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;

#[derive(Clone, Debug)]
pub struct NetworkKeypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl NetworkKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key().clone();
        Self {
            signing_key,
            verifying_key,
        }
    }
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantIdentity {
    pub id: u8, // 0,1,2 for 2-of-3
    pub network_verifying_key: VerifyingKey,
    pub wallet: [u8; 20],
    pub chain_id: u64,
}

impl ParticipantIdentity {
    pub fn new(
        id: u8,
        network_verifying_key: VerifyingKey,
        wallet: [u8; 20],
        chain_id: u64,
    ) -> Self {
        Self {
            id,
            network_verifying_key,
            wallet,
            chain_id,
        }
    }
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.network_verifying_key.verify(msg, sig).is_ok()
    }
    /// Check that identity matches expected wallet/chain — prevents cross-wallet replay
    pub fn check_wallet(&self, wallet: &[u8; 20], chain_id: u64) -> bool {
        &self.wallet == wallet && self.chain_id == chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_identity_sign_verify() {
        let kp = NetworkKeypair::generate();
        let msg = b"hello keymesh";
        let sig = kp.sign(msg);
        let id = ParticipantIdentity::new(0, kp.verifying_key().clone(), [0x11; 20], 31337);
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"wrong", &sig));
    }
    #[test]
    fn wallet_binding() {
        let kp = NetworkKeypair::generate();
        let id = ParticipantIdentity::new(1, kp.verifying_key().clone(), [0xAA; 20], 11155111);
        assert!(id.check_wallet(&[0xAA; 20], 11155111));
        assert!(!id.check_wallet(&[0xBB; 20], 11155111));
        assert!(!id.check_wallet(&[0xAA; 20], 1));
    }
}
