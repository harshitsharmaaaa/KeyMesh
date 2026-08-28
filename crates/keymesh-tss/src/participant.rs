//! Participant state — wrappers around synedrion types.
//! No private key reconstruction; each participant holds its own ThresholdKeyShare and AuxInfo.

use manul::dev::{TestSigner, TestVerifier};
use synedrion::k256::ProductionParams112;
use synedrion::{AuxInfo, ThresholdKeyShare};

pub type Params = ProductionParams112;
pub type ThresholdShare = ThresholdKeyShare<Params, TestVerifier>;
pub type Aux = AuxInfo<Params, TestVerifier>;

#[derive(Clone)]
pub struct Participant {
    pub index: u8,
    pub signer: TestSigner,
    pub verifier: TestVerifier,
    pub threshold_share: ThresholdShare,
    pub aux_info: Aux,
}

impl Participant {
    pub fn verifying_key(&self) -> k256::ecdsa::VerifyingKey {
        // ThresholdKeyShare::verifying_key returns the group key
        self.threshold_share.verifying_key().expect("verifying key")
    }
    pub fn ethereum_address(&self) -> [u8; 20] {
        crate::ethereum_address_from_verifying_key(&self.verifying_key())
    }
}
