//! Cross-language vectors for TSS prototype.
//! Deterministic via ChaCha20Rng seed so TS/Solidity can pin.

#[cfg(test)]
mod vectors {
    use crate::dkg::distributed_keygen;
    use crate::session::{derive_session_id, SessionBinding};
    use crate::signature::{threshold_sign, verify_signature};
    use k256::{elliptic_curve::Field, Scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Deterministic helpers for vector generation (not used in production DKG)
    pub fn seeded_scalar(seed: u64) -> Scalar {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        loop {
            let s = Scalar::random(&mut rng);
            if !bool::from(s.is_zero()) {
                return s;
            }
        }
    }

    #[test]
    fn cross_language_vector_print() {
        // This test prints a vector that can be copied to TS/Solidity.
        // Use seeded DKG to make deterministic for cross-language pinning.
        let mat = crate::dkg::distributed_keygen_seeded(3, 2, 0xdeadbeefcafe1234);
        let digest =
            hex::decode("ef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a")
                .unwrap();
        let digest_arr: [u8; 32] = digest.try_into().unwrap();
        let binding = SessionBinding {
            wallet: hex::decode("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
                .unwrap()
                .try_into()
                .unwrap(),
            chain_id: 31337,
            nonce: 0,
            digest: digest_arr,
            policy_version: 1,
            signing_protocol_version: "cggmp21/v1".into(),
            random: [0x99; 32],
        };
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        assert!(verify_signature(
            &digest_arr,
            &sig,
            &mat.group_verifying_key
        ));
        // Print for manual copy
        println!("GROUP_ADDRESS=0x{}", hex::encode(mat.ethereum_address));
        println!("DIGEST=0x{}", hex::encode(digest_arr));
        println!("R=0x{}", hex::encode(sig.r));
        println!("S=0x{}", hex::encode(sig.s));
        println!("V={}", sig.v);
        println!("SESSION_ID={}", sid.to_hex());
    }
}
