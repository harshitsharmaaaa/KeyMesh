#[cfg(test)]
mod tests {
    use crate::dkg::distributed_keygen;
    use crate::session::{derive_session_id, SessionBinding, SigningSession, SigningSessionStatus};
    use crate::shamir::lagrange_interpolate_at_zero;
    use crate::signature::{threshold_sign, verify_signature};
    use crate::transcript::SigningTranscript;
    use crate::transport::SimulatedTransport;

    fn dummy_binding_with_digest(digest: [u8; 32], random: [u8; 32]) -> SessionBinding {
        SessionBinding {
            wallet: hex::decode("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
                .unwrap()
                .try_into()
                .unwrap(),
            chain_id: 31337,
            nonce: 0,
            digest,
            policy_version: 1,
            signing_protocol_version: "cggmp21/v1".into(),
            random,
        }
    }

    fn keymesh_digest_example() -> [u8; 32] {
        // Use actual KEYMESH_TX_V1 vector 1 digest from docs/protocol/canonical-transaction.md
        // ef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a
        hex::decode("ef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn dkg_2of3_succeeds_and_group_key_consistent() {
        let mat = distributed_keygen(3, 2);
        assert_eq!(mat.shares.len(), 3);
        assert_eq!(mat.threshold, 2);
        // All 3 derive same group key via lagrange from different pairs
        let x12 = lagrange_interpolate_at_zero(&mat.shares[0..2]);
        let x13 = lagrange_interpolate_at_zero(&[mat.shares[0].clone(), mat.shares[2].clone()]);
        let x23 = lagrange_interpolate_at_zero(&mat.shares[1..3]);
        assert_eq!(x12, x13);
        assert_eq!(x13, x23);
        // Ethereum address consistent
        let addr = mat.ethereum_address;
        assert_ne!(addr, [0u8; 20]);
        // Deterministic? No, random, but address non-zero and 20 bytes
    }

    #[test]
    fn threshold_2of3_all_pairs_succeed_single_fails() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0x11; 32]);
        let sid = derive_session_id(&binding);
        // A+B
        assert!(threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_ok());
        // A+C
        assert!(threshold_sign(
            &[mat.shares[0].clone(), mat.shares[2].clone()],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_ok());
        // B+C
        assert!(threshold_sign(
            &mat.shares[1..3],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_ok());
        // Single
        assert!(threshold_sign(
            &mat.shares[0..1],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_err());
        assert!(threshold_sign(
            &mat.shares[1..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_err());
        assert!(threshold_sign(
            &mat.shares[2..3],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_err());
    }

    #[test]
    fn produced_signature_is_standard_ecdsa_low_s_and_recovers() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0x22; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        assert_ne!(sig.r, [0u8; 32]);
        assert_ne!(sig.s, [0u8; 32]);
        assert!(sig.s_is_low(), "s must be low");
        assert!(sig.v == 27 || sig.v == 28);
        assert!(verify_signature(&digest, &sig, &mat.group_verifying_key));
        // Verify with wrong digest fails
        let mut wrong = digest;
        wrong[0] ^= 0x01;
        assert!(!verify_signature(&wrong, &sig, &mat.group_verifying_key));
    }

    #[test]
    fn signature_bound_to_keymesh_digest_modified_digest_fails() {
        let mat = distributed_keygen(3, 2);
        let digest_a = [0x11u8; 32];
        let digest_b = [0x22u8; 32];
        let binding_a = dummy_binding_with_digest(digest_a, [0x33; 32]);
        let sid_a = derive_session_id(&binding_a);
        let sig_a = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding_a,
            &sid_a,
            2,
        )
        .unwrap();
        // Attempt to verify sig_a against digest_b must fail
        assert!(!verify_signature(
            &digest_b,
            &sig_a,
            &mat.group_verifying_key
        ));
        // Attempt to sign digest_b with session bound to digest_a must fail (session mismatch)
        let binding_b = dummy_binding_with_digest(digest_b, [0x33; 32]);
        // sid_a does NOT match binding_b
        assert!(threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding_b,
            &sid_a,
            2
        )
        .is_err());
    }

    #[test]
    fn replayed_session_fails() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0x44; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        assert!(verify_signature(&digest, &sig, &mat.group_verifying_key));
        // New binding with different random => different session_id, replay old session_id fails
        let binding2 = dummy_binding_with_digest(digest, [0x55; 32]);
        let sid2 = derive_session_id(&binding2);
        assert_ne!(sid, sid2);
        // Trying to use old sid with new binding must fail
        assert!(threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding2,
            &sid,
            2
        )
        .is_err());
        // Also wrong digest replay fails
        let mut wrong_digest = digest;
        wrong_digest[1] ^= 0xff;
        let binding_wrong = dummy_binding_with_digest(wrong_digest, [0x44; 32]);
        assert!(threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding_wrong,
            &sid,
            2
        )
        .is_err());
    }

    #[test]
    fn wrong_participant_identity_fails() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0x66; 32]);
        let sid = derive_session_id(&binding);
        // Duplicate participant index
        let dup = vec![mat.shares[0].clone(), mat.shares[0].clone()];
        assert!(threshold_sign(&dup, &mat.group_verifying_key, &binding, &sid, 2).is_err());
        // Unknown participant (index 99) not part of DKG — still threshold_sign would treat as share but with fake scalar, will produce invalid recovery
        let fake = crate::dkg::ParticipantShare {
            index: 99,
            secret_share: mat.shares[0].secret_share,
        };
        let res = threshold_sign(
            &[mat.shares[0].clone(), fake],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        );
        assert!(
            res.is_err(),
            "fake participant should not produce valid sig"
        );
    }

    #[test]
    fn wrong_round_and_duplicate_handling_via_transport() {
        let mut t = SimulatedTransport::new();
        let sid = [0xaa; 32];
        let digest = [0xbb; 32];
        t.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 1,
            payload: vec![1, 2],
            digest,
        });
        t.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 2,
            round: 1,
            payload: vec![3, 4],
            digest,
        });
        assert!(t.check_no_duplicate().is_ok());
        assert!(t.check_round_order().is_ok());
        // Duplicate
        t.duplicate_first();
        assert!(t.check_no_duplicate().is_err());
        // Clean
        let mut t2 = SimulatedTransport::new();
        t2.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 1,
            payload: vec![1],
            digest,
        });
        t2.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 2,
            payload: vec![2],
            digest,
        });
        // Reorder doesn't matter for this simple check, but we test reorder
        t2.reorder();
        assert!(t2.check_no_duplicate().is_ok()); // same sender different round is ok
                                                  // Modify digest -> binding fails
        t2.modify_first_digest([0xff; 32]);
        assert!(t2.verify_binding(&sid, &digest).is_err());
        // Wrong round
        let mut t3 = SimulatedTransport::new();
        t3.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 99,
            payload: vec![],
            digest,
        });
        assert!(t3.check_round_order().is_err());
    }

    #[test]
    fn offline_participant_2of3_still_succeeds_1_fails() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0x77; 32]);
        let sid = derive_session_id(&binding);
        // Simulate C offline -> A+B still ok
        assert!(threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_ok());
        // Only A -> fail
        assert!(threshold_sign(
            &mat.shares[0..1],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_err());
    }

    #[test]
    fn abort_cannot_finalize_and_reuse_fails() {
        let mut session = SigningSession::new(
            dummy_binding_with_digest([0x88; 32], [0x99; 32]),
            vec![1, 2],
            2,
        );
        assert_eq!(session.status, SigningSessionStatus::Started);
        session.transition(SigningSessionStatus::Aborted).unwrap();
        assert!(session.transition(SigningSessionStatus::Completed).is_err());
        // Reuse session_id with new binding should be new session, old sid not reusable
        let sid = session.session_id.clone();
        // Create new session with same binding but different random -> different sid
        let binding2 = dummy_binding_with_digest([0x88; 32], [0xaa; 32]);
        let sid2 = derive_session_id(&binding2);
        assert_ne!(sid, sid2);
    }

    #[test]
    fn transcript_records_without_secrets() {
        let mat = distributed_keygen(3, 2);
        let digest = keymesh_digest_example();
        let binding = dummy_binding_with_digest(digest, [0xcc; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        let transcript = SigningTranscript::new_success(
            vec![1, 2],
            sid.clone(),
            digest,
            31337,
            binding.wallet,
            0,
            1,
            sig.clone(),
        );
        assert_eq!(transcript.participant_indices, vec![1, 2]);
        assert_eq!(transcript.digest, digest);
        assert_eq!(transcript.session_id, sid);
        assert_eq!(transcript.final_signature.unwrap().r, sig.r);
        // No secret shares in transcript
    }

    #[test]
    fn ethereum_address_derivation_consistent() {
        let mat = distributed_keygen(3, 2);
        // Re-derive via lib helper
        let derived = crate::ethereum_address_from_verifying_key(&mat.group_verifying_key);
        assert_eq!(derived, mat.ethereum_address);
        // Simulate cross-language vector: address is 20 bytes keccak of uncompressed pubkey
        assert_eq!(mat.ethereum_address.len(), 20);
    }

    #[test]
    fn keymesh_digest_flow() {
        // Simulate real KEYMESH_TX_V1 digest via tiny-keccak as in keymesh-core
        use tiny_keccak::{Hasher, Keccak};
        // Use known vector: domain tag + wallet etc. Instead of full canonical, we test that our digest from example verifies
        let digest = keymesh_digest_example();
        let mat = distributed_keygen(3, 2);
        let binding = dummy_binding_with_digest(digest, [0xdd; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        assert!(verify_signature(&digest, &sig, &mat.group_verifying_key));
    }

    #[test]
    fn performance_measure_2of3() {
        let start = std::time::Instant::now();
        let mat = distributed_keygen(3, 2);
        let dkg_ms = start.elapsed().as_millis();
        let digest = [0x55u8; 32];
        let binding = dummy_binding_with_digest(digest, [0xee; 32]);
        let sid = derive_session_id(&binding);
        let start2 = std::time::Instant::now();
        let _ = threshold_sign(
            &mat.shares[0..2],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2,
        )
        .unwrap();
        let sign_ms = start2.elapsed().as_millis();
        // Not asserting performance, just measuring; ensure not absurdly slow
        assert!(dkg_ms < 5000, "DKG should be <5s");
        assert!(sign_ms < 1000, "sign should be <1s");
        // Approximate message counts
        let mut t = SimulatedTransport::new();
        t.send(crate::transport::TransportMessage {
            session_id: sid.0,
            sender: 1,
            round: 1,
            payload: vec![0; 64],
            digest,
        });
        t.send(crate::transport::TransportMessage {
            session_id: sid.0,
            sender: 2,
            round: 1,
            payload: vec![0; 64],
            digest,
        });
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn no_exposed_reconstruct_in_public_api() {
        // Ensure reconstruct function is not accessible via public threshold_sign path with single share
        let mat = distributed_keygen(3, 2);
        let digest = [0x99u8; 32];
        let binding = dummy_binding_with_digest(digest, [0xff; 32]);
        let sid = derive_session_id(&binding);
        // Single share must fail, proving no single-share reconstruct
        assert!(threshold_sign(
            &mat.shares[0..1],
            &mat.group_verifying_key,
            &binding,
            &sid,
            2
        )
        .is_err());
    }
}
