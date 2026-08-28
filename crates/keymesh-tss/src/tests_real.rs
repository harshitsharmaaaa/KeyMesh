#[cfg(test)]
mod real_tests {
    use crate::dkg::setup_2of3;
    use crate::session::{derive_session_id, SessionBinding, SigningSession, SigningSessionStatus};
    use crate::signing::{threshold_sign, verify_signature};
    use crate::transport::SimulatedTransport;

    fn dummy_binding(digest: [u8; 32], random: [u8; 32]) -> SessionBinding {
        SessionBinding {
            wallet: hex::decode("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
                .unwrap()
                .try_into()
                .unwrap(),
            chain_id: 31337,
            nonce: 0,
            digest,
            policy_version: 1,
            signing_protocol_version: "synedrion/0.3-cggmp24".into(),
            random,
        }
    }

    fn keymesh_digest() -> [u8; 32] {
        hex::decode("ef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    #[ignore = "heavy synedrion DKG — run on Linux CI with --ignored"]
    fn dkg_succeeds_and_group_key_stable() {
        let mat = setup_2of3().expect("dkg");
        assert_eq!(mat.participants.len(), 3);
        let vk = mat.group_public_key.verifying_key;
        for p in &mat.participants {
            assert_eq!(p.verifying_key(), vk);
        }
        assert_eq!(
            mat.group_public_key.ethereum_address,
            crate::ethereum_address_from_verifying_key(&vk)
        );
    }

    #[test]
    #[ignore = "heavy"]
    fn threshold_2of3_all_pairs_succeed_single_fails_real() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0x11; 32]);
        let sid = derive_session_id(&binding);
        assert!(threshold_sign(&mat, &[0, 1], &binding, &sid).is_ok());
        assert!(threshold_sign(&mat, &[0, 2], &binding, &sid).is_ok());
        assert!(threshold_sign(&mat, &[1, 2], &binding, &sid).is_ok());
        assert!(threshold_sign(&mat, &[0], &binding, &sid).is_err());
        assert!(threshold_sign(&mat, &[1], &binding, &sid).is_err());
        assert!(threshold_sign(&mat, &[2], &binding, &sid).is_err());
    }

    #[test]
    #[ignore = "heavy"]
    fn final_signature_low_s_and_recovers_real() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0x22; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(&mat, &[0, 1], &binding, &sid).expect("sign");
        assert_ne!(sig.r, [0u8; 32]);
        assert_ne!(sig.s, [0u8; 32]);
        assert!(sig.s_is_low());
        assert!(sig.v == 27 || sig.v == 28);
        assert!(verify_signature(
            &digest,
            &sig,
            &mat.group_public_key.verifying_key
        ));
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(!verify_signature(
            &wrong,
            &sig,
            &mat.group_public_key.verifying_key
        ));
    }

    #[test]
    #[ignore = "heavy"]
    fn signature_randomness_fresh_valid() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding1 = dummy_binding(digest, [0x33; 32]);
        let sid1 = derive_session_id(&binding1);
        let sig1 = threshold_sign(&mat, &[0, 1], &binding1, &sid1).unwrap();
        let binding2 = dummy_binding(digest, [0x44; 32]);
        let sid2 = derive_session_id(&binding2);
        let sig2 = threshold_sign(&mat, &[0, 1], &binding2, &sid2).unwrap();
        assert!(verify_signature(
            &digest,
            &sig1,
            &mat.group_public_key.verifying_key
        ));
        assert!(verify_signature(
            &digest,
            &sig2,
            &mat.group_public_key.verifying_key
        ));
    }

    #[test]
    #[ignore = "heavy"]
    fn digest_binding_wrong_digest_rejected() {
        let mat = setup_2of3().expect("dkg");
        let digest_a = [0x11u8; 32];
        let digest_b = [0x22u8; 32];
        let binding_a = dummy_binding(digest_a, [0x55; 32]);
        let sid_a = derive_session_id(&binding_a);
        let sig_a = threshold_sign(&mat, &[0, 1], &binding_a, &sid_a).unwrap();
        assert!(!verify_signature(
            &digest_b,
            &sig_a,
            &mat.group_public_key.verifying_key
        ));
        let binding_b = dummy_binding(digest_b, [0x55; 32]);
        assert!(threshold_sign(&mat, &[0, 1], &binding_b, &sid_a).is_err());
    }

    #[test]
    #[ignore = "heavy"]
    fn session_replay_rejected() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0x66; 32]);
        let sid = derive_session_id(&binding);
        let _sig = threshold_sign(&mat, &[0, 1], &binding, &sid).unwrap();
        let binding2 = dummy_binding(digest, [0x77; 32]);
        let sid2 = derive_session_id(&binding2);
        assert_ne!(sid, sid2);
        assert!(threshold_sign(&mat, &[0, 1], &binding2, &sid).is_err());
        let mut wrong = digest;
        wrong[5] ^= 1;
        let binding_wrong = dummy_binding(wrong, [0x66; 32]);
        assert!(threshold_sign(&mat, &[0, 1], &binding_wrong, &sid).is_err());
    }

    #[test]
    #[ignore = "heavy"]
    fn participant_identity_duplicate_fails() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0x88; 32]);
        let sid = derive_session_id(&binding);
        assert!(threshold_sign(&mat, &[0, 0], &binding, &sid).is_err());
    }

    #[test]
    fn transport_simulator_checks() {
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
        t.duplicate_first();
        assert!(t.check_no_duplicate().is_err());
        let mut t2 = SimulatedTransport::new();
        t2.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 99,
            payload: vec![],
            digest,
        });
        assert!(t2.check_round_order().is_err());
        t2 = SimulatedTransport::new();
        t2.send(crate::transport::TransportMessage {
            session_id: sid,
            sender: 1,
            round: 1,
            payload: vec![],
            digest,
        });
        t2.modify_first_digest([0xff; 32]);
        assert!(t2.verify_binding(&sid, &digest).is_err());
    }

    #[test]
    fn abort_terminal() {
        let mut sess = SigningSession::new(dummy_binding([0xaa; 32], [0xbb; 32]), vec![1, 2], 2);
        assert_eq!(sess.status, SigningSessionStatus::Started);
        sess.transition(SigningSessionStatus::Aborted).unwrap();
        assert!(sess.transition(SigningSessionStatus::Completed).is_err());
        let sid_old = sess.session_id.clone();
        let binding2 = dummy_binding([0xaa; 32], [0xcc; 32]);
        let sid2 = derive_session_id(&binding2);
        assert_ne!(sid_old, sid2);
    }

    #[test]
    #[ignore = "heavy"]
    fn no_reconstruction_exposed() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0xdd; 32]);
        let sid = derive_session_id(&binding);
        assert!(threshold_sign(&mat, &[0], &binding, &sid).is_err());
    }

    #[test]
    #[ignore = "heavy"]
    fn ethereum_address_stable_across_signing() {
        let mat = setup_2of3().expect("dkg");
        let addr = mat.group_public_key.ethereum_address;
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0xee; 32]);
        let sid = derive_session_id(&binding);
        let sig = threshold_sign(&mat, &[1, 2], &binding, &sid).unwrap();
        assert!(verify_signature(
            &digest,
            &sig,
            &mat.group_public_key.verifying_key
        ));
        assert_eq!(addr, mat.group_public_key.ethereum_address);
    }

    #[test]
    #[ignore = "heavy"]
    fn offline_participant_still_succeeds() {
        let mat = setup_2of3().expect("dkg");
        let digest = keymesh_digest();
        let binding = dummy_binding(digest, [0x99; 32]);
        let sid = derive_session_id(&binding);
        assert!(threshold_sign(&mat, &[0, 1], &binding, &sid).is_ok());
        assert!(threshold_sign(&mat, &[0], &binding, &sid).is_err());
    }
}
