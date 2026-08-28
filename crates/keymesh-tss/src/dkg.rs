use std::collections::{BTreeMap, BTreeSet};

use manul::dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier};
use manul::signature::Keypair;
use rand_core::OsRng;
use synedrion::{AuxGen, KeyInit, KeyResharing, NewHolder, OldHolder, ThresholdKeyShare};

use crate::errors::TssError;
use crate::participant::{Params, Participant, ThresholdShare};

#[derive(Clone, Debug)]
pub struct GroupPublicKey {
    pub verifying_key: k256::ecdsa::VerifyingKey,
    pub ethereum_address: [u8; 20],
}

#[derive(Clone)]
pub struct ThresholdKeyMaterial {
    pub participants: Vec<Participant>,
    pub group_public_key: GroupPublicKey,
    pub threshold: usize,
    pub total: usize,
}

fn make_signers(n: usize) -> (Vec<TestSigner>, Vec<TestVerifier>) {
    let signers = (0..n).map(|i| TestSigner::new(i as u8)).collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|s| s.verifying_key())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

/// Setup 2-of-3 network via real synedrion DKG + resharing + AuxGen.
/// No trusted dealer — each participant contributes via KeyInit/KeyResharing.
pub fn setup_2of3() -> Result<ThresholdKeyMaterial, TssError> {
    setup_2of3_with_rng(&mut OsRng)
}

pub fn setup_2of3_with_rng<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> Result<ThresholdKeyMaterial, TssError> {
    let t = 2usize;
    let n = 3usize;
    let (signers, verifiers) = make_signers(n);
    let all_verifiers: BTreeSet<TestVerifier> = verifiers.iter().cloned().collect();
    let old_holders: BTreeSet<TestVerifier> = verifiers.iter().take(t).cloned().collect();

    // KeyInit with t participants (t-of-t)
    let entry_points = signers[..t]
        .iter()
        .map(|s| {
            let ep = KeyInit::<Params, TestVerifier>::new(old_holders.clone())
                .map_err(|e| TssError::DkgFailed(format!("{e:?}")))?;
            Ok((*s, ep))
        })
        .collect::<Result<Vec<_>, TssError>>()?;

    let key_shares = run_sync::<_, TestSessionParams<BinaryFormat>>(rng, entry_points)
        .map_err(|e| TssError::DkgFailed(format!("KeyInit run_sync: {e:?}")))?
        .results()
        .map_err(|e| TssError::DkgFailed(format!("KeyInit results: {e:?}")))?;

    let t_key_shares: BTreeMap<TestVerifier, ThresholdShare> = key_shares
        .into_iter()
        .map(|(v, ks)| (v, ThresholdKeyShare::from_key_share(&ks)))
        .collect();

    // New holder info for resharing
    let verifying_key = t_key_shares[&verifiers[0]]
        .verifying_key()
        .map_err(|e| TssError::DkgFailed(format!("vk: {e:?}")))?;
    let new_holder = NewHolder::<Params, TestVerifier> {
        verifying_key,
        old_threshold: t_key_shares[&verifiers[0]].threshold(),
        old_holders: old_holders.clone(),
    };

    // KeyResharing to n participants
    let mut entry_points = Vec::new();
    for idx in 0..t {
        let ep = KeyResharing::<Params, TestVerifier>::new(
            Some(OldHolder {
                key_share: t_key_shares[&verifiers[idx]].clone(),
            }),
            Some(new_holder.clone()),
            all_verifiers.clone(),
            t,
        );
        entry_points.push((signers[idx], ep));
    }
    for idx in t..n {
        let ep = KeyResharing::<Params, TestVerifier>::new(
            None,
            Some(new_holder.clone()),
            all_verifiers.clone(),
            t,
        );
        entry_points.push((signers[idx], ep));
    }

    let new_t_shares_map = run_sync::<_, TestSessionParams<BinaryFormat>>(rng, entry_points)
        .map_err(|e| TssError::DkgFailed(format!("KeyResharing run_sync: {e:?}")))?
        .results()
        .map_err(|e| TssError::DkgFailed(format!("KeyResharing results: {e:?}")))?;

    let new_t_key_shares: BTreeMap<TestVerifier, ThresholdShare> = new_t_shares_map
        .into_iter()
        .map(|(v, opt)| {
            let ks = opt.expect("new holder should have share");
            (v, ks)
        })
        .collect();

    // Verify all have same vk
    let vk0 = new_t_key_shares[&verifiers[0]].verifying_key().unwrap();
    for v in &verifiers {
        assert_eq!(new_t_key_shares[v].verifying_key().unwrap(), vk0);
    }

    // AuxGen
    let entry_points = (0..n)
        .map(|idx| {
            let ep = AuxGen::<Params, TestVerifier>::new(all_verifiers.clone())
                .map_err(|e| TssError::DkgFailed(format!("AuxGen new: {e:?}")))?;
            Ok((signers[idx], ep))
        })
        .collect::<Result<Vec<_>, TssError>>()?;

    let aux_infos = run_sync::<_, TestSessionParams<BinaryFormat>>(rng, entry_points)
        .map_err(|e| TssError::DkgFailed(format!("AuxGen run_sync: {e:?}")))?
        .results()
        .map_err(|e| TssError::DkgFailed(format!("AuxGen results: {e:?}")))?;

    // Assemble participants
    let mut participants = Vec::with_capacity(n);
    for idx in 0..n {
        let v = verifiers[idx];
        let verifier = v;
        participants.push(Participant {
            index: idx as u8,
            signer: signers[idx],
            verifier,
            threshold_share: new_t_key_shares[&verifier].clone(),
            aux_info: aux_infos[&verifier].clone(),
        });
    }

    let group_public_key = GroupPublicKey {
        verifying_key: vk0,
        ethereum_address: crate::ethereum_address_from_verifying_key(&vk0),
    };

    Ok(ThresholdKeyMaterial {
        participants,
        group_public_key,
        threshold: t,
        total: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "heavy synedrion DKG — run on Linux CI with --ignored"]
    fn dkg_produces_same_group_key() {
        let mat = setup_2of3().expect("dkg");
        let vk = mat.group_public_key.verifying_key;
        for p in &mat.participants {
            assert_eq!(p.verifying_key(), vk);
        }
    }
}
