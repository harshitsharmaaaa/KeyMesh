use std::collections::BTreeSet;

use k256::elliptic_curve::FieldBytes;
use manul::dev::{run_sync, BinaryFormat, TestSessionParams};
use synedrion::InteractiveSigning;

use crate::dkg::ThresholdKeyMaterial;
use crate::errors::TssError;
use crate::participant::Params;
use crate::session::{SessionBinding, SessionId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
    pub digest: [u8; 32],
    pub session_id: SessionId,
}

impl ThresholdSignature {
    pub fn s_is_low(&self) -> bool {
        const HALF_N: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ];
        self.s <= HALF_N
    }
}

pub fn verify_signature(
    digest: &[u8; 32],
    sig: &ThresholdSignature,
    vk: &k256::ecdsa::VerifyingKey,
) -> bool {
    if sig.digest != *digest {
        return false;
    }
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&sig.r);
    bytes[32..64].copy_from_slice(&sig.s);
    let signature = match k256::ecdsa::Signature::from_bytes((&bytes).into()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rec = match k256::ecdsa::RecoveryId::try_from((sig.v - 27) as u8) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &signature, rec) {
        Ok(recovered) => recovered == *vk,
        Err(_) => false,
    }
}

/// Threshold sign via real synedrion InteractiveSigning.
/// `subset_indices` are positions in `mat.participants` (0..n-1).
/// Requires at least threshold participants; single share fails.
pub fn threshold_sign(
    mat: &ThresholdKeyMaterial,
    subset_indices: &[usize],
    binding: &SessionBinding,
    session_id: &SessionId,
) -> Result<ThresholdSignature, TssError> {
    if subset_indices.len() < mat.threshold {
        return Err(TssError::InsufficientShares {
            have: subset_indices.len(),
            need: mat.threshold,
        });
    }
    // Session binding check
    let derived = crate::session::derive_session_id(binding);
    if &derived != session_id {
        return Err(TssError::SessionMismatch(
            "session_id does not match binding".into(),
        ));
    }
    // Digest binding: ensure binding.digest matches expected
    // (caller passes binding, we verify it matches session)

    // Check duplicates and bounds
    let mut seen = std::collections::HashSet::new();
    for &idx in subset_indices {
        if idx >= mat.participants.len() {
            return Err(TssError::UnknownParticipant);
        }
        if !seen.insert(idx) {
            return Err(TssError::DuplicateParticipant);
        }
    }

    // Prepare selected participants
    let selected_verifiers: BTreeSet<_> = subset_indices
        .iter()
        .map(|&i| mat.participants[i].verifier)
        .collect();

    let selected_signers: Vec<_> = subset_indices
        .iter()
        .map(|&i| mat.participants[i].signer)
        .collect();
    let selected_shares: Vec<_> = subset_indices
        .iter()
        .map(|&i| {
            let p = &mat.participants[i];
            // Convert threshold share to KeyShare for the selected party set
            p.threshold_share
                .to_key_share(&selected_verifiers)
                .map_err(|e| TssError::SigningFailed(format!("to_key_share: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let selected_aux: Vec<_> = subset_indices
        .iter()
        .map(|&i| {
            let p = &mat.participants[i];
            p.aux_info
                .clone()
                .subset(&selected_verifiers)
                .map_err(|e| TssError::SigningFailed(format!("aux subset: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Message is the digest (prehashed) — FieldBytes for k256
    let message = *FieldBytes::<k256::Secp256k1>::from_slice(&binding.digest);

    let entry_points = (0..subset_indices.len())
        .map(|idx| {
            let ep = InteractiveSigning::new(
                message,
                selected_shares[idx].clone(),
                selected_aux[idx].clone(),
            )
            .map_err(|e| TssError::SigningFailed(format!("InteractiveSigning new: {e:?}")))?;
            Ok((selected_signers[idx], ep))
        })
        .collect::<Result<Vec<_>, TssError>>()?;

    let mut rng = rand_core::OsRng;
    let signatures = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut rng, entry_points)
        .map_err(|e| TssError::SigningFailed(format!("run_sync: {e:?}")))?
        .results()
        .map_err(|e| TssError::SigningFailed(format!("results: {e:?}")))?;

    // All signatures should be same
    let (_, first_sig) = signatures
        .iter()
        .next()
        .ok_or_else(|| TssError::SigningFailed("no signatures".into()))?;
    let (sig, rec_id) = first_sig.clone().to_backend();

    // Verify all same
    for (_, s) in &signatures {
        assert_eq!(s.clone().to_backend().0, sig);
    }

    // Extract r,s
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    s.copy_from_slice(&bytes[32..64]);

    // Low-s normalization (synedrion already produces low-s? but ensure)
    const HALF_N: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ];
    let mut v = rec_id.to_byte() + 27;
    let is_high = s > HALF_N;
    if is_high {
        // synedrion's s is already low, but handle if not — use known order bytes
        use k256::elliptic_curve::generic_array::GenericArray;
        use k256::elliptic_curve::PrimeField;
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        let s_scalar = k256::Scalar::from_repr(GenericArray::clone_from_slice(&s)).unwrap();
        let n_scalar = k256::Scalar::from_repr(GenericArray::clone_from_slice(&N)).unwrap();
        let new_s = n_scalar - s_scalar;
        s = new_s.to_bytes().into();
        v ^= 1;
    }

    let threshold_sig = ThresholdSignature {
        r,
        s,
        v,
        digest: binding.digest,
        session_id: session_id.clone(),
    };

    // Verify
    if !verify_signature(
        &binding.digest,
        &threshold_sig,
        &mat.group_public_key.verifying_key,
    ) {
        return Err(TssError::SigningFailed("recovery mismatch".into()));
    }

    Ok(threshold_sig)
}
